#!/usr/bin/env python3
"""
Vault Enterprise - Hardened Backend API Server
Zero-dependency, security-hardened password vault backend using only Python 3 standard library.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "vault.db")
INDEX_CANDIDATES = [
    os.path.join(BASE_DIR, "static", "index.html"),
    os.path.join(BASE_DIR, "index.html"),
]
SESSION_EXPIRY_MINUTES = 30
OLD_PASSWORD_DAYS = 90
MAX_BODY_BYTES = 5 * 1024 * 1024  # 5MB DoS 방어 상한
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300       # 5분 잠금
VAULT_DEFAULT_LIMIT = 20
VAULT_MAX_LIMIT = 100
VALID_CATEGORIES = ("서버", "네트워크", "보안장비", "DB", "기타")
VALID_PERM_LEVELS = ("VIEW_ONLY", "VIEW_AND_EDIT", "FULL_VAULT")
VALID_SCOPE_TYPES = ("ALL", "CATEGORY", "ITEMS")

os.makedirs(DB_DIR, exist_ok=True)
try:
    os.chmod(DB_DIR, 0o700)
except Exception:
    pass

_db_lock = threading.Lock()
_thread_local = threading.local()
_login_attempts = {}  # ip -> {"count": int, "locked_until": float}


def db() -> sqlite3.Connection:
    """Thread-local SQLite connection to prevent multi-thread cursor corruption."""
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _thread_local.conn = conn
    return conn


def init_db():
    with _db_lock:
        conn = db()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('ADMIN', 'OPERATOR')),
                wrapped_vault_key TEXT NOT NULL DEFAULT '',
                wrapped_vault_key_iv TEXT NOT NULL DEFAULT '',
                key_salt TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                last_active TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL CHECK(category IN ('서버', '네트워크', '보안장비', 'DB', '기타')),
                division TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL,
                ip_url TEXT NOT NULL,
                port TEXT DEFAULT '',
                account_id TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                password_iv TEXT NOT NULL,
                password_fingerprint TEXT DEFAULT '',
                memo TEXT DEFAULT '',
                created_by INTEGER NOT NULL REFERENCES users(id),
                created_by_username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id INTEGER NOT NULL REFERENCES vault_items(id),
                encrypted_password TEXT NOT NULL,
                password_iv TEXT NOT NULL,
                changed_by INTEGER NOT NULL REFERENCES users(id),
                changed_by_username TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id INTEGER NOT NULL REFERENCES vault_items(id),
                vault_hostname TEXT NOT NULL,
                requester_id INTEGER NOT NULL REFERENCES users(id),
                requester_username TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
                approver_id INTEGER,
                approver_username TEXT,
                approved_at TEXT,
                expires_at TEXT,
                rejected_reason TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                user_id INTEGER,
                username TEXT,
                target_vault_id INTEGER,
                target_hostname TEXT,
                ip_address TEXT DEFAULT '',
                details TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                permission_level TEXT NOT NULL CHECK(permission_level IN ('VIEW_ONLY', 'VIEW_AND_EDIT', 'FULL_VAULT')),
                scope_type TEXT NOT NULL CHECK(scope_type IN ('ALL', 'CATEGORY', 'ITEMS')),
                scope_values TEXT NOT NULL DEFAULT '[]',
                starts_at TEXT NOT NULL DEFAULT '',
                expires_at TEXT NOT NULL DEFAULT '',
                memo TEXT DEFAULT '',
                granted_by INTEGER NOT NULL REFERENCES users(id),
                granted_by_username TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            """
        )
        # 기존 users 테이블 안전 마이그레이션 (사용자별 암호화 키 래핑 컬럼)
        ucols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "wrapped_vault_key" not in ucols:
            conn.execute("ALTER TABLE users ADD COLUMN wrapped_vault_key TEXT NOT NULL DEFAULT ''")
        if "wrapped_vault_key_iv" not in ucols:
            conn.execute("ALTER TABLE users ADD COLUMN wrapped_vault_key_iv TEXT NOT NULL DEFAULT ''")
        if "key_salt" not in ucols:
            conn.execute("ALTER TABLE users ADD COLUMN key_salt TEXT NOT NULL DEFAULT ''")

        # 기존 vault_items 테이블 안전 마이그레이션 (구분(division) 컬럼 추가)
        vcols = {r["name"] for r in conn.execute("PRAGMA table_info(vault_items)").fetchall()}
        if "division" not in vcols:
            conn.execute("ALTER TABLE vault_items ADD COLUMN division TEXT NOT NULL DEFAULT ''")
        conn.commit()
    if os.path.exists(DB_PATH):
        try:
            os.chmod(DB_PATH, 0o600)
        except Exception:
            pass


def now_iso() -> str:
    return datetime.utcnow().isoformat()


PBKDF2_ITERATIONS = 600000
LEGACY_KDF_PARAMS = {
    "vault_salt": "vault-enterprise-salt-v1",
    "hmac_salt": "vault-enterprise-hmac-salt-v1",
    "iterations": 100000,
}


def hash_password(password: str, salt_hex: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations
    ).hex()
    return f"pbkdf2_sha256${iterations}${digest}"


def verify_password(password: str, salt_hex: str, stored_hash: str) -> tuple:
    """Verify password in constant time. Returns (ok: bool, needs_rehash: bool)."""
    if stored_hash.startswith("pbkdf2_sha256$"):
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False, False
        try:
            iters = int(parts[1])
        except ValueError:
            return False, False
        expected = hash_password(password, salt_hex, iters)
        return hmac.compare_digest(expected, stored_hash), iters < PBKDF2_ITERATIONS
    # 레거시 100,000회 해시 호환 검증
    legacy_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 100000
    ).hex()
    return hmac.compare_digest(legacy_digest, stored_hash), True


def get_kdf_params() -> dict:
    row = db().execute("SELECT value FROM system_config WHERE key = 'kdf_params'").fetchone()
    if row:
        try:
            parsed = json.loads(row["value"])
            if (
                isinstance(parsed, dict)
                and parsed.get("vault_salt")
                and parsed.get("hmac_salt")
                and int(parsed.get("iterations", 0)) >= 100000
            ):
                return {
                    "vault_salt": str(parsed["vault_salt"]),
                    "hmac_salt": str(parsed["hmac_salt"]),
                    "iterations": int(parsed["iterations"]),
                }
        except Exception:
            pass
    return dict(LEGACY_KDF_PARAMS)


def create_audit(action: str, user_id=None, username=None,
                 target_vault_id=None, target_hostname=None,
                 ip_address="", details=""):
    with _db_lock:
        db().execute(
            "INSERT INTO audit_logs (action, user_id, username, target_vault_id, target_hostname, ip_address, details, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (action, user_id, username, target_vault_id, target_hostname or "", ip_address, str(details)[:500], now_iso()),
        )
        db().commit()


def expire_approved_requests():
    with _db_lock:
        db().execute(
            "UPDATE access_requests SET status='EXPIRED' WHERE status='APPROVED' AND expires_at <= ?",
            (now_iso(),),
        )
        db().commit()


def get_key_verifier():
    row = db().execute("SELECT value FROM system_config WHERE key = 'key_verifier'").fetchone()
    if row:
        try:
            return json.loads(row["value"])
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# User Role & Timed/Scoped Permission Helpers
# ---------------------------------------------------------------------------
def normalize_utc_iso(value: str) -> str:
    """Normalize client ISO-8601 timestamp to UTC naive ISO string matching now_iso()."""
    val = (value or "").strip()
    if not val:
        return ""
    try:
        if val.endswith("Z"):
            dt = datetime.fromisoformat(val[:-1])
        else:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is not None:
                dt = (dt - dt.utcoffset()).replace(tzinfo=None)
        return dt.replace(microsecond=0).isoformat()
    except Exception:
        raise ValueError("날짜/시간 형식이 올바르지 않습니다. (ISO-8601 형식 필요)")


def compute_permission_status(row, now_str: str) -> str:
    if row["revoked"]:
        return "REVOKED"
    if row["expires_at"] and row["expires_at"] <= now_str:
        return "EXPIRED"
    if row["starts_at"] and row["starts_at"] > now_str:
        return "SCHEDULED"
    return "ACTIVE"


def get_active_user_permissions(user_id: int) -> list:
    current = now_iso()
    rows = db().execute(
        "SELECT * FROM user_permissions "
        "WHERE user_id = ? AND revoked = 0 "
        "AND (starts_at = '' OR starts_at <= ?) "
        "AND (expires_at = '' OR expires_at > ?) "
        "ORDER BY id DESC",
        (user_id, current, current),
    ).fetchall()
    parsed = []
    for r in rows:
        try:
            vals = json.loads(r["scope_values"] or "[]")
        except Exception:
            vals = []
        parsed.append({
            "id": r["id"],
            "permission_level": r["permission_level"],
            "scope_type": r["scope_type"],
            "scope_values": vals,
            "starts_at": r["starts_at"],
            "expires_at": r["expires_at"],
            "memo": r["memo"] or "",
        })
    return parsed


def permission_matches_item(perm: dict, item_id: int, category: str) -> bool:
    st = perm["scope_type"]
    if st == "ALL":
        return True
    if st == "CATEGORY":
        return category in perm["scope_values"]
    if st == "ITEMS":
        return item_id in perm["scope_values"]
    return False


def evaluate_vault_item_access(user: dict, item_id: int, category: str,
                               active_perms=None, approved_map=None) -> dict:
    if user["role"] == "ADMIN":
        return {
            "can_view": True,
            "can_edit": True,
            "can_delete": True,
            "can_history": True,
            "expires_at": "",
            "source": "ADMIN",
        }

    perms = active_perms if active_perms is not None else get_active_user_permissions(user["id"])
    can_view = False
    can_edit = False
    can_delete = False
    can_history = False
    best_expiry = ""
    has_permanent = False
    source = ""

    for p in perms:
        if not permission_matches_item(p, item_id, category):
            continue
        lvl = p["permission_level"]
        can_view = True
        if lvl in ("VIEW_AND_EDIT", "FULL_VAULT"):
            can_edit = True
        if lvl == "FULL_VAULT":
            can_delete = True
            can_history = True
        source = "POLICY"
        if not p["expires_at"]:
            has_permanent = True
        elif not has_permanent and (not best_expiry or p["expires_at"] > best_expiry):
            best_expiry = p["expires_at"]

    if approved_map is not None:
        req_exp = approved_map.get(item_id)
    else:
        expire_approved_requests()
        row = db().execute(
            "SELECT expires_at FROM access_requests "
            "WHERE status='APPROVED' AND requester_id=? AND vault_id=? AND expires_at > ? "
            "ORDER BY expires_at DESC LIMIT 1",
            (user["id"], item_id, now_iso()),
        ).fetchone()
        req_exp = row["expires_at"] if row else None

    if req_exp:
        can_view = True
        can_edit = True
        if not source:
            source = "REQUEST"
        if not has_permanent and (not best_expiry or req_exp > best_expiry):
            best_expiry = req_exp

    return {
        "can_view": can_view,
        "can_edit": can_edit,
        "can_delete": can_delete,
        "can_history": can_history,
        "expires_at": "" if has_permanent else best_expiry,
        "source": source,
    }

class VaultHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def client_ip(self) -> str:
        # X-Real-IP(Nginx $remote_addr)를 최우선으로 신뢰하여 X-Forwarded-For 스푸핑 차단
        real = self.headers.get("X-Real-IP")
        if real:
            return real.strip()
        return self.client_address[0] if self.client_address else ""

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("Payload too large")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def authenticate(self):
        token = self.headers.get("X-Auth-Token")
        if not token:
            return None

        current = now_iso()
        cutoff = (datetime.utcnow() - timedelta(minutes=SESSION_EXPIRY_MINUTES)).isoformat()

        with _db_lock:
            db().execute("DELETE FROM sessions WHERE last_active < ?", (cutoff,))
            db().commit()

            row = db().execute(
                "SELECT s.id as sid, s.user_id, u.id, u.username, u.role "
                "FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return None

            db().execute("UPDATE sessions SET last_active = ? WHERE id = ?", (current, row["sid"]))
            db().commit()

        return {"id": row["user_id"], "username": row["username"], "role": row["role"]}

    def require_auth(self):
        user = self.authenticate()
        if user is None:
            self.send_json({"ok": False, "error": "Authentication required"}, 401)
        return user

    def require_admin(self):
        user = self.require_auth()
        if user is None:
            return None
        if user["role"] != "ADMIN":
            self.send_json({"ok": False, "error": "Admin access required"}, 403)
            return None
        return user

    def has_valid_operator_access(self, user_id: int, vid: int) -> dict:
        expire_approved_requests()
        current = now_iso()
        return db().execute(
            "SELECT * FROM access_requests WHERE status='APPROVED' AND requester_id=? AND vault_id=? AND expires_at > ? LIMIT 1",
            (user_id, vid, current),
        ).fetchone()

    def _route(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        try:
            if path in ("/", "/index.html") and method == "GET":
                return self.handle_index()
            if path == "/favicon.ico" and method == "GET":
                self.send_response(204)
                self.end_headers()
                return
            if path == "/api/status" and method == "GET":
                return self.handle_status()
            if path == "/api/auth/init" and method == "POST":
                return self.handle_auth_init()
            if path == "/api/auth/login" and method == "POST":
                return self.handle_auth_login()
            if path == "/api/auth/logout" and method == "POST":
                return self.handle_auth_logout()
            if path == "/api/auth/check" and method == "GET":
                return self.handle_auth_check()
            if path == "/api/auth/wrapped-key" and method == "POST":
                return self.handle_auth_save_wrapped_key()
            if path == "/api/auth/password" and method == "PUT":
                return self.handle_auth_change_password()
            if path == "/api/users":
                if method == "GET":
                    return self.handle_users_list()
                if method == "POST":
                    return self.handle_users_create()
            if path == "/api/admin/permissions":
                if method == "GET":
                    return self.handle_admin_permissions_list(qs)
                if method == "POST":
                    return self.handle_admin_permissions_create()
            if path == "/api/admin/vault-options" and method == "GET":
                return self.handle_admin_vault_options(qs)
            if path == "/api/my/permissions" and method == "GET":
                return self.handle_my_permissions()
            if path == "/api/dashboard/analytics" and method == "GET":
                return self.handle_dashboard_analytics(qs)
            if path == "/api/vault/stats" and method == "GET":
                return self.handle_vault_stats()
            if path == "/api/vault" and method == "GET":
                return self.handle_vault_list(qs)
            if path == "/api/vault" and method == "POST":
                return self.handle_vault_create()
            if path == "/api/vault/bulk" and method == "POST":
                return self.handle_vault_bulk()
            if path == "/api/requests" and method == "GET":
                return self.handle_requests_list(qs)
            if path == "/api/requests" and method == "POST":
                return self.handle_requests_create()
            if path == "/api/audit" and method == "GET":
                return self.handle_audit_list(qs)
            if path == "/api/audit/log" and method == "POST":
                return self.handle_audit_log()

            m = re.match(r"^/api/users/(\d+)/role$", path)
            if m and method == "PUT":
                return self.handle_user_role_update(int(m.group(1)))

            m = re.match(r"^/api/users/(\d+)/password$", path)
            if m and method == "PUT":
                return self.handle_user_password_reset(int(m.group(1)))

            m = re.match(r"^/api/admin/permissions/(\d+)$", path)
            if m:
                pid = int(m.group(1))
                if method == "PUT":
                    return self.handle_admin_permissions_update(pid)
                if method == "DELETE":
                    return self.handle_admin_permissions_revoke(pid)

            m = re.match(r"^/api/vault/(\d+)/secret$", path)
            if m and method == "GET":
                return self.handle_vault_secret(int(m.group(1)))

            m = re.match(r"^/api/vault/(\d+)/history$", path)
            if m and method == "GET":
                return self.handle_vault_history(int(m.group(1)))

            m = re.match(r"^/api/vault/(\d+)$", path)
            if m:
                vid = int(m.group(1))
                if method == "GET":
                    return self.handle_vault_get(vid)
                if method == "PUT":
                    return self.handle_vault_update(vid)
                if method == "DELETE":
                    return self.handle_vault_delete(vid)

            m = re.match(r"^/api/requests/(\d+)/approve$", path)
            if m and method == "PUT":
                return self.handle_request_approve(int(m.group(1)))

            m = re.match(r"^/api/requests/(\d+)/reject$", path)
            if m and method == "PUT":
                return self.handle_request_reject(int(m.group(1)))

            self.send_json({"ok": False, "error": "Not found"}, 404)
        except ValueError as ve:
            self.send_json({"ok": False, "error": str(ve)}, 400)
        except Exception:
            # 내부 스택 트레이스 및 예외 메시지 클라이언트 노출 차단
            self.send_json({"ok": False, "error": "Internal server error"}, 500)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    # ---- handlers ---------------------------------------------------------

    def handle_index(self):
        index_path = next((p for p in INDEX_CANDIDATES if os.path.isfile(p)), None)
        if not index_path:
            return self.send_json({"ok": False, "error": "Frontend index.html not found"}, 404)
        with open(index_path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self';",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_status(self):
        count = db().execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
        self.send_json({"ok": True, "initialized": count > 0})

    def handle_auth_init(self):
        body = self.read_json()
        username = body.get("username", "").strip()
        password = body.get("password", "")
        verifier_cipher = body.get("verifier_cipher", "")
        verifier_iv = body.get("verifier_iv", "")
        wrapped_vault_key = body.get("wrapped_vault_key", "")
        wrapped_vault_key_iv = body.get("wrapped_vault_key_iv", "")
        key_salt = body.get("key_salt", "")
        raw_kdf = body.get("kdf_params")

        if not username or len(password) < 8:
            return self.send_json({"ok": False, "error": "사용자명과 8자 이상의 비밀번호가 필요합니다."}, 400)

        salt = secrets.token_bytes(32).hex()
        pw_hash = hash_password(password, salt)
        ts = now_iso()

        # 설치별 고유 랜덤 Salt + 600,000회 반복 KDF 파라미터
        if (
            isinstance(raw_kdf, dict)
            and isinstance(raw_kdf.get("vault_salt"), str) and len(raw_kdf["vault_salt"]) >= 16
            and isinstance(raw_kdf.get("hmac_salt"), str) and len(raw_kdf["hmac_salt"]) >= 16
        ):
            kdf_params = {
                "vault_salt": raw_kdf["vault_salt"][:128],
                "hmac_salt": raw_kdf["hmac_salt"][:128],
                "iterations": max(PBKDF2_ITERATIONS, min(int(raw_kdf.get("iterations", PBKDF2_ITERATIONS)), 1200000)),
            }
        else:
            kdf_params = {
                "vault_salt": secrets.token_bytes(32).hex(),
                "hmac_salt": secrets.token_bytes(32).hex(),
                "iterations": PBKDF2_ITERATIONS,
            }

        # TOCTOU 경쟁 조건(Race Condition) 방지를 위해 단일 Lock 안에서 체크 및 생성
        with _db_lock:
            count = db().execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
            if count > 0:
                return self.send_json({"ok": False, "error": "System already initialized"}, 400)

            cur = db().execute(
                "INSERT INTO users (username, password_hash, password_salt, role, wrapped_vault_key, wrapped_vault_key_iv, key_salt, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (username, pw_hash, salt, "ADMIN", wrapped_vault_key, wrapped_vault_key_iv, key_salt, ts),
            )
            user_id = cur.lastrowid

            db().execute(
                "INSERT OR REPLACE INTO system_config (key, value) VALUES ('kdf_params', ?)",
                (json.dumps(kdf_params),),
            )
            if verifier_cipher and verifier_iv:
                verifier_json = json.dumps({"cipher": verifier_cipher, "iv": verifier_iv})
                db().execute(
                    "INSERT OR REPLACE INTO system_config (key, value) VALUES ('key_verifier', ?)",
                    (verifier_json,),
                )
            db().commit()

        create_audit("LOG_INIT_ADMIN", user_id=user_id, username=username, ip_address=self.client_ip())
        self.send_json({"ok": True, "user": {"id": user_id, "username": username, "role": "ADMIN"}})

    def handle_auth_login(self):
        ip = self.client_ip()
        now_ts = time.time()

        # Brute-force 방어 (5회 실패 시 5분간 IP 차단)
        attempt = _login_attempts.get(ip)
        if attempt and attempt.get("locked_until", 0) > now_ts:
            remain = int(attempt["locked_until"] - now_ts)
            return self.send_json({"ok": False, "error": f"로그인 시도 초과. {remain}초 후 다시 시도하세요."}, 429)

        body = self.read_json()
        username = body.get("username", "").strip()
        password = body.get("password", "")

        if not username or not password:
            return self.send_json({"ok": False, "error": "Username and password required"}, 400)

        user = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            # 타이밍 공격 완화를 위한 더미 해시 연산
            hash_password(password, "00" * 32)
            self._record_login_failure(ip)
            create_audit("LOGIN_FAILED", username=username, ip_address=ip, details="User not found")
            return self.send_json({"ok": False, "error": "Invalid credentials"}, 401)

        ok_pw, needs_rehash = verify_password(password, user["password_salt"], user["password_hash"])
        # 상수 시간 비교(hmac.compare_digest)로 타이밍 공격 원천 차단
        if not ok_pw:
            self._record_login_failure(ip)
            create_audit("LOGIN_FAILED", user_id=user["id"], username=username, ip_address=ip, details="Wrong password")
            return self.send_json({"ok": False, "error": "Invalid credentials"}, 401)

        _login_attempts.pop(ip, None)

        token = secrets.token_hex(32)
        ts = now_iso()
        with _db_lock:
            # 기존 100,000회 해시 계정은 로그인 성공 시 자동으로 600,000회로 업그레이드
            if needs_rehash:
                new_salt = secrets.token_bytes(32).hex()
                new_hash = hash_password(password, new_salt)
                db().execute(
                    "UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?",
                    (new_hash, new_salt, user["id"]),
                )
            db().execute(
                "INSERT INTO sessions (token, user_id, created_at, last_active) VALUES (?,?,?,?)",
                (token, user["id"], ts, ts),
            )
            db().commit()

        create_audit("LOGIN_SUCCESS", user_id=user["id"], username=username, ip_address=ip)
        wrapped_key = None
        if user["wrapped_vault_key"] and user["wrapped_vault_key_iv"] and user["key_salt"]:
            wrapped_key = {
                "cipher": user["wrapped_vault_key"],
                "iv": user["wrapped_vault_key_iv"],
                "salt": user["key_salt"],
            }
        self.send_json({
            "ok": True,
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
            "key_verifier": get_key_verifier(),
            "kdf_params": get_kdf_params(),
            "wrapped_key": wrapped_key,
        })

    def _record_login_failure(self, ip: str):
        now_ts = time.time()
        entry = _login_attempts.get(ip, {"count": 0, "locked_until": 0})
        if entry["locked_until"] > 0 and entry["locked_until"] <= now_ts:
            entry = {"count": 0, "locked_until": 0}
        entry["count"] += 1
        if entry["count"] >= LOGIN_MAX_ATTEMPTS:
            entry["locked_until"] = now_ts + LOGIN_LOCKOUT_SECONDS
        _login_attempts[ip] = entry

    def handle_auth_logout(self):
        user = self.require_auth()
        if user is None:
            return
        token = self.headers.get("X-Auth-Token")
        with _db_lock:
            db().execute("DELETE FROM sessions WHERE token = ?", (token,))
            db().commit()
        create_audit("LOGOUT", user_id=user["id"], username=user["username"], ip_address=self.client_ip())
        self.send_json({"ok": True})

    def handle_auth_check(self):
        user = self.require_auth()
        if user is None:
            return
        u_row = db().execute(
            "SELECT wrapped_vault_key, wrapped_vault_key_iv, key_salt, created_at FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        wrapped_key = None
        if u_row and u_row["wrapped_vault_key"] and u_row["wrapped_vault_key_iv"] and u_row["key_salt"]:
            wrapped_key = {
                "cipher": u_row["wrapped_vault_key"],
                "iv": u_row["wrapped_vault_key_iv"],
                "salt": u_row["key_salt"],
            }
        self.send_json({
            "ok": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "created_at": u_row["created_at"] if u_row else "",
            },
            "key_verifier": get_key_verifier(),
            "kdf_params": get_kdf_params(),
            "wrapped_key": wrapped_key,
        })

    def handle_auth_change_password(self):
        user = self.require_auth()
        if user is None:
            return
        body = self.read_json()
        current_password = body.get("current_password", "")
        new_password = body.get("new_password", "")
        wrapped_vault_key = (body.get("wrapped_vault_key") or "").strip()
        wrapped_vault_key_iv = (body.get("wrapped_vault_key_iv") or "").strip()
        key_salt = (body.get("key_salt") or "").strip()

        if not current_password or len(new_password) < 8:
            return self.send_json({"ok": False, "error": "현재 비밀번호와 8자 이상의 새 비밀번호가 필요합니다."}, 400)
        if current_password == new_password:
            return self.send_json({"ok": False, "error": "새 비밀번호는 현재 비밀번호와 달라야 합니다."}, 400)

        u_row = db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if u_row is None:
            return self.send_json({"ok": False, "error": "User not found"}, 404)

        ok_pw, _ = verify_password(current_password, u_row["password_salt"], u_row["password_hash"])
        if not ok_pw:
            return self.send_json({"ok": False, "error": "현재 비밀번호가 올바르지 않습니다."}, 400)

        new_salt = secrets.token_bytes(32).hex()
        new_hash = hash_password(new_password, new_salt)
        current_token = self.headers.get("X-Auth-Token") or ""

        with _db_lock:
            if wrapped_vault_key and wrapped_vault_key_iv and key_salt:
                db().execute(
                    "UPDATE users SET password_hash=?, password_salt=?, wrapped_vault_key=?, wrapped_vault_key_iv=?, key_salt=? WHERE id=?",
                    (new_hash, new_salt, wrapped_vault_key, wrapped_vault_key_iv, key_salt, user["id"]),
                )
            else:
                db().execute(
                    "UPDATE users SET password_hash=?, password_salt=? WHERE id=?",
                    (new_hash, new_salt, user["id"]),
                )
            # 본인의 다른 기기/브라우저 세션 만료 (현재 세션은 유지)
            db().execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (user["id"], current_token))
            db().commit()

        create_audit(
            "USER_PASSWORD_CHANGED",
            user_id=user["id"],
            username=user["username"],
            ip_address=self.client_ip(),
            details="Self password change",
        )
        self.send_json({"ok": True})

    def handle_auth_save_wrapped_key(self):
        user = self.require_auth()
        if user is None:
            return
        body = self.read_json()
        wrapped_vault_key = (body.get("wrapped_vault_key") or "").strip()
        wrapped_vault_key_iv = (body.get("wrapped_vault_key_iv") or "").strip()
        key_salt = (body.get("key_salt") or "").strip()
        verifier_cipher = (body.get("verifier_cipher") or "").strip()
        verifier_iv = (body.get("verifier_iv") or "").strip()

        if not wrapped_vault_key or not wrapped_vault_key_iv or not key_salt:
            return self.send_json({"ok": False, "error": "wrapped_vault_key, wrapped_vault_key_iv, key_salt are required"}, 400)

        with _db_lock:
            row = db().execute("SELECT wrapped_vault_key FROM users WHERE id = ?", (user["id"],)).fetchone()
            if row and row["wrapped_vault_key"]:
                return self.send_json({"ok": False, "error": "이미 볼트 키가 연동된 계정입니다."}, 400)
            db().execute(
                "UPDATE users SET wrapped_vault_key=?, wrapped_vault_key_iv=?, key_salt=? WHERE id=?",
                (wrapped_vault_key, wrapped_vault_key_iv, key_salt, user["id"]),
            )
            if verifier_cipher and verifier_iv and user["role"] == "ADMIN" and get_key_verifier() is None:
                verifier_json = json.dumps({"cipher": verifier_cipher, "iv": verifier_iv})
                db().execute(
                    "INSERT OR REPLACE INTO system_config (key, value) VALUES ('key_verifier', ?)",
                    (verifier_json,),
                )
            db().commit()

        self.send_json({"ok": True})

    def handle_users_list(self):
        user = self.require_admin()
        if user is None:
            return
        current = now_iso()
        rows = db().execute("SELECT id, username, role, wrapped_vault_key, created_at FROM users ORDER BY id").fetchall()
        perm_rows = db().execute(
            "SELECT user_id, COUNT(*) as cnt FROM user_permissions "
            "WHERE revoked = 0 AND (starts_at = '' OR starts_at <= ?) AND (expires_at = '' OR expires_at > ?) "
            "GROUP BY user_id",
            (current, current),
        ).fetchall()
        perm_counts = {r["user_id"]: r["cnt"] for r in perm_rows}
        users = [
            {
                "id": r["id"],
                "username": r["username"],
                "role": r["role"],
                "created_at": r["created_at"],
                "active_permission_count": perm_counts.get(r["id"], 0),
                "has_wrapped_key": bool(r["wrapped_vault_key"]),
            }
            for r in rows
        ]
        self.send_json({"ok": True, "users": users})

    def handle_user_password_reset(self, uid: int):
        user = self.require_admin()
        if user is None:
            return

        target = db().execute("SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
        if target is None:
            return self.send_json({"ok": False, "error": "사용자를 찾을 수 없습니다."}, 404)

        body = self.read_json()
        new_password = body.get("password", "")
        wrapped_vault_key = (body.get("wrapped_vault_key") or "").strip()
        wrapped_vault_key_iv = (body.get("wrapped_vault_key_iv") or "").strip()
        key_salt = (body.get("key_salt") or "").strip()

        if len(new_password) < 8:
            return self.send_json({"ok": False, "error": "새 비밀번호는 8자 이상이어야 합니다."}, 400)

        salt = secrets.token_bytes(32).hex()
        pw_hash = hash_password(new_password, salt)
        current_token = self.headers.get("X-Auth-Token") or ""

        with _db_lock:
            if wrapped_vault_key and wrapped_vault_key_iv and key_salt:
                db().execute(
                    "UPDATE users SET password_hash=?, password_salt=?, wrapped_vault_key=?, wrapped_vault_key_iv=?, key_salt=? WHERE id=?",
                    (pw_hash, salt, wrapped_vault_key, wrapped_vault_key_iv, key_salt, uid),
                )
            else:
                db().execute(
                    "UPDATE users SET password_hash=?, password_salt=? WHERE id=?",
                    (pw_hash, salt, uid),
                )
            # 비밀번호 초기화된 대상의 기존 세션 강제 만료 (본인 초기화 시 현재 세션만 유지)
            if uid == user["id"]:
                db().execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (uid, current_token))
            else:
                db().execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
            db().commit()

        create_audit(
            "USER_PASSWORD_RESET",
            user_id=user["id"],
            username=user["username"],
            ip_address=self.client_ip(),
            details=f"Reset password for user '{target['username']}' (vault key synced={bool(wrapped_vault_key)})",
        )
        self.send_json({"ok": True})

    def handle_user_role_update(self, uid: int):
        user = self.require_admin()
        if user is None:
            return
        if uid == user["id"]:
            return self.send_json({"ok": False, "error": "자신의 역할은 변경할 수 없습니다."}, 400)

        target = db().execute("SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
        if target is None:
            return self.send_json({"ok": False, "error": "사용자를 찾을 수 없습니다."}, 404)

        body = self.read_json()
        new_role = (body.get("role") or "").strip().upper()
        if new_role not in ("ADMIN", "OPERATOR"):
            return self.send_json({"ok": False, "error": "역할은 ADMIN 또는 OPERATOR만 가능합니다."}, 400)

        if target["role"] == new_role:
            return self.send_json({"ok": True, "user": {"id": target["id"], "username": target["username"], "role": new_role}})

        with _db_lock:
            if target["role"] == "ADMIN" and new_role != "ADMIN":
                admin_cnt = db().execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'ADMIN'").fetchone()["cnt"]
                if admin_cnt <= 1:
                    return self.send_json({"ok": False, "error": "최소 1명의 관리자(ADMIN) 계정이 필요합니다."}, 400)
            db().execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
            db().commit()

        create_audit(
            "USER_ROLE_CHANGED",
            user_id=user["id"],
            username=user["username"],
            ip_address=self.client_ip(),
            details=f"{target['username']}: {target['role']} -> {new_role}",
        )
        self.send_json({"ok": True, "user": {"id": target["id"], "username": target["username"], "role": new_role}})

    def _validate_permission_payload(self, body: dict):
        permission_level = (body.get("permission_level") or "").strip().upper()
        if permission_level not in VALID_PERM_LEVELS:
            raise ValueError("권한 수준은 VIEW_ONLY, VIEW_AND_EDIT, FULL_VAULT 중 하나여야 합니다.")

        scope_type = (body.get("scope_type") or "").strip().upper()
        if scope_type not in VALID_SCOPE_TYPES:
            raise ValueError("대상 범위는 ALL, CATEGORY, ITEMS 중 하나여야 합니다.")

        raw_values = body.get("scope_values", [])
        if not isinstance(raw_values, list):
            raise ValueError("scope_values는 배열이어야 합니다.")

        if scope_type == "ALL":
            scope_values = []
        elif scope_type == "CATEGORY":
            scope_values = sorted({str(v).strip() for v in raw_values if str(v).strip() in VALID_CATEGORIES})
            if not scope_values:
                raise ValueError("분류별 범위에서는 최소 1개 이상의 분류를 선택해야 합니다.")
        else:  # ITEMS
            clean_ids = []
            for v in raw_values:
                try:
                    clean_ids.append(int(v))
                except (TypeError, ValueError):
                    pass
            scope_values = sorted(set(clean_ids))
            if not scope_values:
                raise ValueError("특정 장비 범위에서는 최소 1개 이상의 장비를 선택해야 합니다.")
            placeholders = ",".join("?" for _ in scope_values)
            existing_rows = db().execute(
                f"SELECT id FROM vault_items WHERE id IN ({placeholders})", scope_values
            ).fetchall()
            valid_ids = sorted({r["id"] for r in existing_rows})
            if not valid_ids:
                raise ValueError("선택한 장비가 존재하지 않습니다.")
            scope_values = valid_ids

        starts_at = normalize_utc_iso(body.get("starts_at", ""))
        expires_at = normalize_utc_iso(body.get("expires_at", ""))
        current = now_iso()

        if expires_at and expires_at <= current:
            raise ValueError("종료 일시는 현재 시각 이후여야 합니다.")
        if starts_at and expires_at and expires_at <= starts_at:
            raise ValueError("종료 일시는 시작 일시 이후여야 합니다.")

        memo = (body.get("memo") or "").strip()[:300]
        return permission_level, scope_type, scope_values, starts_at, expires_at, memo

    def _serialize_permissions(self, rows: list) -> list:
        current = now_iso()
        vault_map = {
            r["id"]: f"{r['hostname']} ({r['category']})"
            for r in db().execute("SELECT id, hostname, category FROM vault_items").fetchall()
        }
        result = []
        for r in rows:
            try:
                vals = json.loads(r["scope_values"] or "[]")
            except Exception:
                vals = []
            if r["scope_type"] == "ALL":
                scope_labels = ["전체 장비"]
            elif r["scope_type"] == "CATEGORY":
                scope_labels = [str(v) for v in vals]
            else:
                scope_labels = [vault_map.get(v, f"장비 #{v}") for v in vals]
            result.append({
                "id": r["id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "user_role": r["user_role"],
                "permission_level": r["permission_level"],
                "scope_type": r["scope_type"],
                "scope_values": vals,
                "scope_labels": scope_labels,
                "starts_at": r["starts_at"],
                "expires_at": r["expires_at"],
                "memo": r["memo"] or "",
                "granted_by_username": r["granted_by_username"],
                "revoked": bool(r["revoked"]),
                "status": compute_permission_status(r, current),
                "created_at": r["created_at"],
            })
        return result

    def handle_admin_permissions_list(self, qs: dict):
        user = self.require_admin()
        if user is None:
            return

        uid_filter = qs.get("user_id", [None])[0]
        query = (
            "SELECT p.*, u.username, u.role as user_role "
            "FROM user_permissions p JOIN users u ON p.user_id = u.id WHERE 1=1"
        )
        params = []
        if uid_filter:
            try:
                query += " AND p.user_id = ?"
                params.append(int(uid_filter))
            except ValueError:
                pass
        query += " ORDER BY p.id DESC"
        rows = db().execute(query, params).fetchall()
        self.send_json({"ok": True, "permissions": self._serialize_permissions(rows)})

    def handle_my_permissions(self):
        user = self.require_auth()
        if user is None:
            return
        rows = db().execute(
            "SELECT p.*, u.username, u.role as user_role "
            "FROM user_permissions p JOIN users u ON p.user_id = u.id "
            "WHERE p.user_id = ? AND p.revoked = 0 ORDER BY p.id DESC",
            (user["id"],),
        ).fetchall()
        perms = [p for p in self._serialize_permissions(rows) if p["status"] in ("ACTIVE", "SCHEDULED")]
        self.send_json({"ok": True, "permissions": perms})

    def handle_admin_permissions_create(self):
        user = self.require_admin()
        if user is None:
            return

        body = self.read_json()
        try:
            target_uid = int(body.get("user_id"))
        except (TypeError, ValueError):
            return self.send_json({"ok": False, "error": "대상 사용자를 선택해주세요."}, 400)

        target = db().execute("SELECT id, username, role FROM users WHERE id = ?", (target_uid,)).fetchone()
        if target is None:
            return self.send_json({"ok": False, "error": "대상 사용자를 찾을 수 없습니다."}, 404)

        permission_level, scope_type, scope_values, starts_at, expires_at, memo = self._validate_permission_payload(body)
        ts = now_iso()

        with _db_lock:
            cur = db().execute(
                "INSERT INTO user_permissions "
                "(user_id, permission_level, scope_type, scope_values, starts_at, expires_at, memo, granted_by, granted_by_username, revoked, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,0,?)",
                (
                    target_uid,
                    permission_level,
                    scope_type,
                    json.dumps(scope_values, ensure_ascii=False),
                    starts_at,
                    expires_at,
                    memo,
                    user["id"],
                    user["username"],
                    ts,
                ),
            )
            db().commit()
            pid = cur.lastrowid

        period_desc = f"{starts_at or '즉시'} ~ {expires_at or '상시'}"
        create_audit(
            "PERMISSION_GRANTED",
            user_id=user["id"],
            username=user["username"],
            ip_address=self.client_ip(),
            details=f"target={target['username']}, level={permission_level}, scope={scope_type}:{scope_values}, period={period_desc}, memo={memo}",
        )
        self.send_json({"ok": True, "id": pid})

    def handle_admin_permissions_update(self, pid: int):
        user = self.require_admin()
        if user is None:
            return

        existing = db().execute(
            "SELECT p.*, u.username FROM user_permissions p JOIN users u ON p.user_id = u.id WHERE p.id = ?",
            (pid,),
        ).fetchone()
        if existing is None:
            return self.send_json({"ok": False, "error": "권한 정책을 찾을 수 없습니다."}, 404)
        if existing["revoked"]:
            return self.send_json({"ok": False, "error": "이미 회수된 권한 정책은 수정할 수 없습니다."}, 400)

        body = self.read_json()
        permission_level, scope_type, scope_values, starts_at, expires_at, memo = self._validate_permission_payload(body)

        with _db_lock:
            db().execute(
                "UPDATE user_permissions SET permission_level=?, scope_type=?, scope_values=?, starts_at=?, expires_at=?, memo=? WHERE id=?",
                (
                    permission_level,
                    scope_type,
                    json.dumps(scope_values, ensure_ascii=False),
                    starts_at,
                    expires_at,
                    memo,
                    pid,
                ),
            )
            db().commit()

        period_desc = f"{starts_at or '즉시'} ~ {expires_at or '상시'}"
        create_audit(
            "PERMISSION_UPDATED",
            user_id=user["id"],
            username=user["username"],
            ip_address=self.client_ip(),
            details=f"id={pid}, target={existing['username']}, level={permission_level}, scope={scope_type}:{scope_values}, period={period_desc}",
        )
        self.send_json({"ok": True})

    def handle_admin_permissions_revoke(self, pid: int):
        user = self.require_admin()
        if user is None:
            return

        existing = db().execute(
            "SELECT p.*, u.username FROM user_permissions p JOIN users u ON p.user_id = u.id WHERE p.id = ?",
            (pid,),
        ).fetchone()
        if existing is None:
            return self.send_json({"ok": False, "error": "권한 정책을 찾을 수 없습니다."}, 404)

        with _db_lock:
            db().execute("UPDATE user_permissions SET revoked = 1 WHERE id = ?", (pid,))
            db().commit()

        create_audit(
            "PERMISSION_REVOKED",
            user_id=user["id"],
            username=user["username"],
            ip_address=self.client_ip(),
            details=f"id={pid}, target={existing['username']}, level={existing['permission_level']}, scope={existing['scope_type']}",
        )
        self.send_json({"ok": True})

    def handle_users_create(self):
        user = self.require_admin()
        if user is None:
            return
        body = self.read_json()
        username = body.get("username", "").strip()
        password = body.get("password", "")
        role = body.get("role", "OPERATOR")
        wrapped_vault_key = (body.get("wrapped_vault_key") or "").strip()
        wrapped_vault_key_iv = (body.get("wrapped_vault_key_iv") or "").strip()
        key_salt = (body.get("key_salt") or "").strip()

        if not username or len(password) < 8:
            return self.send_json({"ok": False, "error": "사용자명과 8자 이상의 비밀번호가 필요합니다."}, 400)
        if role not in ("ADMIN", "OPERATOR"):
            return self.send_json({"ok": False, "error": "Role must be ADMIN or OPERATOR"}, 400)

        existing = db().execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
        if existing:
            return self.send_json({"ok": False, "error": "Username already exists"}, 400)

        salt = secrets.token_bytes(32).hex()
        pw_hash = hash_password(password, salt)
        ts = now_iso()

        with _db_lock:
            cur = db().execute(
                "INSERT INTO users (username, password_hash, password_salt, role, wrapped_vault_key, wrapped_vault_key_iv, key_salt, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (username, pw_hash, salt, role, wrapped_vault_key, wrapped_vault_key_iv, key_salt, ts),
            )
            db().commit()
            new_id = cur.lastrowid

        create_audit("USER_CREATED", user_id=user["id"], username=user["username"],
                     ip_address=self.client_ip(), details=f"Created user '{username}' with role {role}")
        self.send_json({"ok": True, "id": new_id})

    def handle_dashboard_analytics(self, qs: dict):
        user = self.require_auth()
        if user is None:
            return

        try:
            tz_offset = int(qs.get("tz_offset", ["540"])[0])
        except (ValueError, TypeError):
            tz_offset = 540
        tz_offset = max(-720, min(840, tz_offset))
        tz_delta = timedelta(minutes=tz_offset)

        now_utc = datetime.utcnow()
        now_local = now_utc + tz_delta
        today_local = now_local.date()
        yesterday_local = today_local - timedelta(days=1)

        # 1. Vault summary & category distribution
        total_items = db().execute("SELECT COUNT(*) as cnt FROM vault_items").fetchone()["cnt"]
        old_cutoff = (now_utc - timedelta(days=OLD_PASSWORD_DAYS)).isoformat()
        old_count = db().execute(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE updated_at != '' AND updated_at < ?",
            (old_cutoff,),
        ).fetchone()["cnt"]
        duplicate_count = db().execute(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE password_fingerprint != '' AND password_fingerprint IN ("
            "SELECT password_fingerprint FROM vault_items WHERE password_fingerprint != '' "
            "GROUP BY password_fingerprint HAVING COUNT(*) > 1)"
        ).fetchone()["cnt"]
        warnings = db().execute(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE "
            "(updated_at != '' AND updated_at < ?) OR "
            "(password_fingerprint != '' AND password_fingerprint IN ("
            "SELECT password_fingerprint FROM vault_items WHERE password_fingerprint != '' "
            "GROUP BY password_fingerprint HAVING COUNT(*) > 1))",
            (old_cutoff,),
        ).fetchone()["cnt"]

        cat_rows = db().execute(
            "SELECT category, COUNT(*) as cnt FROM vault_items GROUP BY category"
        ).fetchall()
        cat_map = {r["category"]: r["cnt"] for r in cat_rows}
        categories = [{"category": c, "count": cat_map.get(c, 0)} for c in VALID_CATEGORIES]

        # 2. Sessions & pending requests
        sess_cutoff = (now_utc - timedelta(minutes=SESSION_EXPIRY_MINUTES)).isoformat()
        if user["role"] == "ADMIN":
            active_sessions = db().execute(
                "SELECT COUNT(DISTINCT user_id) as cnt FROM sessions WHERE last_active >= ?",
                (sess_cutoff,),
            ).fetchone()["cnt"]
            pending_requests = db().execute(
                "SELECT COUNT(*) as cnt FROM access_requests WHERE status = 'PENDING'"
            ).fetchone()["cnt"]
        else:
            active_sessions = 1
            pending_requests = 0

        # 3. 7-day trend & today/yesterday visitors (in user's local timezone)
        start_local_dt = datetime.combine(today_local - timedelta(days=6), datetime.min.time())
        start_utc_iso = (start_local_dt - tz_delta).isoformat()
        cutoff_24h_iso = (now_utc - timedelta(hours=24)).isoformat()

        is_admin = user["role"] == "ADMIN"
        audit_sql = (
            "SELECT a.action, a.user_id, a.username, a.target_hostname, a.ip_address, a.details, a.created_at, u.role as user_role "
            "FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id "
            "WHERE a.created_at >= ?"
        )
        audit_params = [start_utc_iso]
        if not is_admin:
            audit_sql += " AND a.user_id = ?"
            audit_params.append(user["id"])
        audit_sql += " ORDER BY a.created_at ASC"
        audit_rows = db().execute(audit_sql, audit_params).fetchall()

        day_keys = [(today_local - timedelta(days=i)) for i in range(6, -1, -1)]
        trend_map = {
            d.isoformat(): {"date": d.isoformat(), "label": d.strftime("%m/%d"), "logins": 0, "secrets": 0, "failures": 0}
            for d in day_keys
        }
        today_str = today_local.isoformat()
        yesterday_str = yesterday_local.isoformat()
        today_visitors = {}
        yesterday_visitors = {}
        device_counts = {}
        failed_24h_count = 0
        failed_alerts_map = {}

        for r in audit_rows:
            try:
                dt_utc = datetime.fromisoformat(r["created_at"])
            except Exception:
                continue
            dt_loc = dt_utc + tz_delta
            day_str = dt_loc.date().isoformat()
            act = r["action"]

            if day_str in trend_map:
                if act == "LOGIN_SUCCESS":
                    trend_map[day_str]["logins"] += 1
                elif act in ("SECRET_VIEWED", "SECRET_COPIED"):
                    trend_map[day_str]["secrets"] += 1
                elif act == "LOGIN_FAILED":
                    trend_map[day_str]["failures"] += 1

            if act == "LOGIN_SUCCESS":
                uname = r["username"] or "unknown"
                bucket = today_visitors if day_str == today_str else (yesterday_visitors if day_str == yesterday_str else None)
                if bucket is not None:
                    entry = bucket.get(uname)
                    if entry is None:
                        bucket[uname] = {
                            "username": uname,
                            "role": r["user_role"] or "OPERATOR",
                            "login_count": 1,
                            "last_login": r["created_at"],
                            "last_ip": r["ip_address"] or "-",
                        }
                    else:
                        entry["login_count"] += 1
                        if r["created_at"] >= entry["last_login"]:
                            entry["last_login"] = r["created_at"]
                            entry["last_ip"] = r["ip_address"] or "-"

            if act in ("SECRET_VIEWED", "SECRET_COPIED") and r["target_hostname"]:
                hn = r["target_hostname"]
                device_counts[hn] = device_counts.get(hn, 0) + 1

            if act == "LOGIN_FAILED" and r["created_at"] >= cutoff_24h_iso:
                failed_24h_count += 1
                if is_admin:
                    key = (r["username"] or "unknown", r["ip_address"] or "-")
                    fa = failed_alerts_map.get(key)
                    if fa is None:
                        failed_alerts_map[key] = {
                            "username": key[0],
                            "ip_address": key[1],
                            "count": 1,
                            "last_attempt": r["created_at"],
                            "details": r["details"] or "",
                        }
                    else:
                        fa["count"] += 1
                        if r["created_at"] >= fa["last_attempt"]:
                            fa["last_attempt"] = r["created_at"]
                            fa["details"] = r["details"] or ""

        today_list = sorted(today_visitors.values(), key=lambda x: x["last_login"], reverse=True)
        yesterday_list = sorted(yesterday_visitors.values(), key=lambda x: x["last_login"], reverse=True)
        trend_7d = [trend_map[d.isoformat()] for d in day_keys]
        top_devices = [
            {"hostname": hn, "count": cnt}
            for hn, cnt in sorted(device_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        ]
        failed_alerts = sorted(failed_alerts_map.values(), key=lambda x: (-x["count"], x["last_attempt"]))[:8]

        # 4. Security health score (0~100)
        score = 100
        if total_items > 0:
            score -= min(35, round((duplicate_count / total_items) * 50))
            score -= min(35, round((old_count / total_items) * 50))
        if is_admin:
            score -= min(30, failed_24h_count * 3)
        score = max(0, min(100, score))
        if score >= 90:
            health_grade = "최상"
        elif score >= 75:
            health_grade = "양호"
        elif score >= 50:
            health_grade = "주의"
        else:
            health_grade = "위험"

        # 5. Active temporary grants (approved requests + active user_permissions)
        expire_approved_requests()
        current_iso = now_iso()
        active_grants = []

        req_sql = (
            "SELECT requester_username, vault_hostname, expires_at FROM access_requests "
            "WHERE status='APPROVED' AND expires_at > ?"
        )
        req_params = [current_iso]
        if not is_admin:
            req_sql += " AND requester_id = ?"
            req_params.append(user["id"])
        req_sql += " ORDER BY expires_at ASC LIMIT 10"
        for rr in db().execute(req_sql, req_params).fetchall():
            active_grants.append({
                "type": "REQUEST",
                "username": rr["requester_username"],
                "target": rr["vault_hostname"],
                "level": "열람 승인",
                "expires_at": rr["expires_at"],
            })

        perm_sql = (
            "SELECT p.*, u.username, u.role as user_role FROM user_permissions p "
            "JOIN users u ON p.user_id = u.id "
            "WHERE p.revoked = 0 AND (p.starts_at = '' OR p.starts_at <= ?) AND (p.expires_at = '' OR p.expires_at > ?)"
        )
        perm_params = [current_iso, current_iso]
        if not is_admin:
            perm_sql += " AND p.user_id = ?"
            perm_params.append(user["id"])
        perm_sql += " ORDER BY p.id DESC LIMIT 10"
        perm_rows = db().execute(perm_sql, perm_params).fetchall()
        for sp in self._serialize_permissions(perm_rows):
            active_grants.append({
                "type": "POLICY",
                "username": sp["username"],
                "target": ", ".join(sp["scope_labels"][:2]) + (f" 외 {len(sp['scope_labels'])-2}건" if len(sp["scope_labels"]) > 2 else ""),
                "level": sp["permission_level"],
                "expires_at": sp["expires_at"],
            })

        # 6. Recent audit logs (10 rows)
        recent_sql = "SELECT id, action, username, target_hostname, ip_address, details, created_at FROM audit_logs WHERE 1=1"
        recent_params = []
        if not is_admin:
            recent_sql += " AND user_id = ?"
            recent_params.append(user["id"])
        recent_sql += " ORDER BY id DESC LIMIT 10"
        recent_rows = db().execute(recent_sql, recent_params).fetchall()
        recent_logs = [
            {
                "id": r["id"],
                "action": r["action"],
                "username": r["username"] or "-",
                "target_hostname": r["target_hostname"] or "-",
                "ip_address": r["ip_address"] or "-",
                "details": r["details"] or "-",
                "created_at": r["created_at"],
            }
            for r in recent_rows
        ]

        self.send_json({
            "ok": True,
            "summary": {
                "total_items": total_items,
                "warnings": warnings,
                "duplicate_count": duplicate_count,
                "old_count": old_count,
                "pending_requests": pending_requests,
                "failed_logins_24h": failed_24h_count,
                "health_score": score,
                "health_grade": health_grade,
                "active_sessions": active_sessions,
            },
            "visitors": {
                "today_date": today_str,
                "yesterday_date": yesterday_str,
                "today": today_list,
                "yesterday": yesterday_list,
            },
            "trend_7d": trend_7d,
            "categories": categories,
            "top_devices": top_devices,
            "active_grants": active_grants,
            "failed_alerts": failed_alerts,
            "recent_logs": recent_logs,
        })

    def handle_vault_stats(self):
        user = self.require_auth()
        if user is None:
            return
        total = db().execute("SELECT COUNT(*) as cnt FROM vault_items").fetchone()["cnt"]
        cutoff = (datetime.utcnow() - timedelta(days=OLD_PASSWORD_DAYS)).isoformat()
        warnings = db().execute(
            "SELECT COUNT(*) as cnt FROM vault_items WHERE "
            "(updated_at != '' AND updated_at < ?) OR "
            "(password_fingerprint != '' AND password_fingerprint IN ("
            "SELECT password_fingerprint FROM vault_items WHERE password_fingerprint != '' "
            "GROUP BY password_fingerprint HAVING COUNT(*) > 1))",
            (cutoff,),
        ).fetchone()["cnt"]
        self.send_json({"ok": True, "total": total, "warnings": warnings})

    def handle_admin_vault_options(self, qs: dict):
        user = self.require_admin()
        if user is None:
            return
        search = qs.get("search", [None])[0]
        query = "SELECT id, category, hostname, ip_url FROM vault_items WHERE 1=1"
        params = []
        if search:
            query += " AND (hostname LIKE ? OR ip_url LIKE ? OR category LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])
        query += " ORDER BY id DESC"
        rows = db().execute(query, params).fetchall()
        items = [
            {"id": r["id"], "category": r["category"], "hostname": r["hostname"], "ip_url": r["ip_url"]}
            for r in rows
        ]
        self.send_json({"ok": True, "items": items})

    def handle_vault_get(self, vid: int):
        user = self.require_auth()
        if user is None:
            return
        r = db().execute(
            "SELECT id, category, division, hostname, ip_url, port, account_id, memo, created_by_username, created_at, updated_at "
            "FROM vault_items WHERE id = ?",
            (vid,),
        ).fetchone()
        if r is None:
            return self.send_json({"ok": False, "error": "Vault item not found"}, 404)
        self.send_json({
            "ok": True,
            "item": {
                "id": r["id"],
                "category": r["category"],
                "division": r["division"] if "division" in r.keys() else "",
                "hostname": r["hostname"],
                "ip_url": r["ip_url"],
                "port": r["port"],
                "account_id": r["account_id"],
                "memo": r["memo"],
                "created_by_username": r["created_by_username"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            },
        })

    def handle_vault_list(self, qs: dict):
        user = self.require_auth()
        if user is None:
            return

        search = qs.get("search", [None])[0]
        category = qs.get("category", [None])[0]

        try:
            page = max(1, int(qs.get("page", ["1"])[0]))
        except (ValueError, TypeError):
            page = 1
        try:
            limit = max(1, min(VAULT_MAX_LIMIT, int(qs.get("limit", [str(VAULT_DEFAULT_LIMIT)])[0])))
        except (ValueError, TypeError):
            limit = VAULT_DEFAULT_LIMIT

        where_clause = " WHERE 1=1"
        params = []

        if search:
            where_clause += " AND (hostname LIKE ? OR ip_url LIKE ? OR account_id LIKE ? OR memo LIKE ? OR division LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like, like, like])
        if category:
            where_clause += " AND category = ?"
            params.append(category)

        total = db().execute("SELECT COUNT(*) as cnt FROM vault_items" + where_clause, params).fetchone()["cnt"]
        total_pages = max(1, (total + limit - 1) // limit)
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * limit

        query = (
            "SELECT id, category, division, hostname, ip_url, port, account_id, memo, password_fingerprint, "
            "created_by_username, created_at, updated_at FROM vault_items"
            + where_clause
            + " ORDER BY id DESC LIMIT ? OFFSET ?"
        )
        rows = db().execute(query, params + [limit, offset]).fetchall()

        fp_rows = db().execute(
            "SELECT password_fingerprint, COUNT(*) as cnt FROM vault_items "
            "WHERE password_fingerprint != '' GROUP BY password_fingerprint HAVING cnt > 1"
        ).fetchall()
        dup_fps = {r["password_fingerprint"] for r in fp_rows}

        cutoff = (datetime.utcnow() - timedelta(days=OLD_PASSWORD_DAYS)).isoformat()

        active_perms = None
        approved_map = None
        if user["role"] != "ADMIN":
            expire_approved_requests()
            active_perms = get_active_user_permissions(user["id"])
            app_rows = db().execute(
                "SELECT vault_id, MAX(expires_at) as max_exp FROM access_requests "
                "WHERE status='APPROVED' AND requester_id=? AND expires_at > ? GROUP BY vault_id",
                (user["id"], now_iso()),
            ).fetchall()
            approved_map = {r["vault_id"]: r["max_exp"] for r in app_rows}

        items = []
        for r in rows:
            access = evaluate_vault_item_access(user, r["id"], r["category"], active_perms, approved_map)
            # 보안 패치: password_fingerprint 해시 원문은 클라이언트에 절대 내려주지 않고 is_duplicate 여부만 반환
            item = {
                "id": r["id"],
                "category": r["category"],
                "division": r["division"] if "division" in r.keys() else "",
                "hostname": r["hostname"],
                "ip_url": r["ip_url"],
                "port": r["port"],
                "account_id": r["account_id"],
                "memo": r["memo"],
                "created_by_username": r["created_by_username"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "is_old": r["updated_at"] < cutoff if r["updated_at"] else False,
                "is_duplicate": (r["password_fingerprint"] in dup_fps) if r["password_fingerprint"] else False,
                "access": access,
            }
            items.append(item)

        self.send_json({
            "ok": True,
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
        })

    def handle_vault_create(self):
        user = self.require_auth()
        if user is None:
            return
        body = self.read_json()

        required = ["category", "hostname", "ip_url", "account_id", "encrypted_password", "password_iv"]
        for field in required:
            if not body.get(field):
                return self.send_json({"ok": False, "error": f"Field '{field}' is required"}, 400)

        division = (body.get("division") or "").strip()
        ts = now_iso()
        with _db_lock:
            cur = db().execute(
                "INSERT INTO vault_items (category, division, hostname, ip_url, port, account_id, encrypted_password, password_iv, password_fingerprint, memo, created_by, created_by_username, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    body["category"],
                    division,
                    body["hostname"],
                    body["ip_url"],
                    body.get("port", ""),
                    body["account_id"],
                    body["encrypted_password"],
                    body["password_iv"],
                    body.get("password_fingerprint", ""),
                    body.get("memo", ""),
                    user["id"],
                    user["username"],
                    ts,
                    ts,
                ),
            )
            db().commit()
            new_id = cur.lastrowid

        create_audit("VAULT_CREATED", user_id=user["id"], username=user["username"],
                     target_vault_id=new_id, target_hostname=body["hostname"],
                     ip_address=self.client_ip())
        self.send_json({"ok": True, "id": new_id})

    def handle_vault_update(self, vid: int):
        user = self.require_auth()
        if user is None:
            return

        item = db().execute("SELECT * FROM vault_items WHERE id = ?", (vid,)).fetchone()
        if item is None:
            return self.send_json({"ok": False, "error": "Vault item not found"}, 404)

        # 보안 통제: 운영자(OPERATOR)는 유효한 열람 승인(APPROVED) 또는 부여된 수정 권한 정책(기간/범위 내)이 있어야 수정 가능
        if user["role"] != "ADMIN":
            access = evaluate_vault_item_access(user, vid, item["category"])
            if not access["can_edit"]:
                return self.send_json({"ok": False, "error": "수정 권한이 없습니다. 관리자 열람 승인 또는 수정 권한이 필요합니다."}, 403)

        body = self.read_json()
        if not body.get("encrypted_password") or not body.get("password_iv"):
            return self.send_json({"ok": False, "error": "encrypted_password and password_iv are required"}, 400)

        existing_div = item["division"] if "division" in item.keys() else ""
        division = body.get("division", existing_div)
        if division is not None:
            division = str(division).strip()
        else:
            division = existing_div

        ts = now_iso()

        with _db_lock:
            # 실제로 암호문이 변경되는 경우에만 히스토리에 백업
            if body["encrypted_password"] != item["encrypted_password"] or body["password_iv"] != item["password_iv"]:
                db().execute(
                    "INSERT INTO vault_history (vault_id, encrypted_password, password_iv, changed_by, changed_by_username, changed_at) VALUES (?,?,?,?,?,?)",
                    (vid, item["encrypted_password"], item["password_iv"], user["id"], user["username"], ts),
                )

            db().execute(
                "UPDATE vault_items SET category=?, division=?, hostname=?, ip_url=?, port=?, account_id=?, encrypted_password=?, password_iv=?, password_fingerprint=?, memo=?, updated_at=? WHERE id=?",
                (
                    body.get("category", item["category"]),
                    division,
                    body.get("hostname", item["hostname"]),
                    body.get("ip_url", item["ip_url"]),
                    body.get("port", item["port"]),
                    body.get("account_id", item["account_id"]),
                    body["encrypted_password"],
                    body["password_iv"],
                    body.get("password_fingerprint", item["password_fingerprint"]),
                    body.get("memo", item["memo"]),
                    ts,
                    vid,
                ),
            )
            db().commit()

        create_audit("VAULT_UPDATED", user_id=user["id"], username=user["username"],
                     target_vault_id=vid, target_hostname=body.get("hostname", item["hostname"]),
                     ip_address=self.client_ip())
        self.send_json({"ok": True})

    def handle_vault_delete(self, vid: int):
        user = self.require_auth()
        if user is None:
            return

        item = db().execute("SELECT * FROM vault_items WHERE id = ?", (vid,)).fetchone()
        if item is None:
            return self.send_json({"ok": False, "error": "Vault item not found"}, 404)

        if user["role"] != "ADMIN":
            access = evaluate_vault_item_access(user, vid, item["category"])
            if not access["can_delete"]:
                return self.send_json({"ok": False, "error": "삭제 권한이 없습니다. 관리자 또는 전체 볼트 관리 권한이 필요합니다."}, 403)

        with _db_lock:
            db().execute("DELETE FROM vault_history WHERE vault_id = ?", (vid,))
            db().execute("DELETE FROM access_requests WHERE vault_id = ?", (vid,))
            db().execute("DELETE FROM vault_items WHERE id = ?", (vid,))
            db().commit()

        create_audit("VAULT_DELETED", user_id=user["id"], username=user["username"],
                     target_vault_id=vid, target_hostname=item["hostname"],
                     ip_address=self.client_ip())
        self.send_json({"ok": True})

    def handle_vault_secret(self, vid: int):
        user = self.require_auth()
        if user is None:
            return

        item = db().execute("SELECT * FROM vault_items WHERE id = ?", (vid,)).fetchone()
        if item is None:
            return self.send_json({"ok": False, "error": "Vault item not found"}, 404)

        access = evaluate_vault_item_access(user, vid, item["category"])
        if not access["can_view"]:
            return self.send_json({"ok": False, "error": "Access denied. No valid approved request or permission."}, 403)

        create_audit("SECRET_VIEWED", user_id=user["id"], username=user["username"],
                     target_vault_id=vid, target_hostname=item["hostname"],
                     ip_address=self.client_ip(),
                     details=f"source={access['source']}")
        resp = {
            "ok": True,
            "encrypted_password": item["encrypted_password"],
            "password_iv": item["password_iv"],
        }
        if access["expires_at"]:
            resp["expires_at"] = access["expires_at"]
        self.send_json(resp)

    def handle_vault_history(self, vid: int):
        user = self.require_auth()
        if user is None:
            return

        item = db().execute("SELECT id, category, hostname FROM vault_items WHERE id = ?", (vid,)).fetchone()
        if item is None:
            return self.send_json({"ok": False, "error": "Vault item not found"}, 404)

        if user["role"] != "ADMIN":
            access = evaluate_vault_item_access(user, vid, item["category"])
            if not access["can_history"]:
                return self.send_json({"ok": False, "error": "변경 이력 조회 권한이 없습니다."}, 403)

        rows = db().execute(
            "SELECT id, encrypted_password, password_iv, changed_by_username, changed_at "
            "FROM vault_history WHERE vault_id = ? ORDER BY changed_at DESC",
            (vid,),
        ).fetchall()

        history = [
            {
                "id": r["id"],
                "encrypted_password": r["encrypted_password"],
                "password_iv": r["password_iv"],
                "changed_by_username": r["changed_by_username"],
                "changed_at": r["changed_at"],
            }
            for r in rows
        ]

        create_audit("HISTORY_VIEWED", user_id=user["id"], username=user["username"],
                     target_vault_id=vid, target_hostname=item["hostname"],
                     ip_address=self.client_ip())
        self.send_json({"ok": True, "history": history})

    def handle_vault_bulk(self):
        user = self.require_auth()
        if user is None:
            return
        body = self.read_json()
        items = body.get("items", [])
        if not items or len(items) > 2000:
            return self.send_json({"ok": False, "error": "Invalid items count (1~2000)"}, 400)

        ts = now_iso()
        count = 0

        with _db_lock:
            for entry in items:
                required = ["category", "hostname", "ip_url", "account_id", "encrypted_password", "password_iv"]
                if not all(entry.get(f) for f in required):
                    continue
                division = (entry.get("division") or "").strip()
                db().execute(
                    "INSERT INTO vault_items (category, division, hostname, ip_url, port, account_id, encrypted_password, password_iv, password_fingerprint, memo, created_by, created_by_username, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        entry["category"],
                        division,
                        entry["hostname"],
                        entry["ip_url"],
                        entry.get("port", ""),
                        entry["account_id"],
                        entry["encrypted_password"],
                        entry["password_iv"],
                        entry.get("password_fingerprint", ""),
                        entry.get("memo", ""),
                        user["id"],
                        user["username"],
                        ts,
                        ts,
                    ),
                )
                count += 1
            db().commit()

        create_audit("VAULT_BULK_IMPORT", user_id=user["id"], username=user["username"],
                     ip_address=self.client_ip(), details=f"Imported {count} items")
        self.send_json({"ok": True, "count": count})

    def handle_requests_create(self):
        user = self.require_auth()
        if user is None:
            return
        if user["role"] != "OPERATOR":
            return self.send_json({"ok": False, "error": "Only operators can create access requests"}, 403)

        body = self.read_json()
        vault_id = body.get("vault_id")
        reason = body.get("reason", "").strip()

        if not vault_id or not reason:
            return self.send_json({"ok": False, "error": "vault_id and reason are required"}, 400)

        item = db().execute("SELECT hostname FROM vault_items WHERE id = ?", (vault_id,)).fetchone()
        if item is None:
            return self.send_json({"ok": False, "error": "Vault item not found"}, 404)

        ts = now_iso()
        with _db_lock:
            cur = db().execute(
                "INSERT INTO access_requests (vault_id, vault_hostname, requester_id, requester_username, reason, status, created_at) VALUES (?,?,?,?,?,?,?)",
                (vault_id, item["hostname"], user["id"], user["username"], reason, "PENDING", ts),
            )
            db().commit()
            req_id = cur.lastrowid

        create_audit("ACCESS_REQUESTED", user_id=user["id"], username=user["username"],
                     target_vault_id=vault_id, target_hostname=item["hostname"],
                     ip_address=self.client_ip(), details=reason)
        self.send_json({"ok": True, "id": req_id})

    def handle_requests_list(self, qs: dict):
        user = self.require_auth()
        if user is None:
            return

        expire_approved_requests()
        status_filter = qs.get("status", [None])[0]

        query = "SELECT id, vault_id, vault_hostname, requester_id, requester_username, reason, status, approver_username, approved_at, expires_at, rejected_reason, created_at FROM access_requests WHERE 1=1"
        params = []

        if user["role"] == "OPERATOR":
            query += " AND requester_id = ?"
            params.append(user["id"])

        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        query += " ORDER BY id DESC"
        rows = db().execute(query, params).fetchall()

        requests_list = [
            {
                "id": r["id"],
                "vault_id": r["vault_id"],
                "vault_hostname": r["vault_hostname"],
                "requester_id": r["requester_id"],
                "requester_username": r["requester_username"],
                "reason": r["reason"],
                "status": r["status"],
                "approver_username": r["approver_username"],
                "approved_at": r["approved_at"],
                "expires_at": r["expires_at"],
                "rejected_reason": r["rejected_reason"] or "",
                "created_at": r["created_at"],
            }
            for r in rows
        ]

        self.send_json({"ok": True, "requests": requests_list})

    def handle_request_approve(self, rid: int):
        user = self.require_admin()
        if user is None:
            return

        req = db().execute("SELECT * FROM access_requests WHERE id = ?", (rid,)).fetchone()
        if req is None:
            return self.send_json({"ok": False, "error": "Access request not found"}, 404)
        if req["status"] != "PENDING":
            return self.send_json({"ok": False, "error": f"Request is already {req['status']}"}, 400)

        body = self.read_json()
        try:
            ttl = int(body.get("ttl_minutes", 15))
        except (TypeError, ValueError):
            ttl = 15
        # TTL 범위 강제 (최소 5분 ~ 최대 240분)
        ttl = max(5, min(ttl, 240))

        ts = now_iso()
        expires = (datetime.utcnow() + timedelta(minutes=ttl)).isoformat()

        with _db_lock:
            db().execute(
                "UPDATE access_requests SET status='APPROVED', approver_id=?, approver_username=?, approved_at=?, expires_at=? WHERE id=?",
                (user["id"], user["username"], ts, expires, rid),
            )
            db().commit()

        create_audit("ACCESS_APPROVED", user_id=user["id"], username=user["username"],
                     target_vault_id=req["vault_id"], target_hostname=req["vault_hostname"],
                     ip_address=self.client_ip(),
                     details=f"TTL: {ttl}min, requester: {req['requester_username']}")
        self.send_json({"ok": True})

    def handle_request_reject(self, rid: int):
        user = self.require_admin()
        if user is None:
            return

        req = db().execute("SELECT * FROM access_requests WHERE id = ?", (rid,)).fetchone()
        if req is None:
            return self.send_json({"ok": False, "error": "Access request not found"}, 404)
        if req["status"] != "PENDING":
            return self.send_json({"ok": False, "error": f"Request is already {req['status']}"}, 400)

        body = self.read_json()
        reason = body.get("reason", "")

        with _db_lock:
            db().execute(
                "UPDATE access_requests SET status='REJECTED', approver_id=?, approver_username=?, rejected_reason=? WHERE id=?",
                (user["id"], user["username"], reason, rid),
            )
            db().commit()

        create_audit("ACCESS_REJECTED", user_id=user["id"], username=user["username"],
                     target_vault_id=req["vault_id"], target_hostname=req["vault_hostname"],
                     ip_address=self.client_ip(),
                     details=f"Reason: {reason}, requester: {req['requester_username']}")
        self.send_json({"ok": True})

    def handle_audit_list(self, qs: dict):
        user = self.require_auth()
        if user is None:
            return

        try:
            page = max(1, int(qs.get("page", ["1"])[0]))
        except (ValueError, TypeError):
            page = 1
        try:
            limit = max(1, min(500, int(qs.get("limit", ["50"])[0])))
        except (ValueError, TypeError):
            limit = 50

        action_filter = qs.get("action", [None])[0]

        count_query = "SELECT COUNT(*) as cnt FROM audit_logs WHERE 1=1"
        data_query = "SELECT id, action, username, target_hostname, ip_address, details, created_at FROM audit_logs WHERE 1=1"
        params = []

        # 보안 패치: 운영자(OPERATOR)는 본인의 감사 로그만 조회 가능하도록 제한
        if user["role"] != "ADMIN":
            count_query += " AND user_id = ?"
            data_query += " AND user_id = ?"
            params.append(user["id"])

        if action_filter:
            count_query += " AND action = ?"
            data_query += " AND action = ?"
            params.append(action_filter)

        total = db().execute(count_query, params).fetchone()["cnt"]

        data_query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        offset = (page - 1) * limit
        data_params = params + [limit, offset]

        rows = db().execute(data_query, data_params).fetchall()
        logs = [
            {
                "id": r["id"],
                "action": r["action"],
                "username": r["username"],
                "target_hostname": r["target_hostname"] or "",
                "ip_address": r["ip_address"] or "",
                "details": r["details"] or "",
                "created_at": r["created_at"],
            }
            for r in rows
        ]

        self.send_json({"ok": True, "logs": logs, "total": total, "page": page, "limit": limit})

    def handle_audit_log(self):
        user = self.require_auth()
        if user is None:
            return

        body = self.read_json()
        action = body.get("action", "")
        # 보안 패치: 클라이언트에서 임의의 허위 감사 로그를 주입하지 못하도록 화이트리스트 강제
        allowed_client_actions = {"SECRET_COPIED", "AUTO_LOCKED"}
        if action not in allowed_client_actions:
            return self.send_json({"ok": False, "error": "Invalid client audit action"}, 400)

        create_audit(
            action,
            user_id=user["id"],
            username=user["username"],
            target_vault_id=body.get("target_vault_id"),
            target_hostname=body.get("target_hostname"),
            ip_address=self.client_ip(),
            details=body.get("details", ""),
        )
        self.send_json({"ok": True})


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), VaultHandler)
    print(f"Vault Enterprise Hardened API server running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()