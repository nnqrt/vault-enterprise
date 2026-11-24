#!/usr/bin/env python3
"""
Vault Enterprise - CLI 초기 관리자 계정 생성 도구
웹 화면을 거치지 않고 터미널에서 즉시 관리자 계정을 생성합니다.
"""

import sys
import os
import secrets
import hashlib
import sqlite3
from datetime import datetime

# 프로젝트 디렉토리 경로
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "vault.db")

def init_db(conn):
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'OPERATOR')),
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
    """)
    conn.commit()

def hash_password(password: str, salt_hex: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 600000
    ).hex()
    return f"pbkdf2_sha256$600000${digest}"

def main():
    username = sys.argv[1] if len(sys.argv) > 1 else "admin"
    password = sys.argv[2] if len(sys.argv) > 2 else "Admin1234!"
    name = sys.argv[3] if len(sys.argv) > 3 else "관리자"

    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    # name 컬럼 마이그레이션
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "name" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT ''")
        conn.commit()

    cur = conn.cursor()
    existing = cur.execute("SELECT id, role, name FROM users WHERE username = ?", (username,)).fetchone()
    ts = datetime.utcnow().isoformat()

    salt = secrets.token_bytes(32).hex()
    pw_hash = hash_password(password, salt)

    if existing:
        cur.execute(
            "UPDATE users SET password_hash = ?, password_salt = ?, role = 'ADMIN', name = CASE WHEN name = '' THEN ? ELSE name END WHERE id = ?",
            (pw_hash, salt, name, existing["id"])
        )
        cur.execute(
            "INSERT INTO audit_logs (action, user_id, username, ip_address, details, created_at) VALUES (?,?,?,?,?,?)",
            ("USER_PASSWORD_RESET", existing["id"], username, "127.0.0.1 (CLI)", f"Password reset & ADMIN role renewed via create_admin.py", ts)
        )
        conn.commit()
        print(f"[OK] 기존 계정 '{username}'의 비밀번호를 업데이트하고 ADMIN 권한을 재부여했습니다.")
    else:
        cur.execute(
            "INSERT INTO users (username, name, password_hash, password_salt, role, created_at) VALUES (?,?,?,?,?,?)",
            (username, name, pw_hash, salt, "ADMIN", ts)
        )
        user_id = cur.lastrowid
        cur.execute(
            "INSERT INTO audit_logs (action, user_id, username, ip_address, details, created_at) VALUES (?,?,?,?,?,?)",
            ("LOG_INIT_ADMIN", user_id, username, "127.0.0.1 (CLI)", f"Created via create_admin.py (Name: {name})", ts)
        )
        conn.commit()
        print(f"[OK] 신규 관리자 계정 '{username}'(사용자명: {name})이 성공적으로 생성되었습니다.")

    conn.close()
    print("-" * 50)
    print(f"  아이디 (ID)      : {username}")
    print(f"  비밀번호 (PW)    : {password}")
    print(f"  DB 파일 경로     : {DB_PATH}")
    print("-" * 50)
    print("※ 로그인 시 필요한 'Vault 마스터 비밀번호'는 브라우저 암호화용이므로,")
    print("  원하시는 임의의 안전한 마스터 암호를 입력하시면 됩니다.")

if __name__ == "__main__":
    main()