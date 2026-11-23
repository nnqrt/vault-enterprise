# Vault Enterprise - Hardened API & Architecture Specification (v2.0)

## 1. Authentication & Session Architecture
- Token-based auth using `X-Auth-Token` HTTP header
- Tokens: 64-char hex string via `secrets.token_hex(32)`
- Sessions stored in SQLite: user_id, token, created_at, last_active
- 30-minute server-side session expiry (last_active based)
- In-memory rate limiting: 5 failed attempts per IP → 300s lockout (HTTP 429)
- Constant-time password hash comparison via `hmac.compare_digest`
- Client-side 5-minute inactivity auto-lock (wipes vault key & HMAC key from memory, shows lock screen, closes open modals, sends `AUTO_LOCKED` audit)

## 2. Encryption Architecture (Client-Side WebCrypto AES-256-GCM)
- Users enter a **Vault Master Password** at login / init
- This master password NEVER leaves the browser - server never sees it
- Key derivation in browser:
  - Algorithm: PBKDF2
  - Hash: SHA-256
  - Iterations: 100,000
  - Salt: UTF-8 bytes of `"vault-enterprise-salt-v1"`
  - Key length: 256 bits
  - `extractable: false` (prevents memory extraction even under XSS)
- HMAC fingerprint derivation:
  - PBKDF2 with domain-separated salt: `"vault-enterprise-hmac-salt-v1"`
  - Hash: SHA-256
  - Iterations: 100,000
  - Key length: 256 bits
  - `extractable: false`
- Per-item encryption:
  - Generate 12-byte random IV via `crypto.getRandomValues(new Uint8Array(12))`
  - Encrypt plaintext password with AES-256-GCM using derived AES key and IV
  - Store: `base64(ciphertext+authTag)` as `encrypted_password`, `base64(iv)` as `password_iv`
- Master Key Verifier (Canary):
  - Initial setup encrypts `"VAULT_ENTERPRISE_KEY_VERIFIED_V1"` with master AES key
  - Stored in `system_config` table as `key_verifier` (`{"cipher": "...", "iv": "..."}`)
  - Returned on login & auth check; client must successfully decrypt it to activate session
  - Prevents data corruption caused by master password typos and blocks lock bypass

## 3. Database Schema (SQLite3)

```sql
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
```

## 4. API Endpoints

### GET /api/status
Check if system is initialized (any users exist).
Response: `{"ok": true, "initialized": true/false}`

### POST /api/auth/init
Create initial admin and save master key verifier token. Only works when NO users exist in DB.
Request body: `{"username": "admin", "password": "...", "verifier_cipher": "...", "verifier_iv": "..."}`
Response: `{"ok": true, "user": {"id": 1, "username": "admin", "role": "ADMIN"}}`
Audit: LOG_INIT_ADMIN

### POST /api/auth/login
Rate limited (5 attempts per IP).
Request body: `{"username": "admin", "password": "..."}`
Response: `{"ok": true, "token": "...", "user": {"id": 1, "username": "admin", "role": "ADMIN"}, "key_verifier": {"cipher": "...", "iv": "..."}}`
Audit: LOGIN_SUCCESS / LOGIN_FAILED

### POST /api/auth/logout
Deletes session.
Response: `{"ok": true}`
Audit: LOGOUT

### GET /api/auth/check
Verify token validity, update `last_active`, return user and `key_verifier`.
Response: `{"ok": true, "user": {...}, "key_verifier": {...}}`

### GET /api/users
Admin only. List all users.

### POST /api/users
Admin only. Create a new user (minimum 8-char password).

### GET /api/vault
List all vault items.
**Security Control:** `encrypted_password`, `password_iv`, and `password_fingerprint` raw hashes are NEVER returned.
Returns `is_duplicate: boolean` and `is_old: boolean` along with metadata.

### POST /api/vault
Create a new vault item.

### PUT /api/vault/<id>
Update vault item.
**Security Control:**
- Admin: Allowed.
- Operator: Only allowed if operator has an active, valid `APPROVED` access request for this vault item.
- Only writes to `vault_history` if the encrypted password or IV actually changed.

### DELETE /api/vault/<id>
Admin only. Cascade deletes item, history, and requests.

### GET /api/vault/<id>/secret
Fetch encrypted secret for client-side decryption.
- ADMIN: Always allowed.
- OPERATOR: Requires valid `APPROVED` access request with `expires_at > now`.

### GET /api/vault/<id>/history
**Security Control:** ADMIN ONLY. Prevents operator privilege escalation.

### POST /api/vault/bulk
Bulk import up to 2,000 items.

### POST /api/requests
Operator only. Submit access request with reason.

### GET /api/requests
List requests. Admin sees all; Operator sees only their own.

### PUT /api/requests/<id>/approve
Admin only. TTL bounded between 5 and 240 minutes.

### PUT /api/requests/<id>/reject
Admin only.

### GET /api/audit
**Security Control:**
- Admin: sees all audit logs.
- Operator: sees ONLY their own audit logs (`user_id = user['id']`).

### POST /api/audit/log
Client-side audit logger.
**Security Control:** Whitelisted to `SECRET_COPIED` and `AUTO_LOCKED` only.