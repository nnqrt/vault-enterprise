import os
import sys
import secrets
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
import app

os.makedirs(app.DB_DIR, exist_ok=True)
app.init_db()

conn = sqlite3.connect(app.DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# 1. 관리자 계정(admin) 생성 또는 확인
admin = cur.execute("SELECT id, username, name FROM users WHERE username = 'admin'").fetchone()
ts = datetime.utcnow().isoformat()

if not admin:
    admin_salt = secrets.token_bytes(32).hex()
    admin_pw_hash = app.hash_password("Admin1234!", admin_salt)
    cur.execute(
        "INSERT INTO users (username, name, password_hash, password_salt, role, created_at) "
        "VALUES (?,?,?,?,?,?)",
        ("admin", "최고관리자", admin_pw_hash, admin_salt, "ADMIN", ts)
    )
    admin_id = cur.lastrowid
    cur.execute(
        "INSERT INTO audit_logs (action, user_id, username, ip_address, details, created_at) VALUES (?,?,?,?,?,?)",
        ("LOG_INIT_ADMIN", admin_id, "admin", "127.0.0.1", "Admin initialized for testing", ts)
    )
    print(f"[OK] 관리자 계정 생성 완료: ID='admin', PW='Admin1234!', Name='최고관리자'")
else:
    print(f"[OK] 기존 관리자 계정 존재: ID='{admin['username']}', Name='{admin['name']}'")

# 2. 더미 운용자 10명 생성 (ID: 10 ~ 19, PW: 11111111)
created_count = 0
for uid_num in range(10, 20):
    username = str(uid_num)
    existing = cur.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    salt = secrets.token_bytes(32).hex()
    pw_hash = app.hash_password("11111111", salt)

    if existing:
        cur.execute(
            "UPDATE users SET password_hash = ?, password_salt = ?, role = 'OPERATOR' WHERE id = ?",
            (pw_hash, salt, existing["id"])
        )
        print(f"  - 운용자 ID '{username}' 비밀번호를 '11111111'(으)로 갱신했습니다.")
    else:
        # 사용자명을 비워두어 관리자 메뉴에서 이름을 직접 입력하고 [저장]하여 고정되는 기능을 테스트할 수 있도록 함
        cur.execute(
            "INSERT INTO users (username, name, password_hash, password_salt, role, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (username, "", pw_hash, salt, "OPERATOR", ts)
        )
        created_count += 1
        print(f"  + 운용자 ID '{username}' 생성 완료 (PW: '11111111', 역할: OPERATOR)")

conn.commit()
conn.close()

print("\n" + "=" * 60)
print(f"총 {created_count}명의 신규 더미 운용자(10~19)가 생성되었습니다.")
print("관리자 메뉴에서 ID 확인 및 '사용자명' 입력/저장 테스트가 가능합니다.")
print("=" * 60)
