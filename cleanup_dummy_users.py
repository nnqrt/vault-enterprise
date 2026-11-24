import os
import sys
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
import app

if not os.path.exists(app.DB_PATH):
    print("데이터베이스 파일이 존재하지 않습니다.")
    sys.exit(0)

conn = sqlite3.connect(app.DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

dummy_ids = [str(i) for i in range(10, 20)]
placeholders = ",".join("?" for _ in dummy_ids)

users = cur.execute(f"SELECT id, username FROM users WHERE username IN ({placeholders})", dummy_ids).fetchall()

if not users:
    print("[안내] 삭제할 더미 운용자(ID: 10~19)가 존재하지 않습니다.")
    conn.close()
    sys.exit(0)

uids = [u["id"] for u in users]
uid_placeholders = ",".join("?" for _ in uids)

# 세션, 권한, 요청 내역 정리
cur.execute(f"DELETE FROM sessions WHERE user_id IN ({uid_placeholders})", uids)
cur.execute(f"DELETE FROM user_permissions WHERE user_id IN ({uid_placeholders})", uids)
cur.execute(f"DELETE FROM access_requests WHERE requester_id IN ({uid_placeholders})", uids)

# 사용자 삭제
cur.execute(f"DELETE FROM users WHERE id IN ({uid_placeholders})", uids)
conn.commit()
conn.close()

print(f"[완료] 더미 운용자 {len(users)}명(ID: 10~19)이 정상적으로 모두 삭제되었습니다.")
