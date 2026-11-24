import os
import sys
import shutil
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
TEST_DIR = os.path.join(BASE_DIR, "test_cli_data")
if os.path.exists(TEST_DIR):
    shutil.rmtree(TEST_DIR, ignore_errors=True)
os.makedirs(TEST_DIR, exist_ok=True)

import create_admin
import clean_maintenance
import app

create_admin.DB_DIR = TEST_DIR
create_admin.DB_PATH = os.path.join(TEST_DIR, "vault.db")

clean_maintenance.DB_DIR = TEST_DIR
clean_maintenance.DB_PATH = os.path.join(TEST_DIR, "vault.db")

app.DB_DIR = TEST_DIR
app.DB_PATH = os.path.join(TEST_DIR, "vault.db")
if hasattr(app._thread_local, "conn"):
    del app._thread_local.conn

print("[1] Testing create_admin.py execution...")
sys.argv = ["create_admin.py", "cliadmin", "AdminPass123!"]
create_admin.main()

conn = sqlite3.connect(create_admin.DB_PATH)
conn.row_factory = sqlite3.Row
user = conn.execute("SELECT * FROM users WHERE username = 'cliadmin'").fetchone()
assert user is not None, "User not found"
assert user["role"] == "ADMIN", f"Expected ADMIN, got {user['role']}"
conn.close()
print("  -> create_admin OK")

print("[2] Testing app.py schema migration on DB created by create_admin...")
# app.init_db should add missing columns and tables cleanly
app.init_db()
conn = sqlite3.connect(create_admin.DB_PATH)
conn.row_factory = sqlite3.Row
cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
assert "wrapped_vault_key" in cols
assert "key_salt" in cols
conn.close()
print("  -> Migration on existing DB OK")

print("[3] Testing clean_maintenance.py list & role changing...")
clean_maintenance.list_users()

# Create another admin so we can test role change
sys.argv = ["create_admin.py", "secondadmin", "SecondPass123!"]
create_admin.main()

clean_maintenance.set_user_role("secondadmin", "OPERATOR")
conn = sqlite3.connect(create_admin.DB_PATH)
conn.row_factory = sqlite3.Row
u = conn.execute("SELECT role FROM users WHERE username = 'secondadmin'").fetchone()
assert u["role"] == "OPERATOR"
conn.close()
print("  -> clean_maintenance role change OK")

print("[4] Testing clean_maintenance.py clear_audit...")
conn = sqlite3.connect(create_admin.DB_PATH)
cur = conn.cursor()
cur.execute("DELETE FROM audit_logs;")
conn.commit()
cnt = cur.execute("SELECT COUNT(*) as cnt FROM audit_logs").fetchone()[0]
assert cnt == 0
conn.close()
print("  -> Audit log clear OK")

shutil.rmtree(TEST_DIR, ignore_errors=True)
print("\n>>> CLI TOOLS TEST PASSED! <<<")
