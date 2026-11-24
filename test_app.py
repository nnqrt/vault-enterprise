import os
import sys
import json
import time
import shutil
import urllib.request
import urllib.parse
import threading

# Set temporary DB path for testing so we don't mess up any existing data
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
TEST_DATA_DIR = os.path.join(BASE_DIR, "test_data")
if os.path.exists(TEST_DATA_DIR):
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
os.makedirs(TEST_DATA_DIR, exist_ok=True)

import app

# Override paths
app.DB_DIR = TEST_DATA_DIR
app.DB_PATH = os.path.join(TEST_DATA_DIR, "vault.db")
app.PORT = 8999
app.HOST = "127.0.0.1"

# Reset thread local
if hasattr(app._thread_local, "conn"):
    del app._thread_local.conn

app.init_db()

# Start server in thread
server = app.ThreadingHTTPServer((app.HOST, app.PORT), app.VaultHandler)
server_thread = threading.Thread(target=server.serve_forever, daemon=True)
server_thread.start()
time.sleep(0.5)

BASE_URL = f"http://{app.HOST}:{app.PORT}"

def request(path, method="GET", data=None, token=None):
    url = f"{BASE_URL}{path}"
    headers = {}
    if token:
        headers["X-Auth-Token"] = token
    req_body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        req_body = json.dumps(data).encode("utf-8")
    
    req = urllib.request.Request(url, data=req_body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return resp.status, json.loads(body.decode("utf-8"))
            return resp.status, body
    except urllib.error.HTTPError as e:
        err_body = e.read()
        try:
            return e.code, json.loads(err_body.decode("utf-8"))
        except Exception:
            return e.code, err_body

print("[1] Testing server startup and frontend index...")
status, body = request("/")
assert status == 200, f"Expected 200, got {status}"
assert b"Vault Enterprise" in body or b"<!DOCTYPE html>" in body, "Frontend content check failed"
print("  -> Frontend index served OK")

print("[2] Testing /api/status before init...")
status, res = request("/api/status")
assert status == 200 and res.get("initialized") is False, f"Init check failed: {res}"
print("  -> /api/status returns uninitialized OK")

print("[3] Testing /api/auth/init...")
init_payload = {
    "username": "admin",
    "password": "Password123!",
    "verifier_cipher": "test_cipher",
    "verifier_iv": "test_iv",
    "wrapped_vault_key": "wrapped_k",
    "wrapped_vault_key_iv": "wrapped_iv",
    "key_salt": "key_salt_hex"
}
status, res = request("/api/auth/init", method="POST", data=init_payload)
assert status == 200 and res.get("ok") is True, f"Auth init failed: {res}"
print("  -> Auth init OK")

print("[4] Testing /api/status after init...")
status, res = request("/api/status")
assert status == 200 and res.get("initialized") is True, f"Init check failed: {res}"
print("  -> /api/status returns initialized OK")

print("[5] Testing /api/auth/login for admin...")
login_payload = {"username": "admin", "password": "Password123!"}
status, res = request("/api/auth/login", method="POST", data=login_payload)
assert status == 200 and res.get("ok") is True, f"Login failed: {res}"
admin_token = res["token"]
assert admin_token and len(admin_token) == 64, "Invalid token length"
assert res.get("key_verifier") is not None, "Missing key_verifier"
print("  -> Admin login OK, token received")

print("[6] Testing /api/auth/check...")
status, res = request("/api/auth/check", token=admin_token)
assert status == 200 and res.get("ok") is True, f"Auth check failed: {res}"
assert res["user"]["role"] == "ADMIN"
print("  -> Auth check OK")

print("[7] Testing user creation (operator)...")
user_payload = {
    "username": "operator1",
    "password": "OperatorPassword123!",
    "role": "OPERATOR"
}
status, res = request("/api/users", method="POST", data=user_payload, token=admin_token)
assert status == 200 and res.get("ok") is True, f"Create user failed: {res}"
operator_id = res["id"]
print("  -> Operator user created OK")

print("[8] Testing operator login...")
op_login = {"username": "operator1", "password": "OperatorPassword123!"}
status, res = request("/api/auth/login", method="POST", data=op_login)
assert status == 200 and res.get("ok") is True, f"Operator login failed: {res}"
op_token = res["token"]
print("  -> Operator login OK")

print("[9] Testing vault item creation...")
vault_payload = {
    "category": "서버",
    "division": "인프라팀",
    "hostname": "prod-db-01",
    "ip_url": "192.168.1.100",
    "port": "22",
    "account_id": "root",
    "encrypted_password": "cipher_text_test",
    "password_iv": "iv_test",
    "password_fingerprint": "fp_hash_1",
    "memo": "Production Database Server"
}
status, res = request("/api/vault", method="POST", data=vault_payload, token=admin_token)
assert status == 200 and res.get("ok") is True, f"Vault create failed: {res}"
item_id = res["id"]
print(f"  -> Vault item created (id: {item_id}) OK")

print("[10] Testing vault item listing & secret access...")
status, res = request("/api/vault", token=admin_token)
assert status == 200 and res.get("total") == 1
assert res["items"][0]["hostname"] == "prod-db-01"
# Admin should be able to view secret
status, res = request(f"/api/vault/{item_id}/secret", token=admin_token)
assert status == 200 and res.get("encrypted_password") == "cipher_text_test"
print("  -> Admin vault list & secret access OK")

print("[11] Testing operator access restrictions...")
# Operator should be denied secret access without approved request or permission
status, res = request(f"/api/vault/{item_id}/secret", token=op_token)
assert status == 403, f"Expected 403, got {status}: {res}"
print("  -> Operator secret access properly denied (403) OK")

print("[12] Testing access request workflow...")
req_payload = {"vault_id": item_id, "reason": "Emergency maintenance"}
status, res = request("/api/requests", method="POST", data=req_payload, token=op_token)
assert status == 200 and res.get("ok") is True, f"Request create failed: {res}"
req_id = res["id"]

# Admin approves request
approve_payload = {"ttl_minutes": 30}
status, res = request(f"/api/requests/{req_id}/approve", method="PUT", data=approve_payload, token=admin_token)
assert status == 200 and res.get("ok") is True, f"Request approve failed: {res}"

# Operator now has access!
status, res = request(f"/api/vault/{item_id}/secret", token=op_token)
assert status == 200 and res.get("encrypted_password") == "cipher_text_test", f"Operator access failed: {res}"
print("  -> Access request & approval workflow OK")

print("[13] Testing bulk vault import...")
bulk_payload = {
    "items": [
        {
            "category": "네트워크",
            "division": "보안팀",
            "hostname": "firewall-01",
            "ip_url": "10.0.0.1",
            "port": "443",
            "account_id": "admin",
            "encrypted_password": "fw_cipher",
            "password_iv": "fw_iv",
            "password_fingerprint": "fp_hash_1", # Duplicate fingerprint test
            "memo": "Main Firewall"
        },
        {
            "category": "보안장비",
            "division": "보안팀",
            "hostname": "vpn-gw-01",
            "ip_url": "10.0.0.2",
            "account_id": "admin",
            "encrypted_password": "vpn_cipher",
            "password_iv": "vpn_iv",
            "password_fingerprint": "fp_hash_2",
            "memo": "SSL VPN"
        }
    ]
}
status, res = request("/api/vault/bulk", method="POST", data=bulk_payload, token=admin_token)
assert status == 200 and res.get("count") == 2, f"Bulk import failed: {res}"

# Verify duplicate detection
status, res = request("/api/vault", token=admin_token)
assert res["total"] == 3
dup_items = [i for i in res["items"] if i["is_duplicate"]]
assert len(dup_items) == 2, f"Expected 2 duplicate items, got {len(dup_items)}"
print("  -> Bulk import and duplicate fingerprint detection OK")

print("[14] Testing dashboard analytics...")
status, res = request("/api/dashboard/analytics", token=admin_token)
assert status == 200 and res.get("ok") is True, f"Dashboard analytics failed: {res}"
assert res["summary"]["total_items"] == 3
print("  -> Dashboard analytics OK")

print("[15] Testing audit logs & security isolation...")
# Client audit log whitelist check
status, res = request("/api/audit/log", method="POST", data={"action": "SECRET_COPIED", "target_hostname": "prod-db-01"}, token=op_token)
assert status == 200 and res.get("ok") is True
# Invalid action should be blocked
status, res = request("/api/audit/log", method="POST", data={"action": "FAKE_ACTION"}, token=op_token)
assert status == 400

# Operator audit isolation: operator sees only their own logs
status, res = request("/api/audit", token=op_token)
assert status == 200
for log in res["logs"]:
    assert log["username"] == "operator1", f"Operator saw another user's log: {log}"
print("  -> Audit log recording and row-level isolation OK")

# Clean up
server.shutdown()
shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
print("\n>>> ALL 15 AUTOMATED TESTS PASSED SUCCESSFULLY! <<<")
