import os
import sys
import json
import time
import shutil
import urllib.request
import urllib.parse
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
TEST_DATA_DIR = os.path.join(BASE_DIR, "test_updated_data")
if os.path.exists(TEST_DATA_DIR):
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
os.makedirs(TEST_DATA_DIR, exist_ok=True)

import app

app.DB_DIR = TEST_DATA_DIR
app.DB_PATH = os.path.join(TEST_DATA_DIR, "vault.db")
app.PORT = 8998
app.HOST = "127.0.0.1"

if hasattr(app._thread_local, "conn"):
    del app._thread_local.conn

app.init_db()

server = app.ThreadingHTTPServer((app.HOST, app.PORT), app.VaultHandler)
server_thread = threading.Thread(target=server.serve_forever, daemon=True)
server_thread.start()
time.sleep(0.5)

BASE_URL = f"http://{app.HOST}:{app.PORT}"

def req(path, method="GET", data=None, token=None):
    url = f"{BASE_URL}{path}"
    headers = {}
    if token:
        headers["X-Auth-Token"] = token
    req_body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        req_body = json.dumps(data).encode("utf-8")
    
    request_obj = urllib.request.Request(url, data=req_body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request_obj) as resp:
            body = resp.read()
            ct = resp.headers.get("Content-Type", "")
            if "application/json" in ct:
                return resp.status, json.loads(body.decode("utf-8"))
            return resp.status, body
    except urllib.error.HTTPError as e:
        err_body = e.read()
        try:
            return e.code, json.loads(err_body.decode("utf-8"))
        except Exception:
            return e.code, err_body

print("[1] Testing initial setup with ID & Name...")
init_data = {
    "username": "admin",
    "name": "최고관리자",
    "password": "AdminPassword123!",
    "verifier_cipher": "test_c",
    "verifier_iv": "test_iv",
}
status, res = req("/api/auth/init", method="POST", data=init_data)
assert status == 200 and res.get("ok") is True
assert res["user"]["username"] == "admin"
assert res["user"]["name"] == "최고관리자"
print("  -> Init with Name '최고관리자' OK")

print("[2] Testing login and auth check user info...")
login_data = {"username": "admin", "password": "AdminPassword123!"}
status, res = req("/api/auth/login", method="POST", data=login_data)
assert status == 200 and res["ok"] is True
admin_token = res["token"]
assert res["user"]["name"] == "최고관리자"

status, res = req("/api/auth/check", token=admin_token)
assert status == 200 and res["user"]["name"] == "최고관리자"
print("  -> Login and check return Name OK")

print("[3] Testing user creation with ID and Name...")
user1_data = {
    "username": "hong",
    "name": "홍길동",
    "password": "HongPassword123!",
    "role": "OPERATOR"
}
status, res = req("/api/users", method="POST", data=user1_data, token=admin_token)
assert status == 200 and res.get("ok") is True
hong_id = res["id"]

# Create another user without name initially (to test name setting)
user2_data = {
    "username": "kim",
    "name": "",
    "password": "KimPassword123!",
    "role": "OPERATOR"
}
status, res = req("/api/users", method="POST", data=user2_data, token=admin_token)
assert status == 200 and res.get("ok") is True
kim_id = res["id"]

status, res = req("/api/users", token=admin_token)
users = {u["username"]: u for u in res["users"]}
assert users["hong"]["name"] == "홍길동"
print("  -> User creation with ID & Name OK")

print("[4] Testing PUT /api/users/<id>/name (immutable once set)...")
# User kim has no name yet, setting name should succeed
status, res = req(f"/api/users/{kim_id}/name", method="PUT", data={"name": "김철수"}, token=admin_token)
assert status == 200 and res.get("ok") is True
assert res["name"] == "김철수"

# Verify kim now has name '김철수'
status, res = req("/api/users", token=admin_token)
users = {u["username"]: u for u in res["users"]}
assert users["kim"]["name"] == "김철수"

# Attempting to modify kim's name again MUST FAIL (400)
status, res = req(f"/api/users/{kim_id}/name", method="PUT", data={"name": "김영희"}, token=admin_token)
assert status == 400, f"Expected 400, got {status}: {res}"
assert "수정할 수 없습니다" in res.get("error", "")

# Attempting to modify hong's name MUST FAIL (400)
status, res = req(f"/api/users/{hong_id}/name", method="PUT", data={"name": "홍길순"}, token=admin_token)
assert status == 400, f"Expected 400, got {status}: {res}"
assert "수정할 수 없습니다" in res.get("error", "")
print("  -> Immutability of 사용자명 (once set, cannot be modified) verified OK")

print("[5] Testing vault item creation & interactions...")
v1_data = {
    "category": "서버",
    "division": "인프라",
    "hostname": "web-server-01",
    "ip_url": "10.10.1.10",
    "account_id": "root",
    "encrypted_password": "enc_pw_1",
    "password_iv": "iv_1",
}
status, res = req("/api/vault", method="POST", data=v1_data, token=admin_token)
v1_id = res["id"]

v2_data = {
    "category": "DB",
    "division": "데이터",
    "hostname": "db-server-01",
    "ip_url": "10.10.2.10",
    "account_id": "postgres",
    "encrypted_password": "enc_pw_2",
    "password_iv": "iv_2",
}
status, res = req("/api/vault", method="POST", data=v2_data, token=admin_token)
v2_id = res["id"]

# Login as hong
status, res = req("/api/auth/login", method="POST", data={"username": "hong", "password": "HongPassword123!"})
hong_token = res["token"]

# Grant hong view permission for category '서버'
perm_data = {
    "user_id": hong_id,
    "permission_level": "VIEW_ONLY",
    "scope_type": "CATEGORY",
    "scope_values": ["서버"],
}
status, res = req("/api/admin/permissions", method="POST", data=perm_data, token=admin_token)
assert status == 200

# Hong views web-server-01 secret (view action)
status, res = req(f"/api/vault/{v1_id}/secret?action=view", token=hong_token)
assert status == 200

# Hong copies web-server-01 secret (copy action)
status, res = req(f"/api/vault/{v1_id}/secret?action=copy", token=hong_token)
assert status == 200

# Admin views db-server-01 detail (VAULT_VIEWED)
status, res = req(f"/api/vault/{v2_id}", token=admin_token)
assert status == 200

print("[6] Testing dashboard analytics activity identification...")
status, res = req("/api/dashboard/analytics", token=admin_token)
assert status == 200 and res.get("ok") is True

today_visitors = res["visitors"]["today"]
print(f"  -> Today visitors count: {len(today_visitors)}")
v_map = {v["username"]: v for v in today_visitors}

# Both admin and hong MUST appear in today_visitors!
assert "admin" in v_map, "admin missing from today_visitors"
assert "hong" in v_map, "hong missing from today_visitors"

# Check that Name is correctly associated
assert v_map["admin"]["name"] == "최고관리자"
assert v_map["hong"]["name"] == "홍길동"

# Check activity counts: hong logged in and had view/copy actions
assert v_map["hong"]["activity_count"] >= 3, f"Expected >=3 activities for hong, got {v_map['hong']['activity_count']}"
print(f"  -> Hong activities identified: {v_map['hong']['activity_count']} actions, name={v_map['hong']['name']}")

# Check top_devices: web-server-01 should be #1 frequently viewed device
top_devices = res["top_devices"]
print(f"  -> Top devices: {top_devices}")
assert len(top_devices) >= 1
assert top_devices[0]["hostname"] == "web-server-01"
assert top_devices[0]["count"] >= 2
assert top_devices[0]["category"] == "서버"

# Check trend_7d: today should have secrets views >= 2
today_trend = res["trend_7d"][-1]
assert today_trend["secrets"] >= 2, f"Expected >= 2 secrets in trend, got {today_trend['secrets']}"
assert today_trend["logins"] >= 2, f"Expected >= 2 logins in trend, got {today_trend['logins']}"
print(f"  -> 7-day trend today metrics: logins={today_trend['logins']}, secrets={today_trend['secrets']}, failures={today_trend['failures']}")

server.shutdown()
shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
print("\n>>> ALL UPDATED FEATURE & BUG FIX TESTS PASSED SUCCESSFULLY! <<<")
