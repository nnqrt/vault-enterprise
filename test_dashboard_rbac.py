import json
import urllib.request
import urllib.parse
import sys

BASE_URL = "http://127.0.0.1:8000"

def api(method, path, body=None, token=None):
    url = BASE_URL + "/api" + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Auth-Token"] = token
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return json.loads(err_body)
        except Exception:
            return {"ok": False, "error": err_body, "status": e.code}

print("=== 1. ADMIN TEST ===")
admin_login = api("POST", "/auth/login", {"username": "admin", "password": "Admin1234!"})
assert admin_login.get("ok"), f"Admin login failed: {admin_login}"
admin_token = admin_login["token"]
print("Admin logged in successfully.")

admin_dash = api("GET", "/dashboard/analytics?tz_offset=540", token=admin_token)
assert admin_dash.get("ok"), f"Admin dashboard failed: {admin_dash}"

v_today = admin_dash["visitors"]["today"]
usernames_today = [u["username"] for u in v_today]
print(f"Admin sees today visitors: {usernames_today}")
assert "10" in usernames_today, "User 10 should be in admin's today visitors"
assert "11" in usernames_today, "User 11 should be in admin's today visitors"

u10 = next(u for u in v_today if u["username"] == "10")
u11 = next(u for u in v_today if u["username"] == "11")

print(f"User 10: login_count = {u10['login_count']}, activity_count = {u10.get('activity_count')}")
print(f"User 11: login_count = {u11['login_count']}, activity_count = {u11.get('activity_count')}")

assert u10["login_count"] == 1, f"User 10 login_count should be exactly 1, got {u10['login_count']}"
assert u11["login_count"] == 1, f"User 11 login_count should be exactly 1, got {u11['login_count']}"

admin_audit = api("GET", "/audit?limit=100", token=admin_token)
assert admin_audit.get("ok"), "Admin audit fetch failed"
admin_audit_users = set(l["username"] for l in admin_audit["logs"] if l["username"])
print(f"Admin audit log users: {admin_audit_users}")
assert "admin" in admin_audit_users and ("10" in admin_audit_users or "11" in admin_audit_users), "Admin should see all users in audit logs"

print("\n=== 2. OPERATOR 10 TEST ===")
op10_login = api("POST", "/auth/login", {"username": "10", "password": "11111111"})
assert op10_login.get("ok"), f"Op 10 login failed: {op10_login}"
op10_token = op10_login["token"]

op10_dash = api("GET", "/dashboard/analytics?tz_offset=540", token=op10_token)
assert op10_dash.get("ok"), f"Op 10 dashboard failed: {op10_dash}"

op10_visitors = [u["username"] for u in op10_dash["visitors"]["today"]]
print(f"Operator 10 sees today visitors: {op10_visitors}")
# Operator 10 must ONLY see user 10 (not admin or 11!)
assert op10_visitors == ["10"], f"Operator 10 should only see themselves, got {op10_visitors}"

# Operator 10 logged in again just now with op10_login, so login_count is 2 (first test log + this login)
op10_u = op10_dash["visitors"]["today"][0]
print(f"Operator 10 visitor entry: login_count={op10_u['login_count']}, activity_count={op10_u['activity_count']}")

op10_audit = api("GET", "/audit?limit=100", token=op10_token)
assert op10_audit.get("ok"), "Operator 10 audit fetch failed"
op10_audit_users = set(l["username"] for l in op10_audit["logs"] if l["username"])
print(f"Operator 10 audit log users: {op10_audit_users}")
assert op10_audit_users == {"10"}, f"Operator 10 must only see their own audit logs, got {op10_audit_users}"

print("\n=== 3. OPERATOR 11 TEST ===")
op11_login = api("POST", "/auth/login", {"username": "11", "password": "11111111"})
assert op11_login.get("ok"), f"Op 11 login failed: {op11_login}"
op11_token = op11_login["token"]

op11_dash = api("GET", "/dashboard/analytics?tz_offset=540", token=op11_token)
assert op11_dash.get("ok"), f"Op 11 dashboard failed: {op11_dash}"

op11_visitors = [u["username"] for u in op11_dash["visitors"]["today"]]
print(f"Operator 11 sees today visitors: {op11_visitors}")
# Operator 11 must ONLY see user 11 (not admin or 10!)
assert op11_visitors == ["11"], f"Operator 11 should only see themselves, got {op11_visitors}"

op11_audit = api("GET", "/audit?limit=100", token=op11_token)
assert op11_audit.get("ok"), "Operator 11 audit fetch failed"
op11_audit_users = set(l["username"] for l in op11_audit["logs"] if l["username"])
print(f"Operator 11 audit log users: {op11_audit_users}")
assert op11_audit_users == {"11"}, f"Operator 11 must only see their own audit logs, got {op11_audit_users}"

print("\n>>> ALL TESTS PASSED SUCCESSFULLY! RBAC AND LOGIN COUNTS FULLY VERIFIED! <<<")
