#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vault Enterprise - 폐쇄망 전용 DB 유지보수 및 정리 도구
인터넷 연결 없이 기본 파이썬(sqlite3)만으로 실행 가능합니다.
"""

import os
import sys
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "vault.db")


def get_conn():
    if not os.path.exists(DB_PATH):
        print(f"[오류] 데이터베이스 파일을 찾을 수 없습니다: {DB_PATH}")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def list_users():
    conn = get_conn()
    cur = conn.cursor()
    cols = {r["name"] for r in cur.execute("PRAGMA table_info(users)").fetchall()}
    has_name = "name" in cols
    query = "SELECT id, username, " + ("name, " if has_name else "'' as name, ") + "role, created_at FROM users ORDER BY id"
    users = cur.execute(query).fetchall()
    print("\n" + "=" * 80)
    print(f"{'Num':<6}{'ID':<18}{'사용자명(Name)':<18}{'역할(Role)':<14}{'생성일시(Created At)':<24}")
    print("-" * 80)
    for u in users:
        u_name = u['name'] if u['name'] else '-'
        print(f"{u['id']:<6}{u['username']:<18}{u_name:<18}{u['role']:<14}{u['created_at']:<24}")
    print("=" * 80 + "\n")
    conn.close()


def delete_user(target):
    conn = get_conn()
    cur = conn.cursor()

    # ID 또는 사용자명으로 대상 조회
    if str(target).isdigit():
        user = cur.execute("SELECT id, username, role FROM users WHERE id = ?", (int(target),)).fetchone()
    else:
        user = cur.execute("SELECT id, username, role FROM users WHERE username = ?", (str(target),)).fetchone()

    if not user:
        print(f"[오류] 사용자를 찾을 수 없습니다: '{target}'")
        conn.close()
        return

    uid = user["id"]
    uname = user["username"]
    role = user["role"]

    # 관리자 계정 삭제 시 최소 1명의 관리자 유지 체크
    if role == "ADMIN":
        admin_count = cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'ADMIN'").fetchone()["cnt"]
        if admin_count <= 1:
            print("[오류] 시스템에 최소 1명의 관리자(ADMIN)가 존재해야 합니다. 삭제할 수 없습니다.")
            conn.close()
            return

    # 잔여 다른 관리자 계정 탐색 (소유권 이전을 위해)
    other_admin = cur.execute(
        "SELECT id, username FROM users WHERE role = 'ADMIN' AND id != ? ORDER BY id LIMIT 1",
        (uid,),
    ).fetchone()

    print(f"\n[안내] 삭제 대상 계정: ID={uid}, 사용자명='{uname}', 역할={role}")
    confirm = input(f"정말로 '{uname}' 계정을 삭제하시겠습니까? (yes/no): ").strip().lower()
    if confirm not in ("y", "yes"):
        print("[취소] 삭제 작업을 취소했습니다.")
        conn.close()
        return

    try:
        # 1. 활성 세션 정리
        cur.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))

        # 2. 개별 권한 정책 정리
        cur.execute("DELETE FROM user_permissions WHERE user_id = ? OR granted_by = ?", (uid, uid))

        # 3. 비밀번호 요청 내역 정리
        cur.execute("DELETE FROM access_requests WHERE requester_id = ? OR approver_id = ?", (uid, uid))

        # 4. 등록한 비밀번호(vault_items) 소유권 이전 (존재할 경우)
        owned_vaults = cur.execute("SELECT COUNT(*) as cnt FROM vault_items WHERE created_by = ?", (uid,)).fetchone()["cnt"]
        if owned_vaults > 0 and other_admin:
            cur.execute(
                "UPDATE vault_items SET created_by = ?, created_by_username = ? WHERE created_by = ?",
                (other_admin["id"], other_admin["username"], uid),
            )
            print(f"  - 해당 계정이 등록했던 볼트 아이템 {owned_vaults}개의 소유자를 '{other_admin['username']}'(으)로 이전했습니다.")

        # 5. 히스토리 기록 작성자 정보 업데이트 (외래키 제약 준수)
        cur.execute(
            "UPDATE vault_history SET changed_by = ? WHERE changed_by = ?",
            (other_admin["id"] if other_admin else 1, uid),
        )

        # 6. 사용자 삭제
        cur.execute("DELETE FROM users WHERE id = ?", (uid,))

        conn.commit()
        print(f"[완료] 계정 '{uname}'(ID: {uid})이 성공적으로 삭제되었습니다.\n")
    except Exception as e:
        conn.rollback()
        print(f"[실패] 계정 삭제 중 오류 발생: {e}")
    finally:
        conn.close()


def clear_audit_logs():
    conn = get_conn()
    cur = conn.cursor()
    cnt = cur.execute("SELECT COUNT(*) as cnt FROM audit_logs").fetchone()["cnt"]
    print(f"\n현재 저장된 감사 로그 건수: {cnt}건")
    confirm = input("모든 감사 로그를 영구 삭제하시겠습니까? (yes/no): ").strip().lower()
    if confirm not in ("y", "yes"):
        print("[취소] 삭제 작업을 취소했습니다.")
        conn.close()
        return

    try:
        cur.execute("DELETE FROM audit_logs;")
        # AUTOINCREMENT 시퀀스 초기화
        cur.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_logs';")
        conn.commit()
        # DB 파일 용량 정리 및 최적화
        cur.execute("VACUUM;")
        print("[완료] 모든 감사 로그가 삭제되었으며, DB 파일 공간이 최적화되었습니다.\n")
    except Exception as e:
        conn.rollback()
        print(f"[실패] 감사 로그 삭제 중 오류 발생: {e}")
    finally:
        conn.close()


def set_user_role(target, new_role):
    new_role = new_role.upper()
    if new_role not in ("ADMIN", "OPERATOR"):
        print("[오류] 역할은 'ADMIN' 또는 'OPERATOR'만 가능합니다.")
        return

    conn = get_conn()
    cur = conn.cursor()
    if str(target).isdigit():
        user = cur.execute("SELECT id, username, role FROM users WHERE id = ?", (int(target),)).fetchone()
    else:
        user = cur.execute("SELECT id, username, role FROM users WHERE username = ?", (str(target),)).fetchone()

    if not user:
        print(f"[오류] 사용자를 찾을 수 없습니다: '{target}'")
        conn.close()
        return

    uid = user["id"]
    if user["role"] == "ADMIN" and new_role != "ADMIN":
        admin_count = cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'ADMIN'").fetchone()["cnt"]
        if admin_count <= 1:
            print("[오류] 최소 1명의 관리자(ADMIN)가 유지되어야 합니다.")
            conn.close()
            return

    cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
    conn.commit()
    print(f"[완료] 사용자 '{user['username']}'의 역할이 '{user['role']}' -> '{new_role}'(으)로 변경되었습니다.\n")
    conn.close()


def show_help():
    print("""
[Vault Enterprise 폐쇄망 유지보수 도구 사용법]

1. 전체 사용자 목록 조회:
   python clean_maintenance.py list

2. 특정 계정 삭제 (중복 생성된 Admin 또는 admin 삭제):
   python clean_maintenance.py delete <사용자명 또는 ID>
   예시) python clean_maintenance.py delete Admin

3. 감사 로그 전체 삭제 및 DB 최적화:
   python clean_maintenance.py clear-audit

4. 사용자 역할 변경 (user 계정을 OPERATOR로 강제 변경 시):
   python clean_maintenance.py role <사용자명> <ADMIN|OPERATOR>
   예시) python clean_maintenance.py role user OPERATOR
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_help()
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd in ("list", "list-users", "-l"):
        list_users()
    elif cmd in ("delete", "del", "remove"):
        if len(sys.argv) < 3:
            print("[오류] 삭제할 사용자명 또는 ID를 입력하세요. 예: python clean_maintenance.py delete Admin")
        else:
            delete_user(sys.argv[2])
    elif cmd in ("clear-audit", "clean-audit", "clear_audit"):
        clear_audit_logs()
    elif cmd in ("role", "set-role"):
        if len(sys.argv) < 4:
            print("[오류] 사용자명과 역할을 입력하세요. 예: python clean_maintenance.py role user OPERATOR")
        else:
            set_user_role(sys.argv[2], sys.argv[3])
    else:
        show_help()
