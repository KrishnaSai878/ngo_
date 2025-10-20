#!/usr/bin/env python3
import os
import sys
import json

# Ensure project root on sys.path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app
from database.models import AdminRole, AdminUserRole, User


def main():
    with app.app_context():
        roles = AdminRole.query.all()
        print("== Roles ==")
        if not roles:
            print("(none)")
        for r in roles:
            perms = json.loads(r.permissions or '{}')
            print(f"ROLE id={r.id} name={r.name} permissions={perms}")

        print("\n== Active Role Assignments ==")
        assigns = AdminUserRole.query.filter_by(is_active=True).all()
        if not assigns:
            print("(none)")
        for a in assigns:
            u = User.query.get(a.user_id)
            r = AdminRole.query.get(a.role_id)
            user_label = u.email if u else a.user_id
            role_label = r.name if r else a.role_id
            print(f"USER {user_label} -> ROLE {role_label}")


if __name__ == "__main__":
    main()
