#!/usr/bin/env python3
"""
Ensure only the specified email has the super_admin role.
- Keeps/creates assignment for TARGET_EMAIL
- Deactivates any other active super_admin assignments
"""
import os
import sys
from datetime import datetime

# Ensure project root on sys.path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db
from database.models import User, AdminRole, AdminUserRole

TARGET_EMAIL = "krishnasai8782@gmail.com"


def main():
    with app.app_context():
        role = AdminRole.query.filter_by(name='super_admin', is_active=True).first()
        if not role:
            print("❌ super_admin role not found or inactive. Run seed_roles.py first.")
            return

        # Find/ensure target user
        target_user = User.query.filter_by(email=TARGET_EMAIL).first()
        if not target_user:
            print(f"❌ Target user not found: {TARGET_EMAIL}")
            return

        # Ensure target has an active assignment
        target_assignment = AdminUserRole.query.filter_by(user_id=target_user.id, role_id=role.id, is_active=True).first()
        if target_assignment:
            print(f"✅ Target already has super_admin: {TARGET_EMAIL}")
        else:
            new_assign = AdminUserRole(
                user_id=target_user.id,
                role_id=role.id,
                assigned_by=target_user.id,
                assigned_at=datetime.utcnow(),
                is_active=True,
            )
            db.session.add(new_assign)
            db.session.commit()
            print(f"✅ Assigned super_admin to target: {TARGET_EMAIL}")

        # Deactivate others with this role
        others = AdminUserRole.query.filter(
            AdminUserRole.role_id == role.id,
            AdminUserRole.user_id != target_user.id,
            AdminUserRole.is_active == True,
        ).all()
        changed = 0
        for a in others:
            a.is_active = False
            changed += 1
        if changed:
            db.session.commit()
            print(f"✅ Deactivated {changed} other super_admin assignment(s)")
        else:
            print("✅ No other super_admin assignments to deactivate")


if __name__ == "__main__":
    main()
