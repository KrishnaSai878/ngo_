#!/usr/bin/env python3
"""
Seed initial admin roles and assign the default role to the admin user.
- Creates an 'super_admin' role with broad permissions if not exists
- Assigns it to the admin user (admin@example.com)
"""
import os
import sys
import json
from datetime import datetime

# Ensure project root on sys.path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db
from database.models import User, AdminRole, AdminUserRole

DEFAULT_ADMIN_EMAIL = "admin@example.com"

SUPER_ADMIN_PERMISSIONS = {
    "manage_users": True,
    "manage_ngos": True,
    "manage_events": True,
    "view_reports": True,
    "manage_donations": True,
    "manage_admins": True,
}

def main():
    with app.app_context():
        # Ensure super_admin role exists
        role = AdminRole.query.filter_by(name='super_admin').first()
        if not role:
            role = AdminRole(
                name='super_admin',
                description='Full administrative access',
                permissions=json.dumps(SUPER_ADMIN_PERMISSIONS),
                is_active=True,
            )
            db.session.add(role)
            db.session.commit()
            print("✅ Created role: super_admin")
        else:
            print("✅ Role already exists: super_admin")

        # Find admin user
        admin_user = User.query.filter_by(email=DEFAULT_ADMIN_EMAIL).first()
        if not admin_user:
            print(f"❌ Admin user not found: {DEFAULT_ADMIN_EMAIL}. Run seed_admin.py first.")
            return

        # Assign role if not assigned
        existing_assignment = AdminUserRole.query.filter_by(user_id=admin_user.id, role_id=role.id, is_active=True).first()
        if existing_assignment:
            print("✅ Admin already has super_admin role")
        else:
            assignment = AdminUserRole(
                user_id=admin_user.id,
                role_id=role.id,
                assigned_by=admin_user.id,
                assigned_at=datetime.utcnow(),
                is_active=True,
            )
            db.session.add(assignment)
            db.session.commit()
            print("✅ Assigned super_admin role to admin user")

if __name__ == "__main__":
    main()
