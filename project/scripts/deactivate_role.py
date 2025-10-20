#!/usr/bin/env python3
"""
Deactivate a role by ID safely (sets is_active=False).
Usage context: Deactivate legacy 'Super Admin' (id=1).
"""
import os
import sys

# Ensure project root on sys.path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db
from database.models import AdminRole

ROLE_ID = 1

def main():
    with app.app_context():
        role = AdminRole.query.get(ROLE_ID)
        if not role:
            print(f"❌ Role id={ROLE_ID} not found")
            return
        if not role.is_active:
            print(f"✅ Role id={ROLE_ID} ('{role.name}') already inactive")
            return
        role.is_active = False
        db.session.commit()
        print(f"✅ Deactivated role id={ROLE_ID} ('{role.name}')")

if __name__ == "__main__":
    main()
