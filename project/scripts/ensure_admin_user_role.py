#!/usr/bin/env python3
"""
Ensure the specified user's base role is set to 'admin' so @admin_required passes.
"""
import os
import sys

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db
from database.models import User

TARGET_EMAIL = "krishnasai8782@gmail.com"

def main():
    with app.app_context():
        u = User.query.filter_by(email=TARGET_EMAIL).first()
        if not u:
            print(f"❌ User not found: {TARGET_EMAIL}")
            return
        if u.role != 'admin':
            u.role = 'admin'
            db.session.commit()
            print(f"✅ Updated role to 'admin' for {TARGET_EMAIL}")
        else:
            print(f"✅ User already has role 'admin': {TARGET_EMAIL}")

if __name__ == "__main__":
    main()
