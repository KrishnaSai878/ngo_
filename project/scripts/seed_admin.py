#!/usr/bin/env python3
"""
Seed a default admin user into the database if it does not already exist.
- Default credentials: admin@example.com / admin123
- Reads configuration via app.py (including DATABASE_URL from .env)
"""
import os
import sys
from werkzeug.security import generate_password_hash

# Ensure project root is on sys.path so we can import app.py
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db
from database.models import User

DEFAULT_EMAIL = "admin@example.com"
DEFAULT_PASSWORD = "admin123"


def main():
    with app.app_context():
        existing = User.query.filter_by(email=DEFAULT_EMAIL).first()
        if existing:
            print(f"✅ Admin user already exists: {DEFAULT_EMAIL}")
            return
        user = User(
            first_name="Admin",
            last_name="User",
            email=DEFAULT_EMAIL,
            password_hash=generate_password_hash(DEFAULT_PASSWORD),
            role="admin",
            is_verified=True,
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        print("✅ Admin user created successfully!")
        print(f"   Email: {DEFAULT_EMAIL}")
        print(f"   Password: {DEFAULT_PASSWORD}")


if __name__ == "__main__":
    main()
