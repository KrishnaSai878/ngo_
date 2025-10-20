#!/usr/bin/env python3
"""
Normalize roles to a canonical schema and deactivate duplicates.
- Renames: "Content Manager" -> content_manager, "Analytics Viewer" -> analytics_viewer
- Deactivates: "Super Admin" (keeps canonical: super_admin)
- Unifies permission keys to snake_case canonical set
- Ensures super_admin has all canonical permissions set to True
"""
import os
import sys
import json

# Ensure project root on sys.path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db
from database.models import AdminRole

# Canonical permission keys
CANONICAL_KEYS = [
    "manage_users",
    "manage_ngos",
    "manage_events",
    "manage_content",
    "manage_roles",
    "manage_settings",
    "manage_audit_logs",
    "view_audit_logs",
    "view_analytics",
    "create_users",
    "delete_users",
    "export_data",
]

# Legacy -> Canonical mapping
LEGACY_MAP = {
    "users_manage": "manage_users",
    "content_manage": "manage_content",
    "settings_manage": "manage_settings",
    "analytics_view": "view_analytics",
    "audit_logs_view": "view_audit_logs",
}

RENAME = {
    "Content Manager": "content_manager",
    "Analytics Viewer": "analytics_viewer",
}

DEACTIVATE_NAMES = {"Super Admin"}


def unify_permissions(raw_json: str) -> dict:
    try:
        data = json.loads(raw_json) if raw_json else {}
    except Exception:
        data = {}
    out = {}
    # Map legacy keys
    for k, v in data.items():
        key = LEGACY_MAP.get(k, k)
        if isinstance(v, bool):
            out[key] = v
    # Only keep canonical keys
    out = {k: bool(out.get(k, False)) for k in CANONICAL_KEYS}
    return out


def main():
    with app.app_context():
        changed = 0
        roles = AdminRole.query.all()
        for role in roles:
            orig_name = role.name
            # Rename if needed
            if role.name in RENAME:
                role.name = RENAME[role.name]
                changed += 1
            # Deactivate duplicates
            if orig_name in DEACTIVATE_NAMES:
                role.is_active = False
                changed += 1
            # Unify permissions
            perms = unify_permissions(role.permissions or "{}")
            # For super_admin: ensure all canonical permissions True
            if role.name == "super_admin":
                for k in CANONICAL_KEYS:
                    perms[k] = True
            role.permissions = json.dumps(perms)
            changed += 1
        if changed:
            db.session.commit()
        print(f"✅ Normalization done. Updated items: {changed}")


if __name__ == "__main__":
    main()
