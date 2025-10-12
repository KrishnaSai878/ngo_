from app import app, db
from database.models import AdminRole, AdminUserRole, User
from datetime import datetime, timedelta

def assign_super_admin_role():
    """Assign Super Admin role to the specified admin user"""
    admin_email = 'krishnasai8782@gmail.com'
    
    with app.app_context():
        # Find the admin user
        admin_user = User.query.filter_by(email=admin_email).first()
        if not admin_user:
            print(f"❌ Admin user with email {admin_email} not found")
            return False
        
        # Find the Super Admin role
        super_admin_role = AdminRole.query.filter_by(name='Super Admin').first()
        if not super_admin_role:
            print("❌ Super Admin role not found in the database")
            return False
        
        # Check if the role is already assigned
        existing_role = AdminUserRole.query.filter_by(
            user_id=admin_user.id,
            role_id=super_admin_role.id
        ).first()
        
        if existing_role:
            print(f"✅ User {admin_email} already has Super Admin role assigned")
            return True
        
        # Assign the Super Admin role to the user
        # Set expiry date to 1 year from now
        expires_at = datetime.utcnow() + timedelta(days=365)
        
        user_role = AdminUserRole(
            user_id=admin_user.id,
            role_id=super_admin_role.id,
            is_active=True,
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )
        
        db.session.add(user_role)
        db.session.commit()
        
        print(f"✅ Successfully assigned Super Admin role to {admin_email}")
        print(f"   Role will expire on: {expires_at}")
        return True

if __name__ == "__main__":
    assign_super_admin_role()