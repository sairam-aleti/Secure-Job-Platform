"""
FortKnox Superadmin Setup Utility
Usage: python create_superadmin.py <email> <password> <full_name>

Creates a superadmin account directly in the database.
Only run this once during initial setup.
"""
import sys
import os

# Load .env
from dotenv import load_dotenv
load_dotenv()

from app.database import engine, SessionLocal
from app import models, security

# Create tables if they don't exist
models.Base.metadata.create_all(bind=engine)

def create_superadmin(email: str, password: str, full_name: str):
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(models.User.email == email).first()
        if existing:
            print(f"User {email} already exists. Updating to superadmin...")
            existing.role = "superadmin"
            existing.is_admin_approved = True
            existing.is_active = True
            existing.is_verified = True
            db.commit()
            print(f"✅ {email} is now a superadmin.")
            return
        
        hashed = security.hash_password(password)
        user = models.User(
            email=email,
            hashed_password=hashed,
            full_name=full_name,
            role="superadmin",
            is_active=True,
            is_verified=True,
            is_admin_approved=True
        )
        db.add(user)
        db.commit()
        print(f"✅ Superadmin created: {email}")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python create_superadmin.py <email> <password> <full_name>")
        print("Example: python create_superadmin.py admin@iiitd.ac.in MyP@ssword123! 'Professor Admin'")
        sys.exit(1)
    
    create_superadmin(sys.argv[1], sys.argv[2], sys.argv[3])
