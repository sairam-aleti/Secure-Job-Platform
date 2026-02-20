from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    role = Column(String)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # OTP Security Fields
    failed_otp_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # Profile Fields (NEW)
    headline = Column(String, nullable=True)  # e.g., "Software Engineer at Google"
    location = Column(String, nullable=True)  # e.g., "New Delhi, India"
    bio = Column(String, nullable=True)  # Short description
    skills = Column(String, nullable=True)  # JSON array as string: ["Python", "FastAPI"]
    experience = Column(String, nullable=True)  # JSON array: [{"company": "Google", "role": "SWE"}]
    education = Column(String, nullable=True)  # JSON array
    profile_picture = Column(String, nullable=True)  # URL or filename
    
    # Privacy Settings (NEW)
    headline_privacy = Column(String, default="public")  # "public", "connections", "private"
    location_privacy = Column(String, default="public")
    bio_privacy = Column(String, default="public")
    skills_privacy = Column(String, default="public")
    experience_privacy = Column(String, default="public")
    education_privacy = Column(String, default="public")

class OTP(Base):
    __tablename__ = "otps"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    code = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_used = Column(Boolean, default=False)

class Resume(Base):
    __tablename__ = "resumes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    original_filename = Column(String)
    encrypted_filename = Column(String)  # Filename on disk
    encryption_key = Column(String)  # Base64-encoded key
    nonce = Column(String)  # Base64-encoded nonce
    file_size = Column(Integer)  # Original file size in bytes
    uploaded_at = Column(DateTime, default=datetime.utcnow)