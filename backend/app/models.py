from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime, timezone 
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
    locked_until = Column(DateTime(timezone=True), nullable=True)
    
    # Profile Fields
    headline = Column(String, nullable=True)
    location = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    skills = Column(String, nullable=True)
    experience = Column(String, nullable=True)
    education = Column(String, nullable=True)
    profile_picture = Column(String, nullable=True)
    
    # Privacy Settings
    headline_privacy = Column(String, default="public")
    location_privacy = Column(String, default="public")
    bio_privacy = Column(String, default="public")
    skills_privacy = Column(String, default="public")
    experience_privacy = Column(String, default="public")
    education_privacy = Column(String, default="public")

    # SECURITY MANDATE: RSA Public Key for E2EE Messaging
    public_key = Column(String, nullable=True)

class OTP(Base):
    __tablename__ = "otps"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    code = Column(String)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_used = Column(Boolean, default=False)

class Resume(Base):
    __tablename__ = "resumes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    original_filename = Column(String)
    encrypted_filename = Column(String)
    encryption_key = Column(String)
    nonce = Column(String)
    file_size = Column(Integer)
    uploaded_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    recruiter_id = Column(Integer, index=True)
    name = Column(String, index=True)
    description = Column(String)
    location = Column(String)
    website = Column(String, nullable=True)
    logo_url = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, index=True)
    recruiter_id = Column(Integer, index=True)
    title = Column(String)
    description = Column(String)
    location = Column(String)
    employment_type = Column(String)
    skills_required = Column(String)
    salary_range = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    deadline = Column(DateTime(timezone=True), nullable=True)
    posted_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class Application(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, index=True)
    applicant_id = Column(Integer, index=True)
    resume_id = Column(Integer)
    cover_letter = Column(String, nullable=True)
    status = Column(String, default="Applied")
    applied_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, index=True)
    receiver_id = Column(Integer, index=True)
    encrypted_content = Column(String) # Ciphertext stored on server
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String) # e.g., "USER_SUSPENDED"
    performed_by = Column(String) # Email of the admin
    target_user = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow)
    # FOR BONUS: Integrity Hash
    log_hash = Column(String) 
    previous_hash = Column(String)