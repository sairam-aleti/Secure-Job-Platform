from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from datetime import datetime, timezone 
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    mobile_number = Column(String, unique=True, nullable=True) 
    role = Column(String)  # "job_seeker", "recruiter", "admin", "superadmin"
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Admin approval: admin accounts need superadmin approval for full powers
    is_admin_approved = Column(Boolean, default=False)
    
    # OTP Security Fields
    failed_otp_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    
    # Single Session Enforcement
    session_id = Column(String, nullable=True)  # Active JWT ID (JTI)
    session_fingerprint = Column(String, nullable=True)  # Browser fingerprint hash
    
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
    encrypted_private_key = Column(String, nullable=True)

    share_view_history = Column(Boolean, default=True)

class OTP(Base):
    __tablename__ = "otps"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code = Column(String)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_used = Column(Boolean, default=False)

class Resume(Base):
    __tablename__ = "resumes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    original_filename = Column(String)
    encrypted_filename = Column(String)
    encryption_key = Column(String)  # Envelope-encrypted with master key
    nonce = Column(String)
    file_size = Column(Integer)
    extracted_skills = Column(String, nullable=True) 
    
    # PKI Signature (Requirement H)
    signature = Column(String, nullable=True) 
    
    uploaded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    recruiter_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name = Column(String, index=True)
    description = Column(String)
    location = Column(String)
    website = Column(String, nullable=True)
    logo_url = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    recruiter_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title = Column(String)
    description = Column(String)
    location = Column(String)
    employment_type = Column(String)
    skills_required = Column(String)
    salary_range = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    deadline = Column(DateTime(timezone=True), nullable=True)
    posted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Application(Base):
    __tablename__ = "applications"
    
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    applicant_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    resume_id = Column(Integer, ForeignKey("resumes.id", ondelete="SET NULL"))
    cover_letter = Column(String, nullable=True)
    status = Column(String, default="Applied")
    applied_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    match_score = Column(Integer, default=0)
    recruiter_notes = Column(String, nullable=True)
    is_shortlisted = Column(Boolean, default=False)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    receiver_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    encrypted_content = Column(String)
    is_read = Column(Boolean, default=False)
    
    signature = Column(String, nullable=True) 
    
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)
    performed_by = Column(String)
    target_user = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Integrity Hash (HMAC-based)
    log_hash = Column(String) 
    previous_hash = Column(String)

class Connection(Base):
    __tablename__ = "connections"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    connection_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    status = Column(String)  # "pending", "accepted"
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class ProfileView(Base):
    __tablename__ = "profile_views"
    id = Column(Integer, primary_key=True, index=True)
    viewer_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    target_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AdminActionQueue(Base):
    """
    Superadmin approval queue: When an admin requests a destructive action
    (suspend, delete, activate), it goes here instead of executing immediately.
    Only a superadmin can approve or reject.
    """
    __tablename__ = "admin_action_queue"
    id = Column(Integer, primary_key=True, index=True)
    action_type = Column(String)  # "suspend", "activate", "delete"
    requested_by = Column(String)  # Admin email
    target_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    target_user_email = Column(String)
    status = Column(String, default="pending")  # "pending", "approved", "rejected"
    reason = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reviewed_by = Column(String, nullable=True)  # Superadmin who acted
    reviewed_at = Column(DateTime(timezone=True), nullable=True)

class Report(Base):
    """Content moderation: users can report profiles, jobs, or messages."""
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    reporter_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    target_type = Column(String)  # "user", "job", "message"
    target_id = Column(Integer)
    reason = Column(String)
    details = Column(String, nullable=True)
    status = Column(String, default="pending")  # "pending", "reviewed", "resolved", "dismissed"
    reviewed_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True), nullable=True)

class Group(Base):
    """Group for group E2EE messaging."""
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class GroupMember(Base):
    """Membership table for groups."""
    __tablename__ = "group_members"
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    joined_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class GroupMessage(Base):
    """Encrypted group messages."""
    __tablename__ = "group_messages"
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    encrypted_content = Column(String)  # E2EE ciphertext
    is_read = Column(Boolean, default=False)
    signature = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Block(Base):
    """Blockchain tamper-evident logging: batches of audit logs in immutable blocks."""
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True, index=True)
    block_index = Column(Integer, unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    log_ids = Column(String)  # Comma-separated audit log IDs in this block
    log_count = Column(Integer, default=0)
    data_hash = Column(String)  # SHA-256 hash of all log data in this block
    block_hash = Column(String)  # SHA-256(block_index + timestamp + data_hash + previous_block_hash)
    previous_block_hash = Column(String, default="0")
