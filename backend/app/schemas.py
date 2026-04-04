from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from datetime import datetime
from typing import Optional, Literal
import os
import re

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str = Field(max_length=100)
    # Admin can register (professor requirement) but needs superadmin approval for destructive actions
    role: Literal["job_seeker", "recruiter", "admin"]

    @field_validator('email')
    @classmethod
    def validate_email_domain(cls, v: str) -> str:
        allowed_domains = ['gmail.com', 'iiitd.ac.in']
        domain = v.split('@')[-1].lower()
        
        # SECURITY: Test accounts gated behind environment variable
        if os.environ.get('ALLOW_TEST_ACCOUNTS', 'false').lower() == 'true':
            test_accounts = ['superadmin@secure.com', 'recruiter@tech.com', 'final@test.com']
            if v.lower() in test_accounts:
                return v
            
        if domain not in allowed_domains:
            raise ValueError('Registration is only allowed for @gmail.com or @iiitd.ac.in domains')
        return v

    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?' for char in v):
            raise ValueError('Password must contain at least one special character')
        return v

    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        # SECURITY: Prevent script injection in names
        if not re.match(r'^[a-zA-Z\s\.\-\']+$', v):
            raise ValueError('Full name can only contain letters, spaces, dots, hyphens, and apostrophes')
        return v.strip()

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_verified: bool
    
    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str = Field(min_length=6, max_length=6)

class OTPResponse(BaseModel):
    message: str
    dev_otp: Optional[str] = None

class ResumeResponse(BaseModel):
    id: int
    original_filename: str
    file_size: int
    uploaded_at: datetime
    signature: Optional[str] = None 

    class Config:
        from_attributes = True

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=100)
    headline: Optional[str] = Field(default=None, max_length=200)
    location: Optional[str] = Field(default=None, max_length=100)
    bio: Optional[str] = Field(default=None, max_length=2000)
    skills: Optional[str] = Field(default=None, max_length=1000)
    experience: Optional[str] = Field(default=None, max_length=5000)
    education: Optional[str] = Field(default=None, max_length=5000)
    
    # Privacy settings for each field
    headline_privacy: Optional[Literal["public", "connections", "private"]] = None
    location_privacy: Optional[Literal["public", "connections", "private"]] = None
    bio_privacy: Optional[Literal["public", "connections", "private"]] = None
    skills_privacy: Optional[Literal["public", "connections", "private"]] = None
    experience_privacy: Optional[Literal["public", "connections", "private"]] = None
    education_privacy: Optional[Literal["public", "connections", "private"]] = None
    share_view_history: Optional[bool] = None
    profile_picture: Optional[str] = None

    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        if v is not None:
            if not re.match(r'^[a-zA-Z\s\.\-\']+$', v):
                raise ValueError('Full name can only contain letters, spaces, dots, hyphens, and apostrophes')
            return v.strip()
        return v

class ProfileResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_verified: bool    
    is_active: bool 
    headline: Optional[str]
    location: Optional[str]
    bio: Optional[str]
    skills: Optional[str]
    experience: Optional[str]
    education: Optional[str]
    profile_picture: Optional[str]
    
    # Privacy settings
    headline_privacy: str
    location_privacy: str
    bio_privacy: str
    skills_privacy: str
    experience_privacy: str
    education_privacy: str
    share_view_history: bool

    public_key: Optional[str] = None
    encrypted_private_key: Optional[str] = None
    
    class Config:
        from_attributes = True

class UserListItem(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    is_admin_approved: bool
    
    class Config:
        from_attributes = True

class AdminAction(BaseModel):
    message: str
    user_id: int

# --- COMPANY SCHEMAS ---
class CompanyCreate(BaseModel):
    name: str = Field(max_length=200)
    description: str = Field(max_length=5000)
    location: str = Field(max_length=200)
    website: Optional[str] = Field(default=None, max_length=500)

class CompanyResponse(BaseModel):
    id: int
    name: str
    description: str
    location: str
    website: Optional[str]
    recruiter_id: int
    
    class Config:
        from_attributes = True

# --- JOB SCHEMAS ---
class JobCreate(BaseModel):
    company_id: int
    title: str = Field(max_length=200)
    description: str = Field(max_length=10000)
    location: str = Field(max_length=200)
    employment_type: Literal["Full-time", "Part-time", "Internship", "Contract", "Remote"]
    skills_required: str = Field(max_length=2000)
    salary_range: Optional[str] = Field(default=None, max_length=100)
    deadline: Optional[datetime] = None

class JobResponse(BaseModel):
    id: int
    company_id: int
    title: str
    description: str
    location: str
    employment_type: str
    skills_required: str
    salary_range: Optional[str]
    posted_at: datetime
    is_active: bool
    deadline: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# --- APPLICATION SCHEMAS ---
class ApplicationCreate(BaseModel):
    job_id: int
    resume_id: int
    cover_letter: Optional[str] = Field(default=None, max_length=5000)

class ApplicationResponse(BaseModel):
    id: int
    job_id: int
    applicant_id: int
    resume_id: int
    cover_letter: Optional[str]
    status: str
    applied_at: datetime
    match_score: int
    
    class Config:
        from_attributes = True

# Extended response for Recruiters to see Applicant details
class ApplicationDetail(ApplicationResponse):
    applicant_name: str
    job_title: str
    recruiter_notes: Optional[str] = None

# --- MESSAGING SCHEMAS ---

class PublicKeyUpdate(BaseModel):
    public_key: str = Field(max_length=5000)
    encrypted_private_key: Optional[str] = Field(default=None, max_length=15000)

class MessageCreate(BaseModel):
    receiver_id: int
    encrypted_content: str = Field(max_length=50000)
    signature: Optional[str] = Field(default=None, max_length=5000)

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    encrypted_content: str
    signature: Optional[str] = None 
    timestamp: datetime

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: int
    action: str
    performed_by: str
    target_user: Optional[str]
    timestamp: datetime
    log_hash: str
    
    class Config:
        from_attributes = True

# SECURITY FIX: Restrict status to valid values only
class ApplicationStatusUpdate(BaseModel):
    status: Literal["Applied", "Reviewed", "Interview", "Offer", "Rejected"]

# --- CONNECTION SCHEMAS ---

class ConnectionRequest(BaseModel):
    receiver_id: int

# SECURITY FIX: Restrict to valid status values  
class ConnectionUpdate(BaseModel):
    request_id: int
    status: Literal["accepted", "rejected"]

class ConnectionResponse(BaseModel):
    id: int
    user_id: int
    connection_id: int
    status: str
    
    class Config:
        from_attributes = True

class DirectoryUser(BaseModel):
    id: int
    full_name: str
    headline: Optional[str] = None
    role: str
    
    class Config:
        from_attributes = True

class UserProfilePublic(BaseModel):
    id: int
    full_name: str
    role: str
    headline: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    skills: Optional[str] = None
    experience: Optional[str] = None
    education: Optional[str] = None
    mutual_connections: int 
    
    class Config:
        from_attributes = True

class DeleteAccountRequest(BaseModel):
    otp_code: str = Field(min_length=6, max_length=6)

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    otp_code: str = Field(min_length=6, max_length=6)
    new_password: str

    # SECURITY FIX: Enforce password strength at schema level
    @field_validator('new_password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?' for char in v):
            raise ValueError('Password must contain at least one special character')
        return v

# --- ADMIN ACTION QUEUE SCHEMAS ---

class AdminActionRequest(BaseModel):
    action_type: Literal["suspend", "activate", "delete"]
    target_user_id: int
    reason: Optional[str] = Field(default=None, max_length=500)

class AdminActionResponse(BaseModel):
    id: int
    action_type: str
    requested_by: str
    target_user_id: int
    target_user_email: str
    status: str
    reason: Optional[str]
    created_at: datetime
    reviewed_by: Optional[str]
    reviewed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class AdminActionReview(BaseModel):
    action_id: int
    decision: Literal["approved", "rejected"]

# --- LOGIN OTP FLOW ---
class LoginPendingResponse(BaseModel):
    login_pending: bool = True
    email: str
    message: str

# --- REPORT / MODERATION SCHEMAS ---

class ReportCreate(BaseModel):
    target_type: Literal["user", "job", "message"]
    target_id: int
    reason: str = Field(max_length=200)
    details: Optional[str] = Field(default=None, max_length=2000)

class ReportResponse(BaseModel):
    id: int
    reporter_id: int
    target_type: str
    target_id: int
    reason: str
    details: Optional[str]
    status: str
    reviewed_by: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class ReportReview(BaseModel):
    status: Literal["resolved", "dismissed"]

# --- GROUP MESSAGING SCHEMAS ---

class GroupCreate(BaseModel):
    name: str = Field(max_length=100)
    member_ids: list[int]

class GroupAddMembers(BaseModel):
    member_ids: list[int]

class GroupResponse(BaseModel):
    id: int
    name: str
    created_by: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class GroupMessageCreate(BaseModel):
    encrypted_content: str = Field(max_length=50000)
    signature: Optional[str] = Field(default=None, max_length=5000)

class GroupMessageResponse(BaseModel):
    id: int
    group_id: int
    sender_id: int
    encrypted_content: str
    signature: Optional[str] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True

# --- RECRUITER NOTES ---

class ApplicationNotesUpdate(BaseModel):
    notes: str = Field(max_length=5000)

# --- RECRUITER SHORTLIST REMOVED ---

# --- BLOCKCHAIN SCHEMAS ---

class BlockResponse(BaseModel):
    id: int
    block_index: int
    timestamp: datetime
    log_count: int
    block_hash: str
    previous_block_hash: str
    
    class Config:
        from_attributes = True

class ChainVerifyResponse(BaseModel):
    is_valid: bool
    total_blocks: int
    message: str
    broken_at: Optional[int] = None