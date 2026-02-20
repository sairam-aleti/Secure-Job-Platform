from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from typing import Optional, Literal

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: Literal["job_seeker", "recruiter", "admin"]
    
    @field_validator('password')
    def password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        return v
    
    @field_validator('full_name')
    def name_not_empty(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v

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
    otp_code: str

class OTPResponse(BaseModel):
    message: str
    dev_otp: str = None  # Only populated in dev mode

class ResumeResponse(BaseModel):
    id: int
    original_filename: str
    file_size: int
    uploaded_at: datetime
    
    class Config:
        from_attributes = True

class ProfileUpdate(BaseModel):
    headline: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    skills: Optional[str] = None  # JSON string: '["Python", "FastAPI"]'
    experience: Optional[str] = None  # JSON string
    education: Optional[str] = None  # JSON string
    
    # Privacy settings for each field
    headline_privacy: Optional[Literal["public", "connections", "private"]] = None
    location_privacy: Optional[Literal["public", "connections", "private"]] = None
    bio_privacy: Optional[Literal["public", "connections", "private"]] = None
    skills_privacy: Optional[Literal["public", "connections", "private"]] = None
    experience_privacy: Optional[Literal["public", "connections", "private"]] = None
    education_privacy: Optional[Literal["public", "connections", "private"]] = None

class ProfileResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
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
    
    class Config:
        from_attributes = True

class UserListItem(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    
    class Config:
        from_attributes = True

class AdminAction(BaseModel):
    message: str
    user_id: int