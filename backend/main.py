from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from sqlalchemy.orm import Session
from app import models, schemas, security, auth, otp, encryption
from app.database import engine, get_db
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import os
import base64

# Create all database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI
app = FastAPI(title="Secure Job Platform", version="2.0")

# CORS Configuration - Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # HTTP (for development)
        "https://localhost:3000"   # HTTPS (secure)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting Configuration
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/")
def home():
    return {"status": "Milestone 2 - Identity System Active"}

@app.post("/register", response_model=schemas.UserResponse)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    SECURE USER REGISTRATION
    - Validates input using Pydantic schemas
    - Checks for duplicate emails
    - Hashes password with Argon2
    - Stores user in database
    """
    # Check if email already exists
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password (SECURITY CRITICAL)
    hashed_password = security.hash_password(user.password)
    
    # Create new user
    new_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        role=user.role,
        is_verified=False  # Will be True after OTP verification
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@app.post("/login", response_model=schemas.Token)
def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """
    SECURE LOGIN
    - Validates email format
    - Checks if user exists
    - Verifies password using Argon2
    - Returns JWT token if successful
    """
    # Check if user exists
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password (SECURITY CRITICAL)
    if not security.verify_password(user_credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if account is active
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended")
    
    # Create JWT token
    access_token = auth.create_access_token(
        data={"sub": user.email, "role": user.role}
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/send-otp", response_model=schemas.OTPResponse)
@limiter.limit("3/15minutes")  # Rate limit: 3 requests per 15 minutes per IP
def send_otp(request: Request, otp_request: schemas.OTPRequest, db: Session = Depends(get_db)):
    """
    SEND OTP FOR EMAIL VERIFICATION
    - Rate limited to prevent spam (3 requests per 15 min per IP)
    - Generates 6-digit OTP valid for 2 minutes
    - Stores OTP in database
    - In DEV mode: returns OTP in response (for testing)
    - In PROD mode: sends email
    """
    # Check if user exists
    user = db.query(models.User).filter(models.User.email == otp_request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if account is already verified
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Account already verified")
    
    # Check if account is locked
    if user.locked_until and otp.is_account_locked(user.locked_until):
        raise HTTPException(
            status_code=403, 
            detail=f"Account locked due to too many failed attempts. Try again after 20 minutes."
        )
    
    # Generate OTP
    otp_code = otp.generate_otp()
    
    # Save OTP to database
    new_otp = models.OTP(
        user_id=user.id,
        code=otp_code,
        created_at=datetime.utcnow()
    )
    db.add(new_otp)
    db.commit()
    
    # DEV MODE: Return OTP in response (for testing without email)
    # PROD MODE: Send email here (we'll add this later)
    return {
        "message": "OTP sent successfully (check terminal in dev mode)",
        "dev_otp": otp_code  # Remove this in production
    }

@app.post("/verify-otp")
def verify_otp_code(otp_verify: schemas.OTPVerify, db: Session = Depends(get_db)):
    """
    VERIFY OTP CODE
    - Checks if OTP is valid and not expired (2 minutes)
    - Prevents brute force (locks account after 5 failed attempts for 20 minutes)
    - Marks user as verified upon success
    - Deletes OTP after successful verification (one-time use)
    """
    # Get user
    user = db.query(models.User).filter(models.User.email == otp_verify.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if already verified
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Account already verified")
    
    # Check if account is locked
    if user.locked_until and otp.is_account_locked(user.locked_until):
        raise HTTPException(
            status_code=403,
            detail="Account locked due to too many failed attempts. Try again later."
        )
    
    # Get the most recent unused OTP for this user
    db_otp = db.query(models.OTP).filter(
        models.OTP.user_id == user.id,
        models.OTP.is_used == False
    ).order_by(models.OTP.created_at.desc()).first()
    
    if not db_otp:
        raise HTTPException(status_code=400, detail="No OTP found. Please request a new one.")
    
    # Check if OTP is expired (2 minutes)
    if otp.is_otp_expired(db_otp.created_at):
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new one.")
    
    # Verify the OTP code
    if db_otp.code != otp_verify.otp_code:
        # Increment failed attempts
        user.failed_otp_attempts += 1
        
        # Lock account if too many failures
        if user.failed_otp_attempts >= otp.MAX_FAILED_ATTEMPTS:
            user.locked_until = otp.calculate_lockout_time()
            db.commit()
            raise HTTPException(
                status_code=403,
                detail=f"Account locked for {otp.LOCKOUT_DURATION_MINUTES} minutes due to too many failed attempts."
            )
        
        db.commit()
        raise HTTPException(
            status_code=400,
            detail=f"Invalid OTP. {otp.MAX_FAILED_ATTEMPTS - user.failed_otp_attempts} attempts remaining."
        )
    
    # SUCCESS: Mark user as verified
    user.is_verified = True
    user.failed_otp_attempts = 0  # Reset counter
    user.locked_until = None  # Clear any lockout
    db_otp.is_used = True  # Mark OTP as used (one-time use)
    
    db.commit()
    
    return {
        "message": "Email verified successfully",
        "is_verified": True
    }

@app.post("/upload-resume", response_model=schemas.ResumeResponse)
def upload_resume(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)  # We'll create this dependency next
):
    """
    SECURE RESUME UPLOAD
    - Only verified users can upload
    - Accepts PDF and DOCX only
    - Encrypts file with AES-256-GCM before storage
    - Stores encryption key securely in database
    - File integrity is verified on decryption
    """
    # Get user from email (from JWT token)
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # Security Check: Only verified users
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before uploading resume")
    
    # Validate file type
    allowed_extensions = [".pdf", ".docx"]
    file_extension = os.path.splitext(file.filename)[1].lower()
    
    if file_extension not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Only PDF and DOCX files are allowed")
    
    # Read file content
    file_content = file.file.read()
    file_size = len(file_content)
    
    # Security Check: File size limit (10MB)
    max_size = 10 * 1024 * 1024  # 10MB
    if file_size > max_size:
        raise HTTPException(status_code=400, detail="File size must be less than 10MB")
    
    # Generate encryption key and encrypt the file
    encryption_key = encryption.generate_key()
    encrypted_data, nonce = encryption.encrypt_file(file_content, encryption_key)
    
    # Generate unique encrypted filename
    encrypted_filename = f"{user.id}_{os.urandom(8).hex()}{file_extension}.enc"
    file_path = os.path.join("uploads", encrypted_filename)
    
    # Save encrypted file to disk
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
    
    # Save metadata to database
    resume = models.Resume(
        user_id=user.id,
        original_filename=file.filename,
        encrypted_filename=encrypted_filename,
        encryption_key=encryption.key_to_string(encryption_key),
        nonce=base64.b64encode(nonce).decode('utf-8'),
        file_size=file_size
    )
    
    db.add(resume)
    db.commit()
    db.refresh(resume)
    
    return resume

@app.get("/download-resume/{resume_id}")
def download_resume(
    resume_id: int,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    SECURE RESUME DOWNLOAD
    - Decrypts resume using stored key
    - Access control: Only owner can download (for now)
    - Verifies file integrity during decryption
    """
    from fastapi.responses import Response
    
    # Get user
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # Get resume metadata
    resume = db.query(models.Resume).filter(models.Resume.id == resume_id).first()
    if not resume:
        raise HTTPException(status_code=404, detail="Resume not found")
    
    # Access Control: Only owner can download
    if resume.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied: You can only download your own resume")
    
    # Read encrypted file
    file_path = os.path.join("uploads", resume.encrypted_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    # Decrypt the file
    try:
        encryption_key = encryption.string_to_key(resume.encryption_key)
        nonce = base64.b64decode(resume.nonce.encode('utf-8'))
        decrypted_data = encryption.decrypt_file(encrypted_data, encryption_key, nonce)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed. File may be corrupted.")
    
    # Return decrypted file
    return Response(
        content=decrypted_data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={resume.original_filename}"
        }
    )

@app.get("/my-resumes", response_model=list[schemas.ResumeResponse])
def list_my_resumes(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    LIST USER'S RESUMES
    - Returns all resumes uploaded by the current user
    - Includes file metadata (name, size, upload date)
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    resumes = db.query(models.Resume).filter(models.Resume.user_id == user.id).all()
    return resumes

@app.get("/profile", response_model=schemas.ProfileResponse)
def get_profile(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    GET USER PROFILE
    - Returns the authenticated user's complete profile
    - Includes all fields and privacy settings
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

@app.put("/profile", response_model=schemas.ProfileResponse)
def update_profile(
    profile_update: schemas.ProfileUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    UPDATE USER PROFILE
    - Users can update their profile information
    - Can set privacy levels for each field (public/connections/private)
    - Only updates fields that are provided (partial updates allowed)
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update only the fields that were provided
    update_data = profile_update.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    
    return user

@app.get("/admin/users", response_model=list[schemas.UserListItem])
def list_all_users(
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """
    ADMIN: LIST ALL USERS
    - Only accessible by Platform Admins
    - Returns all registered users with their status
    - Used for user management and moderation
    """
    users = db.query(models.User).all()
    return users

@app.post("/admin/suspend/{user_id}", response_model=schemas.AdminAction)
def suspend_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """
    ADMIN: SUSPEND USER ACCOUNT
    - Only accessible by Platform Admins
    - Sets is_active to False
    - Suspended users cannot login or perform actions
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.role == "admin":
        raise HTTPException(status_code=403, detail="Cannot suspend other admins")
    
    user.is_active = False
    db.commit()
    
    return {
        "message": f"User {user.email} has been suspended",
        "user_id": user_id
    }

@app.post("/admin/activate/{user_id}", response_model=schemas.AdminAction)
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """
    ADMIN: ACTIVATE SUSPENDED USER
    - Only accessible by Platform Admins
    - Sets is_active to True
    - Re-enables suspended accounts
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = True
    db.commit()
    
    return {
        "message": f"User {user.email} has been activated",
        "user_id": user_id
    }

@app.delete("/admin/delete/{user_id}", response_model=schemas.AdminAction)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """
    ADMIN: DELETE USER ACCOUNT
    - Only accessible by Platform Admins
    - Permanently removes user and associated data
    - Cannot delete other admins
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.role == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete other admins")
    
    email = user.email
    db.delete(user)
    db.commit()
    
    return {
        "message": f"User {email} has been permanently deleted",
        "user_id": user_id
    }