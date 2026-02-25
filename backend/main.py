from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from sqlalchemy.orm import Session
from app import models, schemas, security, auth, otp, encryption
from app.database import engine, get_db
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from datetime import datetime, timedelta, timezone 
import os
import base64
import hashlib

def create_audit_log(db: Session, action: str, admin_email: str, target: str = None):
    last_log = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).first()
    prev_hash = last_log.log_hash if last_log else "0"
    
    # Use timezone-aware UTC
    now = datetime.now(timezone.utc)
    
    log_data = f"{action}-{admin_email}-{target}-{prev_hash}-{now}"
    current_hash = hashlib.sha256(log_data.encode()).hexdigest()
    
    new_log = models.AuditLog(
        action=action,
        performed_by=admin_email,
        target_user=target,
        log_hash=current_hash,
        previous_hash=prev_hash,
        timestamp=now # Explicitly set the aware timestamp
    )
    db.add(new_log)

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
@limiter.limit("100/15minutes")  
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
        created_at=datetime.now(timezone.utc)
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
    - Access control: Owner, Admins, or Recruiters with a valid application.
    """
    from fastapi.responses import Response
    
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    resume = db.query(models.Resume).filter(models.Resume.id == resume_id).first()
    
    if not resume:
        raise HTTPException(status_code=404, detail="Resume not found")
    
    # --- SECURITY CHECK LOGIC ---
    allowed = False
    
    # 1. Is the user the owner?
    if resume.user_id == user.id:
        allowed = True
    
    # 2. Is the user an Admin?
    elif user.role == "admin":
        allowed = True
        
    # 3. Is the user a Recruiter who received an application with this resume?
    elif user.role == "recruiter":
        # We must explicitly define the JOIN condition: models.Job.id == models.Application.job_id
        application = db.query(models.Application).join(
            models.Job, models.Job.id == models.Application.job_id
        ).filter(
            models.Application.resume_id == resume_id,
            models.Job.recruiter_id == user.id
        ).first()
        if application:
            allowed = True

    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied: You are not authorized to view this resume")
    # --- END SECURITY CHECK ---

    # Read and Decrypt (Same logic as before)
    file_path = os.path.join("uploads", resume.encrypted_filename)
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        encryption_key = encryption.string_to_key(resume.encryption_key)
        nonce = base64.b64decode(resume.nonce.encode('utf-8'))
        decrypted_data = encryption.decrypt_file(encrypted_data, encryption_key, nonce)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed.")
    
    return Response(
        content=decrypted_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={resume.original_filename}"}
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
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin":
        raise HTTPException(status_code=403, detail="Cannot suspend other admins")
    
    user.is_active = False
    
    # NEW: Secure Logging
    create_audit_log(db, "USER_SUSPENDED", admin_email, user.email)
    
    db.commit()
    return {"message": f"User {user.email} has been suspended", "user_id": user_id}

@app.post("/admin/activate/{user_id}", response_model=schemas.AdminAction)
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = True
    
    # NEW: Secure Logging
    create_audit_log(db, "USER_ACTIVATED", admin_email, user.email)
    
    db.commit()
    return {"message": f"User {user.email} has been activated", "user_id": user_id}

@app.delete("/admin/delete/{user_id}", response_model=schemas.AdminAction)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete other admins")
    
    target_email = user.email
    db.delete(user)
    
    # NEW: Secure Logging
    create_audit_log(db, "USER_DELETED", admin_email, target_email)
    
    db.commit()
    return {"message": f"User {target_email} has been permanently deleted", "user_id": user_id}

# NEW: Endpoint to let the Admin Panel view the logs
@app.get("/admin/audit-logs", response_model=list[schemas.AuditLogResponse])
def get_audit_logs(db: Session = Depends(get_db), admin_email: str = Depends(auth.require_admin)):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).all()

# --- COMPANY ENDPOINTS ---

@app.post("/companies", response_model=schemas.CompanyResponse)
def create_company(
    company: schemas.CompanyCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    RECRUITER ONLY: Create a Company Page.
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # RBAC: Only recruiters can create companies
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Only recruiters can create company pages")
        
    new_company = models.Company(
        recruiter_id=user.id,
        name=company.name,
        description=company.description,
        location=company.location,
        website=company.website
    )
    db.add(new_company)
    db.commit()
    db.refresh(new_company)
    return new_company

@app.get("/companies", response_model=list[schemas.CompanyResponse])
def list_companies(db: Session = Depends(get_db)):
    """
    PUBLIC: List all companies.
    """
    return db.query(models.Company).all()

# --- JOB ENDPOINTS ---

@app.post("/jobs", response_model=schemas.JobResponse)
def post_job(
    job: schemas.JobCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """RECRUITER ONLY: Post a new job."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Only recruiters can post jobs")
    
    new_job = models.Job(
        recruiter_id=user.id,
        company_id=job.company_id,
        title=job.title,
        description=job.description,
        location=job.location,
        employment_type=job.employment_type,
        skills_required=job.skills_required,
        salary_range=job.salary_range,
        deadline=job.deadline
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    return new_job

@app.get("/jobs", response_model=list[schemas.JobResponse])
def list_jobs(db: Session = Depends(get_db)):
    """PUBLIC: This is the endpoint the Job Board calls to see all jobs."""
    return db.query(models.Job).filter(models.Job.is_active == True).all()

@app.get("/my-jobs", response_model=list[schemas.JobResponse])
def list_my_jobs(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """RECRUITER ONLY: List jobs posted by the logged-in recruiter."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    return db.query(models.Job).filter(models.Job.recruiter_id == user.id).all()

# --- APPLICATION ENDPOINTS ---

@app.post("/applications", response_model=schemas.ApplicationResponse)
def apply_to_job(
    app_data: schemas.ApplicationCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """JOB SEEKER ONLY: Apply to a job using an encrypted resume."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if user.role != "job_seeker":
        raise HTTPException(status_code=403, detail="Only job seekers can apply for jobs")
    
    # Verify the resume belongs to the user
    resume = db.query(models.Resume).filter(models.Resume.id == app_data.resume_id, models.Resume.user_id == user.id).first()
    if not resume:
        raise HTTPException(status_code=404, detail="Resume not found or access denied")

    new_app = models.Application(
        job_id=app_data.job_id,
        applicant_id=user.id,
        resume_id=app_data.resume_id,
        cover_letter=app_data.cover_letter
    )
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return new_app

@app.get("/applications/my", response_model=list[dict])
def list_my_applications(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """JOB SEEKER ONLY: View applications with Job Title and Recruiter ID."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    results = db.query(
        models.Application, 
        models.Job.title.label("job_title"),
        models.Job.recruiter_id.label("recruiter_id") 
    ).join(models.Job, models.Job.id == models.Application.job_id)\
     .filter(models.Application.applicant_id == user.id).all()

    output = []
    for app_obj, title, r_id in results:
        output.append({
            "id": app_obj.id, "job_id": app_obj.job_id, "applicant_id": app_obj.applicant_id,
            "resume_id": app_obj.resume_id, "cover_letter": app_obj.cover_letter,
            "status": app_obj.status, "applied_at": app_obj.applied_at,
            "job_title": title, "recruiter_id": r_id 
        })
    return output

@app.get("/applications/recruiter", response_model=list[schemas.ApplicationDetail])
def list_recruiter_applications(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """RECRUITER ONLY: View all applicants for your jobs."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Query: Get applications for jobs owned by this recruiter
    results = db.query(
        models.Application, 
        models.User.full_name.label("applicant_name"),
        models.Job.title.label("job_title")
    ).join(models.Job, models.Job.id == models.Application.job_id)\
     .join(models.User, models.User.id == models.Application.applicant_id)\
     .filter(models.Job.recruiter_id == user.id).all()
    
    # Manually build the list to ensure Pydantic accepts it
    output = []
    for app_obj, name, title in results:
        output.append({
            "id": app_obj.id,
            "job_id": app_obj.job_id,
            "applicant_id": app_obj.applicant_id,
            "resume_id": app_obj.resume_id,
            "cover_letter": app_obj.cover_letter,
            "status": app_obj.status,
            "applied_at": app_obj.applied_at,
            "applicant_name": name,
            "job_title": title
        })
    return output

# --- MESSAGING ENDPOINTS ---

@app.post("/users/public-key")
def update_public_key(
    data: schemas.PublicKeyUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """Save the user's generated public key to the database."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    user.public_key = data.public_key
    db.commit()
    return {"message": "Public key updated"}

@app.get("/users/{user_id}/public-key")
def get_user_public_key(user_id: int, db: Session = Depends(get_db)):
    """Fetch a recipient's public key for encryption."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.public_key:
        raise HTTPException(status_code=404, detail="Public key not found")
    return {"public_key": user.public_key}

@app.post("/messages", response_model=schemas.MessageResponse)
def send_message(
    msg: schemas.MessageCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """Store an E2EE encrypted message (ciphertext only)."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    new_msg = models.Message(
        sender_id=user.id,
        receiver_id=msg.receiver_id,
        encrypted_content=msg.encrypted_content
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    return new_msg

@app.get("/messages/{other_user_id}", response_model=list[schemas.MessageResponse])
def get_messages(
    other_user_id: int,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """Fetch encrypted chat history between two users."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    return db.query(models.Message).filter(
        ((models.Message.sender_id == user.id) & (models.Message.receiver_id == other_user_id)) |
        ((models.Message.sender_id == other_user_id) & (models.Message.receiver_id == user.id))
    ).order_by(models.Message.timestamp.asc()).all()
