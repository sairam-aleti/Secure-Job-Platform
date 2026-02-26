from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional, List
from app import models, schemas, security, auth, otp, encryption
from app.database import engine, get_db
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from datetime import datetime, timedelta, timezone 
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
import os
import base64
import hashlib
from app import parser

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

conf = ConnectionConfig(
    MAIL_USERNAME = "fortknox914@gmail.com", 
    MAIL_PASSWORD = "lrigfpadqfothkxs",       
    MAIL_FROM = "fortknox914@gmail.com",     
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

fastmail = FastMail(conf)

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
    # 1. Check if email already exists
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    
    if existing_user:
        # IF USER EXISTS BUT IS VERIFIED: Block them (Security)
        if existing_user.is_verified:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # IF USER EXISTS BUT IS NOT VERIFIED: Allow update (User Experience)
        existing_user.hashed_password = security.hash_password(user.password)
        existing_user.full_name = user.full_name
        existing_user.role = user.role
        db.commit()
        db.refresh(existing_user)
        return existing_user
    
    # 2. If new user, create normally
    hashed_password = security.hash_password(user.password)
    new_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        role=user.role,
        is_verified=False
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
async def send_otp(
    request: Request, 
    otp_request: schemas.OTPRequest, 
    background_tasks: BackgroundTasks, # For non-blocking email sending
    db: Session = Depends(get_db)
):
    """
    SEND OTP VIA REAL GMAIL
    - Restricted to @gmail.com and @iiitd.ac.in
    - Uses BackgroundTasks to prevent UI freezing
    """
    user = db.query(models.User).filter(models.User.email == otp_request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 1. Security Check: Account Lockout
    if user.locked_until and otp.is_account_locked(user.locked_until):
        raise HTTPException(status_code=403, detail="Account locked. Try again later.")
    
    db.query(models.OTP).filter(
        models.OTP.user_id == user.id, 
        models.OTP.is_used == False
    ).update({"is_used": True})
    
    # 2. Generate and Save OTP
    otp_code = otp.generate_otp()
    new_otp = models.OTP(
        user_id=user.id,
        code=otp_code,
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_otp)
    db.commit()

    # 3. Create Email Message
    message = MessageSchema(
        subject="FortKnox Security - Your Verification Code",
        recipients=[user.email],
        body=f"Hello {user.full_name},\n\nYour security verification code is: {otp_code}\n\nThis code will expire in 10 minutes.\n\nStay Secure,\nFortKnox Team",
        subtype=MessageType.plain
    )

    # 4. Send Email in Background (Security best practice for performance)
    background_tasks.add_task(fastmail.send_message, message)

    return {
        "message": "A verification code has been sent to your registered email.",
        "dev_otp": None # SECURITY: No longer leaking OTP in API response
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
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    SECURE RESUME UPLOAD WITH PARSING
    - Parses text for matching before encryption
    - Encrypts file with AES-256-GCM for storage
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")
    
    allowed_extensions = [".pdf", ".docx"]
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Only PDF and DOCX files are allowed")
    
    # Read file content
    file_content = file.file.read()
    file_size = len(file_content)
    
    if file_size > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large")

    # --- NEW: PARSE TEXT FOR INTELLIGENT MATCHING ---
    extracted_text = ""
    if file_extension == ".pdf":
        extracted_text = parser.extract_text_from_pdf(file_content)

    # Encryption process
    encryption_key = encryption.generate_key()
    encrypted_data, nonce = encryption.encrypt_file(file_content, encryption_key)
    
    encrypted_filename = f"{user.id}_{os.urandom(8).hex()}{file_extension}.enc"
    file_path = os.path.join("uploads", encrypted_filename)
    
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
    
    # Save metadata AND extracted skills
    resume = models.Resume(
        user_id=user.id,
        original_filename=file.filename,
        encrypted_filename=encrypted_filename,
        encryption_key=encryption.key_to_string(encryption_key),
        nonce=base64.b64encode(nonce).decode('utf-8'),
        file_size=file_size,
        extracted_skills=extracted_text # NEW: Storing text for the recommendation engine
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

@app.put("/applications/{application_id}/status")
def update_application_status(
    application_id: int,
    status_data: schemas.ApplicationStatusUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """RECRUITER ONLY: Update the status of an application and log the change."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # 1. Security Check: Role
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Only recruiters can update application status")
    
    # 2. Find Application
    application = db.query(models.Application).filter(models.Application.id == application_id).first()
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
        
    # 3. Security Check: Ownership (Does this recruiter own the job?)
    job = db.query(models.Job).filter(models.Job.id == application.job_id).first()
    if job.recruiter_id != user.id:
        raise HTTPException(status_code=403, detail="Unauthorized: This is not your job posting")
        
    # 4. Update Status
    old_status = application.status
    application.status = status_data.status
    
    # 5. Audit Log (Cryptographic Chain)
    create_audit_log(db, "APP_STATUS_CHANGE", user.email, f"App ID {application_id}: {old_status} -> {status_data.status}")
    
    db.commit()
    return {"message": "Status updated successfully", "new_status": application.status}

# --- INTELLIGENT MATCHING ENDPOINT (Bonus +2%) ---

@app.get("/jobs/recommendations")
def get_job_recommendations(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    JOB SEEKER ONLY: Suggest Top 3 jobs based on resume parsing.
    - Fetches the user's latest resume text.
    - Compares text against all active job skills.
    - Returns the Top 3 matches with scores.
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # 1. Get the latest resume for this user
    resume = db.query(models.Resume).filter(
        models.Resume.user_id == user.id
    ).order_by(models.Resume.uploaded_at.desc()).first()
    
    if not resume or not resume.extracted_skills:
        return []

    # 2. Get all active jobs from other recruiters (or all jobs)
    all_jobs = db.query(models.Job).filter(models.Job.is_active == True).all()
    
    # 3. Calculate scores
    recommendations = []
    for job in all_jobs:
        # We join with the Company table to get the name for the UI
        company = db.query(models.Company).filter(models.Company.id == job.company_id).first()
        company_name = company.name if company else "Unknown Company"
        
        score = parser.calculate_match_score(resume.extracted_skills, job.skills_required)
        
        # Only suggest if there is some match
        if score > 0:
            recommendations.append({
                "job_id": job.id,
                "title": job.title,
                "company": company_name,
                "location": job.location,
                "type": job.employment_type,
                "match_score": score
            })
    
    # 4. Sort by score (highest first) and take Top 3
    recommendations.sort(key=lambda x: x['match_score'], reverse=True)
    return recommendations[:3]

@app.get("/users/directory")
def get_user_directory(
    q: Optional[str] = None,
    page: int = 1,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """List users with connection status, ensuring keys match the frontend."""
    limit = 15
    offset = (page - 1) * limit
    current_user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # 1. Filter out me and admins
    query = db.query(models.User).filter(
        models.User.id != current_user.id,
        models.User.role != "admin"
    )
    
    if q:
        query = query.filter(
            (models.User.full_name.ilike(f"%{q}%")) | 
            (models.User.headline.ilike(f"%{q}%"))
        )
    
    users = query.offset(offset).limit(limit).all()
    
    output = []
    for u in users:
        # Check relationship in either direction
        conn = db.query(models.Connection).filter(
            ((models.Connection.user_id == current_user.id) & (models.Connection.connection_id == u.id)) |
            ((models.Connection.user_id == u.id) & (models.Connection.connection_id == current_user.id))
        ).first()
        
        status = "none"
        request_id = None
        if conn:
            if conn.status == "accepted":
                status = "accepted"
            else:
                # Distinguish if I sent it or received it
                status = "request_sent" if conn.user_id == current_user.id else "request_received"
            request_id = conn.id

        output.append({
            "id": u.id,
            "full_name": u.full_name,
            "headline": u.headline or "Professional Member",
            "role": u.role,
            "connection_status": status,
            "request_id": request_id
        })
        
    return output

@app.get("/users/{user_id}/profile", response_model=schemas.UserProfilePublic)
def get_other_user_profile(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    SECURE PROFILE VIEW (Requirement A)
    - Enforces Field-Level Privacy
    - Tracks Recent Viewers (with 5-min cooldown)
    - Calculates Mutual Connections (Graph Logic)
    """
    me = db.query(models.User).filter(models.User.email == current_user_email).first()
    target = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
        
    # 1. Check if we are directly connected
    conn = db.query(models.Connection).filter(
        ((models.Connection.user_id == me.id) & (models.Connection.connection_id == target.id) & (models.Connection.status == "accepted")) |
        ((models.Connection.user_id == target.id) & (models.Connection.connection_id == me.id) & (models.Connection.status == "accepted"))
    ).first()
    
    is_connected = True if conn else False
    
    # 2. Privacy Filter Logic
    def filter_field(value, privacy_level):
        if privacy_level == "public":
            return value
        if privacy_level == "connections" and is_connected:
            return value
        return "RESTRICTED_BY_PRIVACY" if value else None

    # 3. Smart Profile View Recording (Prevents duplicates within 5 minutes)
    if me.id != target.id:
        five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent_view = db.query(models.ProfileView).filter(
            models.ProfileView.viewer_id == me.id,
            models.ProfileView.target_id == target.id,
            models.ProfileView.timestamp > five_minutes_ago
        ).first()

        if not recent_view:
            new_view = models.ProfileView(viewer_id=me.id, target_id=target.id)
            db.add(new_view)
            create_audit_log(db, "PROFILE_VIEW", me.email, f"Viewed user ID: {target.id}")
            db.commit()

    # 4. Calculate Mutual Connections (Requirement 2A)
    # Get IDs of people connected to ME
    my_conns = db.query(models.Connection).filter(
        (models.Connection.status == "accepted") & 
        ((models.Connection.user_id == me.id) | (models.Connection.connection_id == me.id))
    ).all()
    my_conn_ids = {c.user_id if c.connection_id == me.id else c.connection_id for c in my_conns}

    # Get IDs of people connected to TARGET
    target_conns = db.query(models.Connection).filter(
        (models.Connection.status == "accepted") & 
        ((models.Connection.user_id == target.id) | (models.Connection.connection_id == target.id))
    ).all()
    target_conn_ids = {c.user_id if c.connection_id == target.id else c.connection_id for c in target_conns}

    # Find intersection of sets
    mutual_count = len(my_conn_ids.intersection(target_conn_ids))

    return {
        "id": target.id,
        "full_name": target.full_name,
        "role": target.role,
        "headline": filter_field(target.headline, target.headline_privacy),
        "location": filter_field(target.location, target.location_privacy),
        "bio": filter_field(target.bio, target.bio_privacy),
        "skills": filter_field(target.skills, target.skills_privacy),
        "experience": filter_field(target.experience, target.experience_privacy),
        "education": filter_field(target.education, target.education_privacy),
        "mutual_connections": mutual_count
    }

@app.get("/profile/viewers")
def get_recent_viewers(
    db: Session = Depends(get_db), 
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    SECURE VIEWERS LIST: Shows who looked at your profile.
    - Respects "Anonymous Mode" (share_view_history toggle).
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # Get the 5 most recent views for this user
    views = db.query(
        models.ProfileView, 
        models.User.full_name, 
        models.User.share_view_history
    ).join(models.User, models.User.id == models.ProfileView.viewer_id)\
     .filter(models.ProfileView.target_id == user.id)\
     .order_by(models.ProfileView.timestamp.desc())\
     .limit(5).all()

    output = []
    for view_obj, viewer_name, can_share in views:
        output.append({
            "timestamp": view_obj.timestamp,
            # PRIVACY CHECK: If viewer opted out, hide their name
            "viewer_name": viewer_name if can_share else "Anonymous Professional"
        })
    return output

# --- CONNECTION LOGIC ---

@app.post("/connections/request", response_model=schemas.ConnectionResponse)
def send_connection_request(
    data: schemas.ConnectionRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """Send a connection request to another user."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    if user.id == data.receiver_id:
        raise HTTPException(status_code=400, detail="Cannot connect to yourself")

    # Check if request already exists (either direction)
    exists = db.query(models.Connection).filter(
        ((models.Connection.user_id == user.id) & (models.Connection.connection_id == data.receiver_id)) |
        ((models.Connection.user_id == data.receiver_id) & (models.Connection.connection_id == user.id))
    ).first()
    
    if exists:
        raise HTTPException(status_code=400, detail="Connection or request already exists")

    new_request = models.Connection(
        user_id=user.id,
        connection_id=data.receiver_id,
        status="pending"
    )
    db.add(new_request)
    
    # AUDIT LOG (Security Requirement H)
    create_audit_log(db, "CONN_REQUEST_SENT", user.email, f"Target ID: {data.receiver_id}")
    
    db.commit()
    db.refresh(new_request)
    return new_request

@app.get("/connections/pending", response_model=List[dict])
def get_pending_requests(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """Get incoming connection requests for the current user."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    requests = db.query(
        models.Connection.id.label("request_id"),
        models.User.full_name.label("name"),
        models.User.email.label("email")
    ).join(models.User, models.User.id == models.Connection.user_id)\
     .filter((models.Connection.connection_id == user.id) & (models.Connection.status == "pending")).all()
    
    # Format to list of dictionaries
    return [dict(r._mapping) for r in requests]

@app.put("/connections/accept")
def update_connection_status(
    data: schemas.ConnectionUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """Accept or Reject a connection request."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    conn_req = db.query(models.Connection).filter(models.Connection.id == data.request_id).first()
    
    if not conn_req or conn_req.connection_id != user.id:
        raise HTTPException(status_code=404, detail="Request not found")
        
    if data.status == "accepted":
        conn_req.status = "accepted"
        create_audit_log(db, "CONN_ACCEPTED", user.email, f"Sender ID: {conn_req.user_id}")
    else:
        db.delete(conn_req)
        create_audit_log(db, "CONN_REJECTED", user.email, f"Sender ID: {conn_req.user_id}")
        
    db.commit()
    return {"message": f"Connection {data.status}"}