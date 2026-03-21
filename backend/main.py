from dotenv import load_dotenv
load_dotenv()  # Load .env file FIRST before any other imports that use env vars

from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional, List
from app import models, schemas, security, auth, otp, encryption
from app.database import engine, get_db
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
import os
import base64
import hashlib
import hmac
import re
import logging
import uuid
from app import parser

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Configure logging (replaces all print() statements)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- SERVER PKI KEY (Persistent across restarts) ---
PKI_KEY_PATH = os.environ.get("SERVER_PKI_KEY_PATH", "server_private_key.pem")

def _load_or_generate_server_key():
    """Load persistent server PKI key, or generate one if it doesn't exist."""
    if os.path.exists(PKI_KEY_PATH):
        with open(PKI_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        logger.info("Loaded existing server PKI key")
        return private_key
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PKI_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(PKI_KEY_PATH, 0o600)  # Owner-only read/write
        logger.info("Generated and saved new server PKI key")
        return private_key

SERVER_PRIVATE_KEY = _load_or_generate_server_key()
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()

# --- AUDIT LOG HMAC KEY ---
AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", "change-this-hmac-key").encode()

def create_audit_log(db: Session, action: str, admin_email: str, target: str = None):
    last_log = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).first()
    prev_hash = last_log.log_hash if last_log else "0"
    
    now = datetime.now(timezone.utc)
    
    # SECURITY FIX: Use HMAC instead of plain SHA-256 for tamper-evident logs
    log_data = f"{action}-{admin_email}-{target}-{prev_hash}-{now}"
    current_hash = hmac.new(AUDIT_HMAC_KEY, log_data.encode(), hashlib.sha256).hexdigest()
    
    new_log = models.AuditLog(
        action=action,
        performed_by=admin_email,
        target_user=target,
        log_hash=current_hash,
        previous_hash=prev_hash,
        timestamp=now
    )
    db.add(new_log)

# Create all database tables
models.Base.metadata.create_all(bind=engine)

# --- ENVIRONMENT-BASED CONFIGURATION ---
IS_PRODUCTION = os.environ.get("ENVIRONMENT", "development") == "production"

# API Path Randomization: configurable prefix to obscure endpoints from scanners
API_PREFIX = os.environ.get("API_PREFIX", "/api/v1")

# Initialize FastAPI — disable docs in production, hide server identity
app = FastAPI(
    title="Secure Job Platform",
    version="2.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json"
)

# --- SMTP CONFIGURATION (from environment variables) ---
conf = ConnectionConfig(
    MAIL_USERNAME = os.environ.get("SMTP_USERNAME", "fortknox914@gmail.com"),
    MAIL_PASSWORD = os.environ.get("SMTP_PASSWORD", ""),
    MAIL_FROM = os.environ.get("SMTP_FROM", "fortknox914@gmail.com"),
    MAIL_PORT = int(os.environ.get("SMTP_PORT", "587")),
    MAIL_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

fastmail = FastMail(conf)

# --- SECURITY HEADERS + SERVER FINGERPRINT REMOVAL MIDDLEWARE ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Add unique request ID for tracing
    request_id = str(uuid.uuid4())[:8]
    
    response = await call_next(request)
    
    # Security headers
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://127.0.0.1:8000"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    
    # Request ID for tracing
    response.headers["X-Request-ID"] = request_id
    
    # ANTI-FINGERPRINTING: Remove/replace server identity headers
    response.headers["Server"] = "FortKnox"
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]
    
    return response

# --- CORS Configuration (restricted) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Rate Limiting Configuration
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- HELPER: Sanitize filename for Content-Disposition ---
def sanitize_filename(filename: str) -> str:
    """Remove path components and unsafe characters from filename."""
    # Strip path separators
    filename = os.path.basename(filename)
    # Allow only safe characters
    filename = re.sub(r'[^\w\s\-\.]', '_', filename)
    return filename[:200]  # Limit length

# --- HELPER: Validate file magic bytes ---
MAGIC_BYTES = {
    ".pdf": b"%PDF",
    ".docx": b"PK\x03\x04",  # DOCX is a ZIP archive
}

def validate_file_content(file_content: bytes, extension: str) -> bool:
    """Check if file content matches expected magic bytes."""
    expected = MAGIC_BYTES.get(extension)
    if expected:
        return file_content[:len(expected)] == expected
    return False

# --- HELPER: Escape LIKE special characters ---
def escape_like(value: str) -> str:
    """Escape SQL LIKE special characters."""
    return value.replace('%', r'\%').replace('_', r'\_')


@app.get("/")
def home():
    return {"status": "Secure Job Platform Active", "version": "2.0"}

# ==================== REGISTRATION ====================

@app.post("/register", response_model=schemas.UserResponse)
@limiter.limit("10/minute")
def register_user(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    # 1. Check if email already exists
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    
    if existing_user:
        if existing_user.is_verified:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # IF USER EXISTS BUT IS NOT VERIFIED: Allow update
        existing_user.hashed_password = security.hash_password(user.password)
        existing_user.full_name = user.full_name
        existing_user.role = user.role
        db.commit()
        db.refresh(existing_user)
        return existing_user
    
    # 2. Create new user (admin can register but needs superadmin approval for destructive actions)
    hashed_password = security.hash_password(user.password)
    new_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        role=user.role,
        is_verified=False,
        is_admin_approved=(user.role != "admin")  # Non-admins are auto-approved
    )
    db.add(new_user)
    
    # Audit log
    create_audit_log(db, "USER_REGISTERED", user.email, f"Role: {user.role}")
    
    db.commit()
    db.refresh(new_user)
    return new_user

# ==================== LOGIN ====================

@app.post("/login", response_model=schemas.Token)
@limiter.limit("10/minute")
def login(request: Request, user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """
    SECURE LOGIN with:
    - Rate limiting
    - Audit logging (success + failure)
    - Single session enforcement (old sessions invalidated)
    - Browser fingerprint binding
    """
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()
    if not user:
        create_audit_log(db, "LOGIN_FAILED", user_credentials.email, "User not found")
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not security.verify_password(user_credentials.password, user.hashed_password):
        create_audit_log(db, "LOGIN_FAILED", user_credentials.email, "Wrong password")
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        create_audit_log(db, "LOGIN_BLOCKED", user_credentials.email, "Account suspended")
        db.commit()
        raise HTTPException(status_code=403, detail="Account suspended")
    
    # SINGLE SESSION: Generate unique JTI, store in DB to invalidate any previous session
    session_jti = auth.generate_session_id()
    fingerprint = auth.compute_fingerprint(request)
    
    # If user already has a session, log it (they're being logged out from the other device)
    if user.session_id:
        create_audit_log(db, "SESSION_REPLACED", user.email, f"Old session invalidated, new login from IP {request.client.host}")
    
    # Store session info in DB
    user.session_id = session_jti
    user.session_fingerprint = fingerprint
    
    access_token, _ = auth.create_access_token(
        data={"sub": user.email, "role": user.role, "jti": session_jti}
    )
    
    create_audit_log(db, "LOGIN_SUCCESS", user.email, f"IP: {request.client.host}")
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer"}

# ==================== OTP ====================

@app.post("/send-otp", response_model=schemas.OTPResponse)
@limiter.limit("5/15minutes")
async def send_otp(
    request: Request, 
    otp_request: schemas.OTPRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == otp_request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.locked_until and otp.is_account_locked(user.locked_until):
        raise HTTPException(status_code=403, detail="Account locked. Try again later.")
    
    # Invalidate all existing unused OTPs
    db.query(models.OTP).filter(
        models.OTP.user_id == user.id, 
        models.OTP.is_used == False
    ).update({"is_used": True})
    
    otp_code = otp.generate_otp()
    new_otp = models.OTP(
        user_id=user.id,
        code=otp_code,
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_otp)
    db.commit()

    message = MessageSchema(
        subject="FortKnox Security - Your Verification Code",
        recipients=[user.email],
        body=f"Hello {user.full_name},\n\nYour security verification code is: {otp_code}\n\nThis code will expire in 2 minutes.\n\nStay Secure,\nFortKnox Team",
        subtype=MessageType.plain
    )

    background_tasks.add_task(fastmail.send_message, message)

    return {
        "message": "A verification code has been sent to your registered email.",
        "dev_otp": None
    }

@app.post("/verify-otp")
@limiter.limit("10/minute")
def verify_otp_code(request: Request, otp_verify: schemas.OTPVerify, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == otp_verify.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Account already verified")
    
    if user.locked_until and otp.is_account_locked(user.locked_until):
        raise HTTPException(
            status_code=403,
            detail="Account locked due to too many failed attempts. Try again later."
        )
    
    db_otp = db.query(models.OTP).filter(
        models.OTP.user_id == user.id,
        models.OTP.is_used == False
    ).order_by(models.OTP.created_at.desc()).first()
    
    if not db_otp:
        raise HTTPException(status_code=400, detail="No OTP found. Please request a new one.")
    
    if otp.is_otp_expired(db_otp.created_at):
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new one.")
    
    if db_otp.code != otp_verify.otp_code:
        user.failed_otp_attempts += 1
        
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
    
    user.is_verified = True
    user.failed_otp_attempts = 0
    user.locked_until = None
    db_otp.is_used = True
    
    db.commit()
    
    return {
        "message": "Email verified successfully",
        "is_verified": True
    }

# ==================== RESUME UPLOAD/DOWNLOAD ====================

@app.post("/upload-resume", response_model=schemas.ResumeResponse)
def upload_resume(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    SECURE RESUME UPLOAD WITH PARSING AND PKI
    - Validates file type by magic bytes (not just extension)
    - Signs original file with Server Private Key
    - Encrypts file with AES-256-GCM, key envelope-encrypted with master key
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")
    
    allowed_extensions = [".pdf", ".docx"]
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Only PDF and DOCX files are allowed")
    
    file_content = file.file.read()
    file_size = len(file_content)
    
    if file_size > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # SECURITY FIX: Validate magic bytes
    if not validate_file_content(file_content, file_extension):
        raise HTTPException(status_code=400, detail="File content does not match expected format. Upload rejected.")

    # Parse text for intelligent matching (before encryption)
    extracted_text = ""
    if file_extension == ".pdf":
        extracted_text = parser.extract_text_from_pdf(file_content)

    # Encryption process
    encryption_key = encryption.generate_key()
    encrypted_data, nonce = encryption.encrypt_file(file_content, encryption_key)
    
    # SECURITY FIX: Sanitize filename
    safe_filename = sanitize_filename(file.filename)
    encrypted_filename = f"{user.id}_{os.urandom(8).hex()}{file_extension}.enc"
    file_path = os.path.join("uploads", encrypted_filename)
    
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
        
    # PKI Signature
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_content)
    file_hash = digest.finalize()
    
    signature_bytes = SERVER_PRIVATE_KEY.sign(
        file_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    
    # SECURITY FIX: Envelope-encrypt the per-file key before DB storage
    encrypted_file_key = encryption.envelope_encrypt_key(encryption_key)
    
    resume = models.Resume(
        user_id=user.id,
        original_filename=safe_filename,
        encrypted_filename=encrypted_filename,
        encryption_key=encrypted_file_key,  # Now envelope-encrypted
        nonce=base64.b64encode(nonce).decode('utf-8'),
        file_size=file_size,
        extracted_skills=extracted_text,
        signature=signature_b64
    )
    
    db.add(resume)
    
    # Audit log
    create_audit_log(db, "RESUME_UPLOADED", user.email, f"File: {safe_filename}")
    
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
    SECURE RESUME DOWNLOAD with PKI integrity verification.
    """
    from fastapi.responses import Response
    
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    resume = db.query(models.Resume).filter(models.Resume.id == resume_id).first()
    
    # SECURITY FIX: Uniform response to prevent enumeration
    if not resume:
        raise HTTPException(status_code=403, detail="Access denied")
    
    allowed = False
    
    if resume.user_id == user.id:
        allowed = True
    elif user.role == "admin":
        allowed = True
    elif user.role == "recruiter":
        application = db.query(models.Application).join(
            models.Job, models.Job.id == models.Application.job_id
        ).filter(
            models.Application.resume_id == resume_id,
            models.Job.recruiter_id == user.id
        ).first()
        if application:
            allowed = True

    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied")
    
    file_path = os.path.join("uploads", resume.encrypted_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        # SECURITY FIX: Envelope-decrypt the per-file key
        encryption_key = encryption.envelope_decrypt_key(resume.encryption_key)
        nonce = base64.b64decode(resume.nonce.encode('utf-8'))
        decrypted_data = encryption.decrypt_file(encrypted_data, encryption_key, nonce)
        
        # PKI Integrity Verification
        if resume.signature:
            try:
                digest = hashes.Hash(hashes.SHA256())
                digest.update(decrypted_data)
                file_hash = digest.finalize()
                
                sig_bytes = base64.b64decode(resume.signature.encode('utf-8'))
                
                SERVER_PUBLIC_KEY.verify(
                    sig_bytes,
                    file_hash,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                logger.info(f"PKI VERIFIED: Resume {resume_id} integrity confirmed.")
            except Exception:
                logger.warning(f"PKI ALERT: Resume {resume_id} failed integrity check!")
                raise HTTPException(status_code=500, detail="Resume integrity verification failed.")
                  
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed.")
    
    # Audit log
    create_audit_log(db, "RESUME_DOWNLOADED", current_user_email, f"Resume ID: {resume_id}")
    db.commit()
    
    # SECURITY FIX: Sanitize filename in Content-Disposition header
    safe_name = sanitize_filename(resume.original_filename)
    
    return Response(
        content=decrypted_data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
    )

@app.get("/my-resumes", response_model=list[schemas.ResumeResponse])
def list_my_resumes(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    resumes = db.query(models.Resume).filter(models.Resume.user_id == user.id).all()
    return resumes

# ==================== PROFILE ====================

@app.get("/profile", response_model=schemas.ProfileResponse)
def get_profile(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
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
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # SECURITY: Only update fields defined in the schema (not role, email, etc.)
    update_data = profile_update.model_dump(exclude_unset=True)
    
    # Whitelist of allowed fields
    allowed_fields = {
        'headline', 'location', 'bio', 'skills', 'experience', 'education',
        'headline_privacy', 'location_privacy', 'bio_privacy', 
        'skills_privacy', 'experience_privacy', 'education_privacy',
        'share_view_history'
    }
    
    for field, value in update_data.items():
        if field in allowed_fields:
            setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    
    return user

# ==================== ADMIN ====================

@app.get("/admin/users", response_model=list[schemas.UserListItem])
def list_all_users(
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    users = db.query(models.User).all()
    return users

@app.post("/admin/request-action", response_model=schemas.AdminActionResponse)
def request_admin_action(
    action: schemas.AdminActionRequest,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """
    Admin requests a destructive action (suspend/delete/activate).
    The action goes into a queue for SUPERADMIN approval.
    Superadmins can execute directly.
    """
    admin_user = db.query(models.User).filter(models.User.email == admin_email).first()
    target = db.query(models.User).filter(models.User.id == action.target_user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    if target.role in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Cannot perform actions on other admins")
    
    # SUPERADMIN: Execute immediately without queue
    if admin_user.role == "superadmin":
        if action.action_type == "suspend":
            target.is_active = False
            create_audit_log(db, "USER_SUSPENDED", admin_email, target.email)
        elif action.action_type == "activate":
            target.is_active = True
            create_audit_log(db, "USER_ACTIVATED", admin_email, target.email)
        elif action.action_type == "delete":
            create_audit_log(db, "USER_DELETED", admin_email, target.email)
            db.delete(target)
        
        # Record it in the queue as auto-approved for audit trail
        queue_entry = models.AdminActionQueue(
            action_type=action.action_type,
            requested_by=admin_email,
            target_user_id=action.target_user_id,
            target_user_email=target.email,
            status="approved",
            reason=action.reason,
            reviewed_by=admin_email,
            reviewed_at=datetime.now(timezone.utc)
        )
        db.add(queue_entry)
        db.commit()
        db.refresh(queue_entry)
        return queue_entry
    
    # REGULAR ADMIN: Queue for superadmin approval
    queue_entry = models.AdminActionQueue(
        action_type=action.action_type,
        requested_by=admin_email,
        target_user_id=action.target_user_id,
        target_user_email=target.email,
        status="pending",
        reason=action.reason
    )
    db.add(queue_entry)
    create_audit_log(db, f"ADMIN_ACTION_REQUESTED", admin_email, f"{action.action_type} user {target.email}")
    db.commit()
    db.refresh(queue_entry)
    return queue_entry

@app.get("/admin/action-queue", response_model=list[schemas.AdminActionResponse])
def get_action_queue(
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """View all pending admin actions (admins see their own, superadmins see all)."""
    admin_user = db.query(models.User).filter(models.User.email == admin_email).first()
    if admin_user.role == "superadmin":
        return db.query(models.AdminActionQueue).order_by(models.AdminActionQueue.created_at.desc()).all()
    return db.query(models.AdminActionQueue).filter(
        models.AdminActionQueue.requested_by == admin_email
    ).order_by(models.AdminActionQueue.created_at.desc()).all()

@app.post("/superadmin/review-action", response_model=schemas.AdminActionResponse)
def review_admin_action(
    review: schemas.AdminActionReview,
    db: Session = Depends(get_db),
    superadmin_email: str = Depends(auth.require_superadmin)
):
    """
    SUPERADMIN ONLY: Approve or reject a pending admin action.
    Only approved actions are executed.
    """
    queue_item = db.query(models.AdminActionQueue).filter(
        models.AdminActionQueue.id == review.action_id,
        models.AdminActionQueue.status == "pending"
    ).first()
    if not queue_item:
        raise HTTPException(status_code=404, detail="Pending action not found")
    
    queue_item.reviewed_by = superadmin_email
    queue_item.reviewed_at = datetime.now(timezone.utc)
    
    if review.decision == "approved":
        queue_item.status = "approved"
        target = db.query(models.User).filter(models.User.id == queue_item.target_user_id).first()
        if target:
            if queue_item.action_type == "suspend":
                target.is_active = False
                target.session_id = None  # Force logout
                create_audit_log(db, "USER_SUSPENDED", superadmin_email, target.email)
            elif queue_item.action_type == "activate":
                target.is_active = True
                create_audit_log(db, "USER_ACTIVATED", superadmin_email, target.email)
            elif queue_item.action_type == "delete":
                create_audit_log(db, "USER_DELETED", superadmin_email, target.email)
                db.delete(target)
        create_audit_log(db, "ADMIN_ACTION_APPROVED", superadmin_email, f"Action ID: {review.action_id}")
    else:
        queue_item.status = "rejected"
        create_audit_log(db, "ADMIN_ACTION_REJECTED", superadmin_email, f"Action ID: {review.action_id}")
    
    db.commit()
    db.refresh(queue_item)
    return queue_item

@app.post("/superadmin/approve-admin/{user_id}")
def approve_admin_registration(
    user_id: int,
    db: Session = Depends(get_db),
    superadmin_email: str = Depends(auth.require_superadmin)
):
    """SUPERADMIN ONLY: Approve an admin account for full admin powers."""
    user = db.query(models.User).filter(models.User.id == user_id, models.User.role == "admin").first()
    if not user:
        raise HTTPException(status_code=404, detail="Admin user not found")
    user.is_admin_approved = True
    create_audit_log(db, "ADMIN_APPROVED", superadmin_email, user.email)
    db.commit()
    return {"message": f"Admin {user.email} has been approved"}

@app.get("/admin/audit-logs", response_model=list[schemas.AuditLogResponse])
def get_audit_logs(db: Session = Depends(get_db), admin_email: str = Depends(auth.require_admin)):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).all()

# Legacy endpoints for backward compatibility (redirect to queue system)
@app.post("/admin/suspend/{user_id}", response_model=schemas.AdminAction)
def suspend_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """Legacy: Redirects to the queue system."""
    admin_user = db.query(models.User).filter(models.User.email == admin_email).first()
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Cannot suspend admins")
    
    # Superadmin: execute immediately
    if admin_user.role == "superadmin":
        user.is_active = False
        user.session_id = None
        create_audit_log(db, "USER_SUSPENDED", admin_email, user.email)
        db.commit()
        return {"message": f"User {user.email} has been suspended", "user_id": user_id}
    
    # Regular admin: queue it
    queue_entry = models.AdminActionQueue(
        action_type="suspend", requested_by=admin_email,
        target_user_id=user_id, target_user_email=user.email, status="pending"
    )
    db.add(queue_entry)
    create_audit_log(db, "ADMIN_ACTION_REQUESTED", admin_email, f"suspend {user.email}")
    db.commit()
    return {"message": f"Suspend request queued for superadmin approval", "user_id": user_id}

@app.post("/admin/activate/{user_id}", response_model=schemas.AdminAction)
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """Legacy: Redirects to the queue system."""
    admin_user = db.query(models.User).filter(models.User.email == admin_email).first()
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if admin_user.role == "superadmin":
        user.is_active = True
        create_audit_log(db, "USER_ACTIVATED", admin_email, user.email)
        db.commit()
        return {"message": f"User {user.email} has been activated", "user_id": user_id}
    
    queue_entry = models.AdminActionQueue(
        action_type="activate", requested_by=admin_email,
        target_user_id=user_id, target_user_email=user.email, status="pending"
    )
    db.add(queue_entry)
    create_audit_log(db, "ADMIN_ACTION_REQUESTED", admin_email, f"activate {user.email}")
    db.commit()
    return {"message": f"Activate request queued for superadmin approval", "user_id": user_id}

@app.delete("/admin/delete/{user_id}", response_model=schemas.AdminAction)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_email: str = Depends(auth.require_admin)
):
    """Legacy: Redirects to the queue system."""
    admin_user = db.query(models.User).filter(models.User.email == admin_email).first()
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Cannot delete admins")
    
    if admin_user.role == "superadmin":
        target_email = user.email
        db.delete(user)
        create_audit_log(db, "USER_DELETED", admin_email, target_email)
        db.commit()
        return {"message": f"User {target_email} has been permanently deleted", "user_id": user_id}
    
    queue_entry = models.AdminActionQueue(
        action_type="delete", requested_by=admin_email,
        target_user_id=user_id, target_user_email=user.email, status="pending"
    )
    db.add(queue_entry)
    create_audit_log(db, "ADMIN_ACTION_REQUESTED", admin_email, f"delete {user.email}")
    db.commit()
    return {"message": f"Delete request queued for superadmin approval", "user_id": user_id}

# ==================== COMPANY ====================

@app.post("/companies", response_model=schemas.CompanyResponse)
def create_company(
    company: schemas.CompanyCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
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
    
    create_audit_log(db, "COMPANY_CREATED", user.email, f"Company: {company.name}")
    
    db.commit()
    db.refresh(new_company)
    return new_company

@app.get("/companies", response_model=list[schemas.CompanyResponse])
def list_companies(db: Session = Depends(get_db)):
    return db.query(models.Company).all()

# ==================== JOB ====================

@app.post("/jobs", response_model=schemas.JobResponse)
def post_job(
    job: schemas.JobCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """RECRUITER ONLY: Post a new job with company ownership verification."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Only recruiters can post jobs")
    
    # SECURITY FIX: Verify recruiter owns the company
    company = db.query(models.Company).filter(
        models.Company.id == job.company_id,
        models.Company.recruiter_id == user.id
    ).first()
    if not company:
        raise HTTPException(status_code=403, detail="You can only post jobs for your own companies")
    
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
    
    create_audit_log(db, "JOB_POSTED", user.email, f"Job: {job.title} for Company ID: {job.company_id}")
    
    db.commit()
    db.refresh(new_job)
    return new_job

@app.get("/jobs", response_model=list[schemas.JobResponse])
def list_jobs(db: Session = Depends(get_db)):
    return db.query(models.Job).filter(models.Job.is_active == True).all()

@app.get("/my-jobs", response_model=list[schemas.JobResponse])
def list_my_jobs(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    return db.query(models.Job).filter(models.Job.recruiter_id == user.id).all()

# ==================== APPLICATION ====================

@app.post("/applications", response_model=schemas.ApplicationResponse)
def apply_to_job(
    app_data: schemas.ApplicationCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """JOB SEEKER ONLY: Apply with automated match score calculation."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if user.role != "job_seeker":
        raise HTTPException(status_code=403, detail="Only job seekers can apply")
    
    existing_app = db.query(models.Application).filter(
        models.Application.job_id == app_data.job_id,
        models.Application.applicant_id == user.id
    ).first()
    
    if existing_app:
        raise HTTPException(status_code=400, detail="You have already applied for this job")

    job = db.query(models.Job).filter(models.Job.id == app_data.job_id).first()
    resume = db.query(models.Resume).filter(
        models.Resume.id == app_data.resume_id, 
        models.Resume.user_id == user.id
    ).first()
    
    if not job or not resume:
        raise HTTPException(status_code=404, detail="Job or Resume not found")

    calculated_score = 0
    if resume.extracted_skills:
        calculated_score = parser.calculate_match_score(resume.extracted_skills, job.skills_required)

    new_app = models.Application(
        job_id=app_data.job_id,
        applicant_id=user.id,
        resume_id=app_data.resume_id,
        cover_letter=app_data.cover_letter,
        match_score=calculated_score 
    )
    
    create_audit_log(db, "JOB_APPLICATION_SUBMITTED", user.email, f"Job ID: {job.id}")
    
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return new_app

@app.get("/applications/my", response_model=list[dict])
def list_my_applications(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
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
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Access denied")
    
    results = db.query(
        models.Application, 
        models.User.full_name.label("applicant_name"),
        models.Job.title.label("job_title")
    ).join(models.Job, models.Job.id == models.Application.job_id)\
     .join(models.User, models.User.id == models.Application.applicant_id)\
     .filter(models.Job.recruiter_id == user.id).all()
    
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
            "job_title": title,
            "match_score": app_obj.match_score 
        })
    return output

# ==================== MESSAGING (E2EE) ====================

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
def get_user_public_key(
    user_id: int,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)  # SECURITY FIX: Added auth
):
    """Fetch a recipient's public key for encryption (requires authentication)."""
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
    """Store an E2EE encrypted message with validation."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    # SECURITY FIX: Validate receiver exists
    receiver = db.query(models.User).filter(models.User.id == msg.receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # SECURITY FIX: Prevent messaging yourself
    if receiver.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot message yourself")
    
    # SECURITY FIX: Verify connection exists between sender and receiver
    conn = db.query(models.Connection).filter(
        models.Connection.status == "accepted",
        (
            ((models.Connection.user_id == user.id) & (models.Connection.connection_id == receiver.id)) |
            ((models.Connection.user_id == receiver.id) & (models.Connection.connection_id == user.id))
        )
    ).first()
    
    # Also allow if there's an application relationship (recruiter-candidate)
    app_link = db.query(models.Application).join(
        models.Job, models.Job.id == models.Application.job_id
    ).filter(
        ((models.Application.applicant_id == user.id) & (models.Job.recruiter_id == receiver.id)) |
        ((models.Application.applicant_id == receiver.id) & (models.Job.recruiter_id == user.id))
    ).first()
    
    if not conn and not app_link:
        raise HTTPException(status_code=403, detail="You can only message connections or linked recruiters/candidates")
    
    new_msg = models.Message(
        sender_id=user.id,
        receiver_id=msg.receiver_id,
        encrypted_content=msg.encrypted_content,
        signature=msg.signature 
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

# ==================== APPLICATION STATUS ====================

@app.put("/applications/{application_id}/status")
def update_application_status(
    application_id: int,
    status_data: schemas.ApplicationStatusUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """RECRUITER ONLY: Update the status of an application."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    if user.role != "recruiter":
        raise HTTPException(status_code=403, detail="Only recruiters can update application status")
    
    application = db.query(models.Application).filter(models.Application.id == application_id).first()
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
        
    job = db.query(models.Job).filter(models.Job.id == application.job_id).first()
    if job.recruiter_id != user.id:
        raise HTTPException(status_code=403, detail="Unauthorized: This is not your job posting")
        
    old_status = application.status
    application.status = status_data.status
    
    create_audit_log(db, "APP_STATUS_CHANGE", user.email, f"App ID {application_id}: {old_status} -> {status_data.status}")
    
    db.commit()
    return {"message": "Status updated successfully", "new_status": application.status}

# ==================== INTELLIGENT MATCHING ====================

@app.get("/jobs/recommendations")
def get_job_recommendations(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    resume = db.query(models.Resume).filter(
        models.Resume.user_id == user.id
    ).order_by(models.Resume.uploaded_at.desc()).first()
    
    if not resume or not resume.extracted_skills:
        return []

    all_jobs = db.query(models.Job).filter(models.Job.is_active == True).all()
    
    recommendations = []
    for job in all_jobs:
        company = db.query(models.Company).filter(models.Company.id == job.company_id).first()
        company_name = company.name if company else "Unknown Company"
        
        score = parser.calculate_match_score(resume.extracted_skills, job.skills_required)
        
        if score > 0:
            recommendations.append({
                "job_id": job.id,
                "title": job.title,
                "company": company_name,
                "location": job.location,
                "type": job.employment_type,
                "match_score": score
            })
    
    recommendations.sort(key=lambda x: x['match_score'], reverse=True)
    return recommendations[:3]

# ==================== USER DIRECTORY ====================

@app.get("/users/directory")
def get_user_directory(
    q: Optional[str] = None,
    page: int = 1,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    limit = 15
    offset = (page - 1) * limit
    current_user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    query = db.query(models.User).filter(
        models.User.id != current_user.id,
        models.User.role != "admin"
    )
    
    if q:
        # SECURITY FIX: Escape LIKE special characters
        safe_q = escape_like(q)
        query = query.filter(
            (models.User.full_name.ilike(f"%{safe_q}%")) | 
            (models.User.headline.ilike(f"%{safe_q}%"))
        )
    
    users = query.offset(offset).limit(limit).all()
    
    output = []
    for u in users:
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

# ==================== PROFILE VIEW ====================

@app.get("/users/{user_id}/profile", response_model=schemas.UserProfilePublic)
def get_other_user_profile(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user_email: str = Depends(auth.get_current_user)
):
    me = db.query(models.User).filter(models.User.email == current_user_email).first()
    target = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
        
    conn = db.query(models.Connection).filter(
        ((models.Connection.user_id == me.id) & (models.Connection.connection_id == target.id) & (models.Connection.status == "accepted")) |
        ((models.Connection.user_id == target.id) & (models.Connection.connection_id == me.id) & (models.Connection.status == "accepted"))
    ).first()
    
    is_connected = True if conn else False
    
    def filter_field(value, privacy_level):
        if privacy_level == "public":
            return value
        if privacy_level == "connections" and is_connected:
            return value
        return "RESTRICTED_BY_PRIVACY" if value else None

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

    my_conns = db.query(models.Connection).filter(
        (models.Connection.status == "accepted") & 
        ((models.Connection.user_id == me.id) | (models.Connection.connection_id == me.id))
    ).all()
    my_conn_ids = {c.user_id if c.connection_id == me.id else c.connection_id for c in my_conns}

    target_conns = db.query(models.Connection).filter(
        (models.Connection.status == "accepted") & 
        ((models.Connection.user_id == target.id) | (models.Connection.connection_id == target.id))
    ).all()
    target_conn_ids = {c.user_id if c.connection_id == target.id else c.connection_id for c in target_conns}

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
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
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
            "viewer_name": viewer_name if can_share else "Anonymous Professional"
        })
    return output

# ==================== CONNECTIONS ====================

@app.post("/connections/request", response_model=schemas.ConnectionResponse)
def send_connection_request(
    data: schemas.ConnectionRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    if user.id == data.receiver_id:
        raise HTTPException(status_code=400, detail="Cannot connect to yourself")
    
    # Verify receiver exists
    receiver = db.query(models.User).filter(models.User.id == data.receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")

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
    
    create_audit_log(db, "CONN_REQUEST_SENT", user.email, f"Target ID: {data.receiver_id}")
    
    db.commit()
    db.refresh(new_request)
    return new_request

@app.get("/connections/pending", response_model=List[dict])
def get_pending_requests(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    requests = db.query(
        models.Connection.id.label("request_id"),
        models.User.full_name.label("name"),
        models.User.email.label("email")
    ).join(models.User, models.User.id == models.Connection.user_id)\
     .filter((models.Connection.connection_id == user.id) & (models.Connection.status == "pending")).all()
    
    return [dict(r._mapping) for r in requests]

@app.put("/connections/accept")
def update_connection_status(
    data: schemas.ConnectionUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
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

# ==================== ACCOUNT DELETION ====================

@app.post("/users/me/delete")
def secure_delete_account(
    req: schemas.DeleteAccountRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(auth.get_current_user)
):
    """
    HIGH RISK: Deletes the user account.
    Requires OTP verification via Virtual Keyboard.
    """
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    
    db_otp = db.query(models.OTP).filter(
        models.OTP.user_id == user.id,
        models.OTP.is_used == False
    ).order_by(models.OTP.created_at.desc()).first()
    
    if not db_otp or otp.is_otp_expired(db_otp.created_at):
        raise HTTPException(status_code=400, detail="OTP invalid or expired. Request a new one.")
        
    if str(db_otp.code).strip() != str(req.otp_code).strip():
        raise HTTPException(status_code=400, detail="Incorrect OTP code.")

    db_otp.is_used = True
    
    create_audit_log(db, "ACCOUNT_SELF_DELETED", user.email, "Account permanently removed")
    
    db.delete(user)
    db.commit()
    
    return {"message": "Account successfully deleted."}

# ==================== PASSWORD RESET ====================

@app.post("/password-reset/request")
@limiter.limit("5/15minutes")
async def request_password_reset(
    request: Request,
    req: schemas.PasswordResetRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Sends an OTP for password reset."""
    user = db.query(models.User).filter(models.User.email == req.email).first()
    if not user:
        # Security: Return generic message to prevent email enumeration
        return {"message": "If the email exists, an OTP has been sent."}
    
    # Invalidate old OTPs
    db.query(models.OTP).filter(
        models.OTP.user_id == user.id, 
        models.OTP.is_used == False
    ).update({"is_used": True})
    
    otp_code = otp.generate_otp()
    new_otp = models.OTP(user_id=user.id, code=otp_code, created_at=datetime.now(timezone.utc))
    db.add(new_otp)
    db.commit()

    message = MessageSchema(
        subject="FortKnox - Password Reset Code",
        recipients=[user.email],
        body=f"Your password reset code is: {otp_code}\n\nDo not share this code with anyone. It expires in 2 minutes.",
        subtype=MessageType.plain
    )
    background_tasks.add_task(fastmail.send_message, message)
    
    create_audit_log(db, "PASSWORD_RESET_REQUESTED", user.email, "User initiated password reset")
    db.commit()
    
    return {"message": "If the email exists, an OTP has been sent."}


@app.post("/password-reset/confirm")
@limiter.limit("10/minute")
def confirm_password_reset(request: Request, req: schemas.PasswordResetConfirm, db: Session = Depends(get_db)):
    """Verifies OTP and updates the password (with brute-force protection)."""
    user = db.query(models.User).filter(models.User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid request")
        
    # SECURITY FIX: Check lockout (same as registration OTP)
    if user.locked_until and otp.is_account_locked(user.locked_until):
        raise HTTPException(
            status_code=403,
            detail="Account locked due to too many failed attempts. Try again later."
        )
    
    db_otp = db.query(models.OTP).filter(
        models.OTP.user_id == user.id,
        models.OTP.is_used == False
    ).order_by(models.OTP.created_at.desc()).first()
    
    if not db_otp or otp.is_otp_expired(db_otp.created_at):
        raise HTTPException(status_code=400, detail="OTP invalid or expired.")
        
    if str(db_otp.code).strip() != str(req.otp_code).strip():
        # SECURITY FIX: Brute-force protection on password reset OTP
        user.failed_otp_attempts += 1
        
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
            detail=f"Incorrect OTP. {otp.MAX_FAILED_ATTEMPTS - user.failed_otp_attempts} attempts remaining."
        )

    # Password strength is now validated at schema level (PasswordResetConfirm)
    user.hashed_password = security.hash_password(req.new_password)
    
    db_otp.is_used = True
    user.failed_otp_attempts = 0
    user.locked_until = None
    
    create_audit_log(db, "PASSWORD_CHANGED", user.email, "Password reset via OTP")
    
    db.commit()
    return {"message": "Password has been successfully reset."}