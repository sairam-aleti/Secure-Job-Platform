from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
import os
import uuid
import hashlib

# SECURITY: Load secret from environment variable
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "CHANGE_ME_BEFORE_DEPLOYMENT")
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "30"))

security_scheme = HTTPBearer()

def generate_session_id() -> str:
    """Generate a unique session ID (JTI) for single-session enforcement."""
    return str(uuid.uuid4())

def compute_fingerprint(request: Request) -> str:
    """
    Compute a browser fingerprint hash from request headers.
    Used to bind sessions to specific clients.
    """
    user_agent = request.headers.get("user-agent", "")
    accept_lang = request.headers.get("accept-language", "")
    # Combine identifiers and hash
    raw = f"{user_agent}|{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT token with unique session ID (JTI)."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Include JTI for single-session enforcement
    if "jti" not in to_encode:
        to_encode["jti"] = generate_session_id()
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, to_encode["jti"]

def verify_token(token: str):
    """Decodes and verifies a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    """
    Extracts and validates the current user from JWT token.
    Enforces single-session (JTI check) and fingerprint binding.
    """
    token = credentials.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
    
    email: str = payload.get("sub")
    jti: str = payload.get("jti")
    if email is None:
        raise credentials_exception
    
    # Cross-check with database
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended")
    
    # SINGLE SESSION ENFORCEMENT: Check JTI matches stored session
    if jti and user.session_id and jti != user.session_id:
        raise HTTPException(
            status_code=401,
            detail="Session expired. You have been logged in from another device."
        )
    
    # FINGERPRINT VALIDATION (soft check — logs mismatch but doesn't block)
    current_fp = compute_fingerprint(request)
    if user.session_fingerprint and current_fp != user.session_fingerprint:
        # Log suspicious activity but don't block (fingerprint can change with browser updates)
        import logging
        logging.getLogger(__name__).warning(
            f"Fingerprint mismatch for {email}: stored={user.session_fingerprint[:8]}... current={current_fp[:8]}..."
        )
    
    return email

def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    """
    Dependency that ensures the current user is an admin or superadmin.
    Cross-checks role against the database.
    """
    token = credentials.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
    
    email: str = payload.get("sub")
    jti: str = payload.get("jti")
    if email is None:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended")
    
    # Single session check
    if jti and user.session_id and jti != user.session_id:
        raise HTTPException(status_code=401, detail="Session expired.")
    
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required"
        )
    
    return email

def require_superadmin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    """
    Dependency that ensures the current user is a SUPERADMIN.
    Only superadmins can approve/reject admin actions.
    """
    token = credentials.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
    
    email: str = payload.get("sub")
    jti: str = payload.get("jti")
    if email is None:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended")
    
    if jti and user.session_id and jti != user.session_id:
        raise HTTPException(status_code=401, detail="Session expired.")
    
    if user.role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Superadmin privileges required"
        )
    
    return email