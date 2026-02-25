import pyotp
from datetime import datetime, timedelta, timezone # NEW: Added timezone

# OTP Configuration
OTP_EXPIRY_MINUTES = 2
LOCKOUT_DURATION_MINUTES = 20
MAX_FAILED_ATTEMPTS = 5

def generate_otp() -> str:
    """Generates a secure 6-digit OTP using TOTP."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=120)
    return totp.now()

def is_otp_expired(created_at: datetime) -> bool:
    """Checks if OTP is older than 2 minutes using timezone-aware comparison."""
    # Ensure we are using the same 'Aware' timezone for comparison
    now = datetime.now(timezone.utc)
    
    # If the database datetime is naive, make it aware (for safety)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
        
    expiry_time = created_at + timedelta(minutes=OTP_EXPIRY_MINUTES)
    return now > expiry_time

def is_account_locked(locked_until: datetime) -> bool:
    """Checks if account is still locked."""
    if locked_until is None:
        return False
    
    now = datetime.now(timezone.utc)
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
        
    return now < locked_until

def calculate_lockout_time() -> datetime:
    """Returns the timestamp when the account should be unlocked."""
    return datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)