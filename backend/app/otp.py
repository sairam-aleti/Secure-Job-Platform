import pyotp
import secrets
from datetime import datetime, timedelta

# OTP Configuration (Your Parameters)
OTP_EXPIRY_MINUTES = 2
LOCKOUT_DURATION_MINUTES = 20
MAX_FAILED_ATTEMPTS = 5

def generate_otp() -> str:
    """
    Generates a secure 6-digit OTP using TOTP.
    Returns a string like "123456"
    """
    # Use secrets for cryptographically secure random generation
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=120)  # 2-minute window
    return totp.now()

def is_otp_expired(created_at: datetime) -> bool:
    """
    Checks if OTP is older than 2 minutes.
    """
    expiry_time = created_at + timedelta(minutes=OTP_EXPIRY_MINUTES)
    return datetime.utcnow() > expiry_time

def is_account_locked(locked_until: datetime) -> bool:
    """
    Checks if account is still locked.
    """
    if locked_until is None:
        return False
    return datetime.utcnow() < locked_until

def calculate_lockout_time() -> datetime:
    """
    Returns the timestamp when the account should be unlocked.
    """
    return datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)