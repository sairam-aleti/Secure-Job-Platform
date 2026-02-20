from passlib.context import CryptContext

# SECURITY CONFIGURATION: Use Argon2id (the strongest hashing algorithm)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    """
    Converts a plaintext password into a secure hash.
    This is a one-way function. You cannot reverse it.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Checks if the user's login password matches the stored hash.
    Returns True if correct, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)