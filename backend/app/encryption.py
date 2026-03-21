from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

def generate_key() -> bytes:
    """
    Generates a secure 256-bit encryption key.
    This key is unique per resume.
    """
    return AESGCM.generate_key(bit_length=256)

def encrypt_file(file_content: bytes, key: bytes) -> tuple:
    """
    Encrypts file content using AES-256-GCM.
    Returns: (encrypted_data, nonce)
    
    Security Notes:
    - AES-GCM provides both encryption AND integrity checking
    - Nonce (number used once) ensures same content encrypts differently each time
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    encrypted_data = aesgcm.encrypt(nonce, file_content, None)
    
    return encrypted_data, nonce

def decrypt_file(encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypts file content.
    Raises exception if data was tampered with (integrity check fails).
    """
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    
    return decrypted_data

def key_to_string(key: bytes) -> str:
    """
    Converts encryption key to base64 string for database storage.
    """
    return base64.b64encode(key).decode('utf-8')

def string_to_key(key_string: str) -> bytes:
    """
    Converts base64 string back to encryption key.
    """
    return base64.b64decode(key_string.encode('utf-8'))

# --- ENVELOPE ENCRYPTION ---
# The per-file key is encrypted with a master key before storage

def _get_master_key() -> bytes:
    """Load the master key from environment variable."""
    master_b64 = os.environ.get("RESUME_MASTER_KEY")
    if not master_b64:
        raise RuntimeError("RESUME_MASTER_KEY environment variable is not set")
    key = base64.b64decode(master_b64)
    if len(key) < 16:
        raise RuntimeError("RESUME_MASTER_KEY must be at least 16 bytes (128 bits)")
    # Ensure exactly 32 bytes for AES-256
    if len(key) < 32:
        # Pad with key derivation if needed (but prefer a proper 32-byte key)
        import hashlib
        key = hashlib.sha256(key).digest()
    return key[:32]

def envelope_encrypt_key(per_file_key: bytes) -> str:
    """
    Encrypts the per-file AES key using the master key (envelope encryption).
    Returns a base64 string containing nonce + encrypted key.
    """
    master_key = _get_master_key()
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    encrypted_key = aesgcm.encrypt(nonce, per_file_key, None)
    # Store as: nonce (12 bytes) + encrypted_key
    combined = nonce + encrypted_key
    return base64.b64encode(combined).decode('utf-8')

def envelope_decrypt_key(encrypted_key_b64: str) -> bytes:
    """
    Decrypts the per-file AES key using the master key.
    """
    master_key = _get_master_key()
    combined = base64.b64decode(encrypted_key_b64)
    nonce = combined[:12]
    encrypted_key = combined[12:]
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, encrypted_key, None)