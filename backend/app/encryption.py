from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
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