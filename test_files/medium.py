"""
SecureScan severity test: MEDIUM candidate
Demonstrates a weak hash choice for password storage.
"""
import hashlib

def store_password_hash(password: str) -> str:
    # Unsafe: SHA-256 alone is not suitable for password storage.
    return hashlib.sha256(password.encode("utf-8")).hexdigest()
