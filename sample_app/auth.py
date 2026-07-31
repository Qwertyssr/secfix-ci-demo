"""User authentication helpers.

NOTE: intentionally vulnerable for the security-fix demo.
Fortify flags the MD5 usage below as 'Weak Cryptographic Hash'.
"""
import hashlib


def hash_password(password: str, salt: str) -> str:
    # VULN (Fortify: Weak Cryptographic Hash) -> should become sha256
    digest = hashlib.md5((salt + password).encode("utf-8"))
    return digest.hexdigest()


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    return hash_password(password, salt) == stored_hash
