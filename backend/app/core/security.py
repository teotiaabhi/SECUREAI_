import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.core.config import get_settings


def _derive_key(secret: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"secureai-salt-v1",
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = _derive_key(get_settings().ENCRYPTION_KEY)
        _fernet = Fernet(key)
    return _fernet


def encrypt_token(token: str) -> str:
    return _get_fernet().encrypt(token.encode()).decode()


def decrypt_token(encrypted: str) -> str:
    return _get_fernet().decrypt(encrypted.encode()).decode()
