"""
KMS (Key Management Service) abstraction layer.

Provides a unified interface for encryption/decryption with pluggable
backends:
- **local**: Wraps the existing Fernet-based encryption from ``core/security.py``
- **aws**: Stub for AWS KMS integration (raises NotImplementedError with setup guide)

Usage:
    from app.core.kms import create_kms_backend

    kms = create_kms_backend(settings)
    ciphertext = await kms.encrypt(b"secret data")
    plaintext  = await kms.decrypt(ciphertext)
"""

import base64
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.logging import get_logger

logger = get_logger("kms")


class KMSBackend(ABC):
    """Abstract KMS interface."""

    @abstractmethod
    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext bytes. Returns ciphertext bytes."""
        ...

    @abstractmethod
    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext bytes. Returns plaintext bytes."""
        ...

    @abstractmethod
    async def rotate_key(self) -> str:
        """Rotate the encryption key. Returns the new key version identifier."""
        ...


class LocalKMSBackend(KMSBackend):
    """Fernet-based local KMS.

    Wraps the same PBKDF2 key derivation used by ``app.core.security``
    so that data encrypted by either path is interoperable.
    """

    def __init__(self, encryption_key: str):
        self._key_material = encryption_key
        self._fernet = self._build_fernet(encryption_key)
        self._version = "local-v1"
        self._created_at = datetime.now(timezone.utc)

    @staticmethod
    def _build_fernet(secret: str) -> Fernet:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"secureai-salt-v1",
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
        return Fernet(key)

    async def encrypt(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    async def decrypt(self, ciphertext: bytes) -> bytes:
        return self._fernet.decrypt(ciphertext)

    async def rotate_key(self) -> str:
        """Local backend key rotation is a no-op placeholder.

        In production, implement key versioning with MultiFernet.
        """
        self._version = f"local-v{int(self._version.split('v')[1]) + 1}"
        logger.info("local_kms_key_rotated", version=self._version)
        return self._version


class AWSKMSBackend(KMSBackend):
    """AWS KMS integration stub.

    Raises ``NotImplementedError`` with setup instructions so that
    operators know exactly what is needed for production deployment.
    """

    def __init__(self, key_id: str):
        self._key_id = key_id
        if not key_id:
            raise ValueError(
                "KMS_AWS_KEY_ID is required when KMS_BACKEND=aws. "
                "Set it to your AWS KMS key ARN."
            )

    async def encrypt(self, plaintext: bytes) -> bytes:
        raise NotImplementedError(
            "AWS KMS integration requires the 'boto3' package and "
            "valid AWS credentials. Install boto3, configure "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION, "
            "and replace this stub with:\n"
            "  client = boto3.client('kms')\n"
            "  response = client.encrypt(KeyId=self._key_id, Plaintext=plaintext)\n"
            "  return response['CiphertextBlob']"
        )

    async def decrypt(self, ciphertext: bytes) -> bytes:
        raise NotImplementedError(
            "AWS KMS decrypt stub — see encrypt() for setup instructions."
        )

    async def rotate_key(self) -> str:
        raise NotImplementedError(
            "AWS KMS automatic key rotation is managed via the AWS console / CLI:\n"
            "  aws kms enable-key-rotation --key-id <your-key-id>"
        )


def create_kms_backend(settings) -> KMSBackend:
    """Factory — select KMS backend based on configuration."""
    backend_type = getattr(settings, "KMS_BACKEND", "local").lower()

    if backend_type == "aws":
        key_id = getattr(settings, "KMS_AWS_KEY_ID", "")
        logger.info("kms_backend_selected", backend="aws", key_id=key_id[:12] + "..." if key_id else "")
        return AWSKMSBackend(key_id=key_id)

    encryption_key = getattr(settings, "ENCRYPTION_KEY", "")
    logger.info("kms_backend_selected", backend="local")
    return LocalKMSBackend(encryption_key=encryption_key)
