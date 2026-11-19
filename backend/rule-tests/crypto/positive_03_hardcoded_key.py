# ==============================================================================
# Test:     positive_03_hardcoded_key
# Expected: TRIGGER rule CRYPTO-PY-001 (Hardcoded encryption key detected)
# Category: Crypto
# Language: Python
# ==============================================================================
# Description: Uses a hardcoded AES encryption key as a string literal directly
# in source code. Hardcoded keys are extractable from compiled binaries and
# version control, making all encrypted data trivially recoverable.
# ==============================================================================

import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# VULNERABLE: Encryption key hardcoded as a string literal
FERNET_KEY = b'ZmRzYTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg='  # hardcoded key
AES_KEY = b'ThisIsAHardcoded32ByteSecretKey!'  # VULNERABLE: 32-byte AES key
AES_IV = b'0123456789abcdef'  # VULNERABLE: hardcoded initialization vector


def encrypt_user_data(user_record: dict) -> str:
    """Encrypt a user data record using Fernet with hardcoded key."""
    fernet = Fernet(FERNET_KEY)  # VULNERABLE: uses hardcoded key
    payload = json.dumps(user_record).encode('utf-8')
    encrypted = fernet.encrypt(payload)
    return encrypted.decode('utf-8')


def decrypt_user_data(token: str) -> dict:
    """Decrypt a user data record."""
    fernet = Fernet(FERNET_KEY)  # VULNERABLE: uses hardcoded key
    decrypted = fernet.decrypt(token.encode('utf-8'))
    return json.loads(decrypted.decode('utf-8'))


def encrypt_field_aes(plaintext: str) -> bytes:
    """Encrypt a single field using AES-CBC with hardcoded key and IV."""
    cipher = Cipher(
        algorithms.AES(AES_KEY),        # VULNERABLE: hardcoded key
        modes.CBC(AES_IV),              # VULNERABLE: hardcoded IV
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padded = plaintext.ljust(32).encode('utf-8')
    return encryptor.update(padded) + encryptor.finalize()


# --- Demo usage ---
if __name__ == '__main__':
    user = {
        'user_id': 1042,
        'email': 'alice@example.com',
        'ssn': '123-45-6789',
        'credit_card': '4111-1111-1111-1111',
    }

    token = encrypt_user_data(user)
    print(f'Encrypted token: {token[:60]}...')

    recovered = decrypt_user_data(token)
    print(f'Decrypted email: {recovered["email"]}')

    enc_ssn = encrypt_field_aes(user['ssn'])
    print(f'AES-CBC encrypted SSN: {base64.b64encode(enc_ssn).decode()}')
