# ==============================================================================
# Test:     negative_03_env_key
# Expected: Must NOT trigger any crypto rules
# Category: Crypto
# Language: Python
# ==============================================================================
# Description: Loads the encryption key from an environment variable instead
# of hardcoding it. This is the recommended practice - keys should come from
# environment variables, secrets managers, or key management services.
# ==============================================================================

import os
import sys
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# SAFE: Key loaded from environment variable, not hardcoded
FERNET_KEY = os.environ.get('APP_FERNET_KEY')
AES_KEY_HEX = os.environ.get('APP_AES_KEY')


def get_fernet_instance():
    """Create a Fernet cipher using an environment-sourced key."""
    if not FERNET_KEY:
        print('ERROR: APP_FERNET_KEY environment variable is not set', file=sys.stderr)
        sys.exit(1)
    return Fernet(FERNET_KEY.encode('utf-8'))  # SAFE: key from env var


def encrypt_record(record: dict) -> str:
    """Encrypt a data record with Fernet using env-sourced key."""
    fernet = get_fernet_instance()
    payload = json.dumps(record).encode('utf-8')
    return fernet.encrypt(payload).decode('utf-8')


def decrypt_record(token: str) -> dict:
    """Decrypt a Fernet token back to a data record."""
    fernet = get_fernet_instance()
    try:
        decrypted = fernet.decrypt(token.encode('utf-8'))
        return json.loads(decrypted.decode('utf-8'))
    except InvalidToken:
        raise ValueError('Decryption failed: invalid key or corrupted token')


def encrypt_field_aes(plaintext: str) -> bytes:
    """Encrypt a field using AES-256-CBC with env-sourced key and random IV."""
    if not AES_KEY_HEX:
        raise RuntimeError('APP_AES_KEY environment variable is not set')
    key = bytes.fromhex(AES_KEY_HEX)                      # SAFE: from env
    iv = os.urandom(16)                                     # SAFE: random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = plaintext.ljust(32).encode('utf-8')
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext  # prepend IV for decryption


# --- Demo usage ---
if __name__ == '__main__':
    record = {'user_id': 42, 'email': 'bob@example.com', 'role': 'admin'}
    token = encrypt_record(record)
    print(f'Encrypted: {token[:60]}...')
    recovered = decrypt_record(token)
    print(f'Decrypted: {recovered}')
