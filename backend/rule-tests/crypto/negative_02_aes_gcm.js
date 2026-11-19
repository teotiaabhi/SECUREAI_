// =============================================================================
// Test:     negative_02_aes_gcm
// Expected: Must NOT trigger any crypto rules
// Category: Crypto
// Language: JavaScript (Node.js)
// =============================================================================
// Description: Uses crypto.createCipheriv('aes-256-gcm', ...) for data
// encryption. AES-256-GCM is an authenticated encryption mode providing both
// confidentiality and integrity. This is the recommended approach.
// =============================================================================

const crypto = require('crypto');

const AES_KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12;      // 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH = 16;

/**
 * Generate a cryptographically secure random key.
 * SAFE: key is generated securely, not hardcoded.
 */
function generateKey() {
  return crypto.randomBytes(AES_KEY_LENGTH);
}

/**
 * Encrypt plaintext using AES-256-GCM.
 * SAFE: strong algorithm, authenticated encryption, random IV per message.
 */
function encrypt(plaintext, key, aad = null) {
  const iv = crypto.randomBytes(IV_LENGTH); // SAFE: random IV per encryption
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); // SAFE

  if (aad) {
    cipher.setAAD(Buffer.from(aad, 'utf8'));
  }

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    ciphertext: encrypted,
    authTag: authTag.toString('hex'),
  };
}

/**
 * Decrypt AES-256-GCM ciphertext and verify authenticity.
 */
function decrypt(encryptedData, key, aad = null) {
  const { iv, ciphertext, authTag } = encryptedData;
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  if (aad) {
    decipher.setAAD(Buffer.from(aad, 'utf8'));
  }

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// --- Demo usage ---
const key = generateKey();
const secretMessage = 'Sensitive payment information: card=4111111111111111';
const aad = 'transaction-id:txn_abc123';

const encrypted = encrypt(secretMessage, key, aad);
console.log('Encrypted:', JSON.stringify(encrypted, null, 2));

const decrypted = decrypt(encrypted, key, aad);
console.log('Decrypted:', decrypted);
