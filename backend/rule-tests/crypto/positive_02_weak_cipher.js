// =============================================================================
// Test:     positive_02_weak_cipher
// Expected: TRIGGER rule CRYPTO-JS-002 (Weak cipher algorithm detected)
// Category: Crypto
// Language: JavaScript (Node.js)
// =============================================================================
// Description: Uses crypto.createCipheriv with DES-ECB and RC4 for data
// encryption. Both are considered insecure: DES has a 56-bit key and ECB mode
// leaks patterns; RC4 has known statistical biases.
// =============================================================================

const crypto = require('crypto');

/**
 * Encrypt data using DES in ECB mode.
 * VULNERABLE: DES has a 56-bit key (brute-forceable) and ECB leaks patterns.
 */
function encryptWithDES(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex'); // 8-byte key for DES
  const cipher = crypto.createCipheriv('des-ecb', key, null); // VULNERABLE
  cipher.setAutoPadding(true);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptWithDES(ciphertext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const decipher = crypto.createDecipheriv('des-ecb', key, null); // VULNERABLE
  decipher.setAutoPadding(true);
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Encrypt data using RC4 stream cipher.
 * VULNERABLE: RC4 has known biases in its keystream output.
 */
function encryptWithRC4(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const cipher = crypto.createCipheriv('rc4', key, ''); // VULNERABLE
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// --- Demo usage ---
const desKey = '0123456789abcdef'; // 8 bytes in hex
const rc4Key = 'deadbeefcafebabe1234567890abcdef'; // 16 bytes in hex

const sensitiveData = 'SSN: 123-45-6789';

const desEncrypted = encryptWithDES(sensitiveData, desKey);
console.log(`DES-ECB encrypted: ${desEncrypted}`);
console.log(`DES-ECB decrypted: ${decryptWithDES(desEncrypted, desKey)}`);

const rc4Encrypted = encryptWithRC4(sensitiveData, rc4Key);
console.log(`RC4 encrypted: ${rc4Encrypted}`);
