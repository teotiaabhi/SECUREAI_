// =============================================================================
// Test:     negative_04_crypto_random
// Expected: Must NOT trigger any crypto rules
// Category: Crypto
// Language: JavaScript (Node.js)
// =============================================================================
// Description: Uses crypto.randomBytes() and crypto.randomUUID() for
// generating tokens, session IDs, and API keys. These are cryptographically
// secure random number generators suitable for security-sensitive operations.
// =============================================================================

const crypto = require('crypto');

/**
 * Generate a cryptographically secure session ID.
 * SAFE: crypto.randomBytes() uses OS-level CSPRNG.
 */
function generateSessionId() {
  return crypto.randomBytes(24).toString('hex'); // SAFE: 192-bit entropy
}

/**
 * Generate a password-reset token using crypto.randomBytes().
 * SAFE: unpredictable, high-entropy output.
 */
function generateResetToken(userId) {
  const token = crypto.randomBytes(32).toString('base64url'); // SAFE
  const expiry = Date.now() + 3600000; // 1 hour
  return { userId, token, expiry };
}

/**
 * Generate an API key with a prefix for identification.
 * SAFE: uses crypto.randomBytes for the random portion.
 */
function generateApiKey(prefix = 'sk') {
  const randomPart = crypto.randomBytes(24).toString('base64url'); // SAFE
  return `${prefix}_${randomPart}`;
}

/**
 * Generate a CSRF token.
 * SAFE: uses crypto.randomBytes for unpredictability.
 */
function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex'); // SAFE
}

/**
 * Generate a UUID v4 for resource identifiers.
 * SAFE: crypto.randomUUID() is cryptographically secure.
 */
function generateResourceId() {
  return crypto.randomUUID(); // SAFE: built-in CSPRNG-backed UUID
}

// --- Demo usage ---
console.log('Session ID:  ', generateSessionId());
console.log('Reset token: ', generateResetToken('user_4821'));
console.log('API key:     ', generateApiKey('sk_live'));
console.log('CSRF token:  ', generateCsrfToken());
console.log('Resource ID: ', generateResourceId());
