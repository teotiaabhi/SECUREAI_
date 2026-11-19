// =============================================================================
// Test:     positive_04_math_random
// Expected: TRIGGER rule CRYPTO-JS-003 (Insecure random number generator)
// Category: Crypto
// Language: JavaScript
// =============================================================================
// Description: Uses Math.random() to generate security-sensitive tokens and
// session identifiers. Math.random() is not cryptographically secure; its
// output is predictable and can be reconstructed from observed values.
// =============================================================================

/**
 * Generate a session ID using Math.random().
 * VULNERABLE: Math.random() is a PRNG seeded from a predictable source.
 */
function generateSessionId() {
  const part1 = Math.random().toString(36).substring(2, 10); // VULNERABLE
  const part2 = Math.random().toString(36).substring(2, 10); // VULNERABLE
  const part3 = Math.random().toString(36).substring(2, 10); // VULNERABLE
  return `${part1}-${part2}-${part3}`;
}

/**
 * Generate a password-reset token using Math.random().
 * VULNERABLE: Attacker can predict future tokens by observing past ones.
 */
function generateResetToken(userId) {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 15); // VULNERABLE
  return `${userId}_${timestamp}_${random}`;
}

/**
 * Generate an API key for a new service account.
 * VULNERABLE: API keys generated with Math.random() can be brute-forced.
 */
function generateApiKey(prefix = 'sk') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = `${prefix}_`;
  for (let i = 0; i < 32; i++) {
    const index = Math.floor(Math.random() * chars.length); // VULNERABLE
    key += chars[index];
  }
  return key;
}

/**
 * Generate a CSRF token for form protection.
 * VULNERABLE: Predictable CSRF tokens defeat the purpose of CSRF protection.
 */
function generateCsrfToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2); // VULNERABLE
}

// --- Demo usage ---
console.log('Session ID: ', generateSessionId());
console.log('Reset token:', generateResetToken('user_4821'));
console.log('API key:    ', generateApiKey('sk_live'));
console.log('CSRF token: ', generateCsrfToken());
