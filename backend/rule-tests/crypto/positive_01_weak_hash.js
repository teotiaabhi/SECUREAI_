// =============================================================================
// Test:     positive_01_weak_hash
// Expected: TRIGGER rule CRYPTO-JS-001 (Weak hashing algorithm detected)
// Category: Crypto
// Language: JavaScript (Node.js)
// =============================================================================
// Description: Uses crypto.createHash('md5') for file integrity verification
// and password checking. MD5 is cryptographically broken and should not be used
// for any security-sensitive purpose.
// =============================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Compute MD5 hash of a file for integrity verification.
 * VULNERABLE: MD5 is collision-prone and should not be used for integrity checks.
 */
function computeFileChecksum(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hash = crypto.createHash('md5'); // VULNERABLE: weak hash algorithm
  hash.update(fileBuffer);
  return hash.digest('hex');
}

/**
 * Verify a file against a known MD5 checksum.
 */
function verifyFileIntegrity(filePath, expectedChecksum) {
  const actualChecksum = computeFileChecksum(filePath);
  console.log(`File: ${filePath}`);
  console.log(`Expected MD5: ${expectedChecksum}`);
  console.log(`Actual MD5:   ${actualChecksum}`);
  return actualChecksum === expectedChecksum;
}

/**
 * Hash a user password using MD5.
 * VULNERABLE: MD5 must never be used for password hashing.
 */
function hashPassword(password) {
  const hash = crypto.createHash('md5'); // VULNERABLE: weak hash for password
  hash.update(password);
  return hash.digest('hex');
}

/**
 * Verify user credentials against stored MD5 hash.
 */
function verifyPassword(inputPassword, storedHash) {
  const inputHash = hashPassword(inputPassword);
  return inputHash === storedHash;
}

// --- Demo usage ---
const targetFile = path.join(__dirname, 'sample.dat');
const knownChecksum = 'd41d8cd98f00b204e9800998ecf8427e';

if (fs.existsSync(targetFile)) {
  const valid = verifyFileIntegrity(targetFile, knownChecksum);
  console.log(`Integrity check passed: ${valid}`);
}

const storedPasswordHash = hashPassword('admin123');
console.log(`Stored hash: ${storedPasswordHash}`);
console.log(`Login valid: ${verifyPassword('admin123', storedPasswordHash)}`);
