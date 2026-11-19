// =============================================================================
// Test:     negative_01_sha256
// Expected: Must NOT trigger any crypto rules
// Category: Crypto
// Language: JavaScript (Node.js)
// =============================================================================
// Description: Uses crypto.createHash('sha256') for non-password file checksum
// verification. SHA-256 is a strong hash algorithm suitable for integrity
// checks (though not for password hashing, which is not done here).
// =============================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Compute SHA-256 checksum of a file.
 * SAFE: SHA-256 is a strong hash used for file integrity (not passwords).
 */
function computeSHA256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256'); // SAFE: strong algorithm
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

/**
 * Verify file integrity against a known SHA-256 digest.
 */
async function verifyChecksum(filePath, expectedDigest) {
  const actualDigest = await computeSHA256(filePath);
  const match = actualDigest === expectedDigest.toLowerCase();
  console.log(`File:     ${path.basename(filePath)}`);
  console.log(`Expected: ${expectedDigest}`);
  console.log(`Actual:   ${actualDigest}`);
  console.log(`Match:    ${match}`);
  return match;
}

/**
 * Generate a checksum manifest for all files in a directory.
 */
async function generateManifest(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const manifest = {};
  for (const entry of entries) {
    if (entry.isFile()) {
      const fullPath = path.join(directory, entry.name);
      manifest[entry.name] = await computeSHA256(fullPath);
    }
  }
  return manifest;
}

// --- Demo usage ---
(async () => {
  const targetDir = path.resolve(__dirname, '../assets');
  if (fs.existsSync(targetDir)) {
    const manifest = await generateManifest(targetDir);
    console.log('SHA-256 Manifest:', JSON.stringify(manifest, null, 2));
  }
})();
