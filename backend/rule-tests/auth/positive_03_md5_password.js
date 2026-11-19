// Test: positive for rule AUTH-JS-003
// Expected: should_trigger
// Category: auth
// Language: javascript
//
// Description: User registration endpoint that hashes passwords with
// MD5 via crypto.createHash('md5'). MD5 is cryptographically broken
// and unsuitable for password storage.

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const db = require('../models/db');

// Helper: produce an MD5 hex digest of a plaintext password
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// POST /api/register - create a new user account
router.post('/api/register', async (req, res) => {
  const { email, username, password, confirmPassword } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const existingUser = await db.query(
    'SELECT id FROM users WHERE email = ? OR username = ?',
    [email, username]
  );
  if (existingUser.length > 0) {
    return res.status(409).json({ error: 'Email or username already in use' });
  }

  // Vulnerable: MD5 hash for password storage
  const hashedPassword = hashPassword(password);

  const result = await db.query(
    'INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, NOW())',
    [email, username, hashedPassword]
  );

  res.status(201).json({
    success: true,
    message: 'Account created',
    userId: result.insertId,
  });
});

// POST /api/login - authenticate and compare MD5 hash
router.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.query('SELECT * FROM users WHERE email = ?', [email]);

  if (!user.length || user[0].password_hash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  res.json({ success: true, userId: user[0].id });
});

module.exports = router;
