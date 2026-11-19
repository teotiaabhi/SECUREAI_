// Test: negative for rule AUTH-JS-003
// Expected: should_not_trigger
// Category: auth
// Language: javascript
//
// Description: User registration and login endpoints that use bcrypt
// with a cost factor of 12 for password hashing and verification.
// This file must NOT trigger AUTH-JS-003.

const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const db = require('../models/db');

const SALT_ROUNDS = 12;

// POST /api/register - create a new user with bcrypt-hashed password
router.post('/api/register', async (req, res) => {
  const { email, username, password, confirmPassword } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  if (password.length < 10) {
    return res.status(400).json({ error: 'Password must be at least 10 characters' });
  }

  const existing = await db.query(
    'SELECT id FROM users WHERE email = ? OR username = ?',
    [email, username]
  );
  if (existing.length > 0) {
    return res.status(409).json({ error: 'Email or username already in use' });
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

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

// POST /api/login - verify credentials using bcrypt.compare
router.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const users = await db.query('SELECT * FROM users WHERE email = ?', [email]);
  if (!users.length) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const isMatch = await bcrypt.compare(password, users[0].password_hash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  res.json({ success: true, userId: users[0].id, username: users[0].username });
});

module.exports = router;
