// Test: negative for rule AUTH-JS-002
// Expected: should_not_trigger
// Category: auth
// Language: javascript
//
// Description: JWT token generation using RS256 with a proper RSA
// private key, short expiration, issuer, and audience claims.
// Verification enforces an algorithms whitelist. This file must NOT
// trigger AUTH-JS-002.

const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const router = express.Router();
const db = require('../models/db');

const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '../keys/rsa_private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '../keys/rsa_public.pem'), 'utf8');

const JWT_OPTIONS = {
  algorithm: 'RS256',
  expiresIn: '15m',
  issuer: 'security-app',
  audience: 'security-app-client',
};

// POST /api/login - authenticate user and return a secure JWT
router.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.query('SELECT * FROM users WHERE email = ?', [email]);

  if (!user.length) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const passwordValid = await bcrypt.compare(password, user[0].password_hash);
  if (!passwordValid) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign(
    { userId: user[0].id, role: user[0].role },
    PRIVATE_KEY,
    JWT_OPTIONS
  );

  res.json({ success: true, token, expiresIn: 900 });
});

// GET /api/profile - verify token with strict algorithm enforcement
router.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'security-app',
      audience: 'security-app-client',
    });

    res.json({ success: true, userId: decoded.userId, role: decoded.role });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
});

module.exports = router;
