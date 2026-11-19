// Test: positive for rule AUTH-JS-002
// Expected: should_trigger
// Category: auth
// Language: javascript
//
// Description: JWT token generation using the 'none' algorithm and no
// expiration claim. The verify call does not enforce an algorithms
// whitelist, allowing algorithm-substitution attacks.

const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const db = require('../models/db');

const SECRET_KEY = 'supersecret';

// Issue a token with algorithm 'none' and no expiry
router.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.findUser(username);

  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Vulnerable: algorithm set to 'none', no expiresIn
  const token = jwt.sign(
    { userId: user.id, role: user.role, username: user.username },
    '',
    { algorithm: 'none' }
  );

  res.json({ success: true, token });
});

// Verify incoming token without restricting allowed algorithms
router.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    // Vulnerable: no algorithms whitelist in verify options
    const decoded = jwt.verify(token, '', { complete: true });
    const user = db.getUserById(decoded.payload.userId);
    res.json({ success: true, data: user });
  } catch (err) {
    res.status(403).json({ error: 'Token verification failed' });
  }
});

module.exports = router;
