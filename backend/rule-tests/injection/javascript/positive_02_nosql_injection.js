// Test: positive for rule JS-INJ-002
// Expected: should_trigger
// Category: injection
// Language: javascript

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Mongoose schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
  lastLogin: { type: Date },
  isActive: { type: Boolean, default: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Request logging middleware
router.use((req, res, next) => {
  logger.info(`[NoSQL Route] ${req.method} ${req.path} from ${req.ip}`);
  next();
});

// VULNERABLE: NoSQL injection via unsanitized req.body passed directly to find()
// An attacker can send { "username": { "$gt": "" }, "password": { "$gt": "" } }
// to bypass authentication entirely
router.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Dangerous: req.body fields are passed directly into the MongoDB query
    // allowing operator injection like $gt, $ne, $regex, etc.
    const user = await User.findOne({
      username: username,
      password: password,
      isActive: true,
    });

    if (!user) {
      logger.warn(`Failed login attempt for username input: ${JSON.stringify(username)}`);
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    logger.info(`User ${user._id} logged in successfully`);
    res.json({
      success: true,
      user: { id: user._id, username: user.username, role: user.role },
    });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).json({ success: false, message: 'Server error during authentication' });
  }
});

// VULNERABLE: NoSQL injection in search via unsanitized query parameters
router.get('/api/users', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    // Dangerous: entire req.query object spread into the find filter
    const filter = { ...req.query };
    delete filter.page;
    delete filter.limit;

    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 25;
    const skip = (page - 1) * limit;

    const users = await User.find(filter)
      .select('-password')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(filter);

    res.json({ success: true, data: users, pagination: { page, limit, total } });
  } catch (err) {
    logger.error(`User search error: ${err.message}`);
    res.status(500).json({ success: false, message: 'Failed to retrieve users' });
  }
});

module.exports = router;
