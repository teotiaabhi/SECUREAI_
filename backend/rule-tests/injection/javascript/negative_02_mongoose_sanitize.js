// Test: negative for rule JS-INJ-002
// Expected: should_not_trigger
// Category: injection
// Language: javascript

const express = require('express');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const { body, query, validationResult } = require('express-validator');
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

// Apply mongo-sanitize middleware to strip $ and . from user input
router.use(mongoSanitize({ replaceWith: '_' }));

// Request logging middleware
router.use((req, res, next) => {
  logger.info(`[NoSQL Route] ${req.method} ${req.path} from ${req.ip}`);
  next();
});

// SAFE: Input validated and sanitized before reaching MongoDB query
router.post('/api/auth/login', [
  body('username').isString().trim().isLength({ min: 3, max: 30 }),
  body('password').isString().isLength({ min: 8 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    // Safe: input was sanitized by mongoSanitize and validated by express-validator.
    // Only plain string values can reach the query — operator objects are stripped.
    const user = await User.findOne({
      username: String(username),
      isActive: true,
    }).select('+password');

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const bcrypt = require('bcrypt');
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      logger.warn(`Failed login attempt for user: ${username}`);
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

// SAFE: Whitelisted query fields with explicit type casting
router.get('/api/users', authenticateToken, requireRole('admin'), [
  query('role').optional().isIn(['user', 'admin', 'moderator']),
  query('isActive').optional().isBoolean(),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  try {
    // Build filter from whitelisted fields only
    const filter = {};
    if (req.query.role) filter.role = String(req.query.role);
    if (req.query.isActive !== undefined) filter.isActive = req.query.isActive === 'true';

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
