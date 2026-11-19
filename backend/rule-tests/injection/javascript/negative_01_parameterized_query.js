// Test: negative for rule JS-INJ-001
// Expected: should_not_trigger
// Category: injection
// Language: javascript

const express = require('express');
const { Pool } = require('pg');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  database: process.env.DB_NAME || 'appdb',
  user: process.env.DB_USER || 'appuser',
  password: process.env.DB_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
});

// Middleware: attach request ID for tracing
router.use((req, res, next) => {
  req.requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  logger.info(`[${req.requestId}] ${req.method} ${req.originalUrl}`);
  next();
});

// SAFE: SQL queries use parameterized placeholders — user input never touches query string
router.get('/api/users/search', authenticateToken, async (req, res) => {
  const { username, role, sortBy } = req.query;

  // Whitelist allowed sort columns to prevent ORDER BY injection
  const allowedSortColumns = ['created_at', 'username', 'email'];
  const safeSort = allowedSortColumns.includes(sortBy) ? sortBy : 'created_at';

  try {
    const queryText = `SELECT id, username, email, role, created_at
      FROM users
      WHERE username ILIKE $1
        AND role = $2
      ORDER BY ${safeSort} DESC
      LIMIT 50`;

    const queryParams = [`%${username}%`, role];

    logger.debug(`[${req.requestId}] Executing parameterized query with ${queryParams.length} params`);
    const result = await pool.query(queryText, queryParams);

    res.json({
      success: true,
      count: result.rowCount,
      users: result.rows,
    });
  } catch (err) {
    logger.error(`[${req.requestId}] Database error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// SAFE: parameterized query for authentication
router.post('/api/users/authenticate', async (req, res) => {
  const { email, password } = req.body;

  try {
    const authQuery = `SELECT id, username, email, password_hash
      FROM users
      WHERE email = $1`;

    const result = await pool.query(authQuery, [email]);

    if (result.rowCount === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Use bcrypt to compare password against stored hash (not raw comparison)
    const bcrypt = require('bcrypt');
    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    logger.info(`[${req.requestId}] User ${user.id} authenticated successfully`);
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    logger.error(`[${req.requestId}] Auth error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
});

module.exports = router;
