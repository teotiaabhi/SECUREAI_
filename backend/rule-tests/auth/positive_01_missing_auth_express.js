// Test: positive for rule AUTH-JS-001
// Expected: should_trigger
// Category: auth
// Language: javascript
//
// Description: Express routes serving admin endpoints without any
// authentication or authorization middleware in the handler chain.
// All route handlers accept (req, res) directly, meaning any
// unauthenticated request can reach sensitive admin operations.

const express = require('express');
const router = express.Router();
const db = require('../models/db');

// GET /api/admin/users - list all users (no auth)
router.get('/api/admin/users', (req, res) => {
  const users = db.query('SELECT id, email, role, created_at FROM users');
  res.json({ success: true, data: users });
});

// GET /api/admin/users/:id - get single user details (no auth)
router.get('/api/admin/users/:id', (req, res) => {
  const user = db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ success: true, data: user });
});

// PUT /api/admin/settings - update application settings (no auth)
router.put('/api/admin/settings', (req, res) => {
  const { siteName, maintenanceMode, maxUploadSize, allowRegistration } = req.body;
  const result = db.query(
    'UPDATE app_settings SET site_name = ?, maintenance_mode = ?, max_upload_size = ?, allow_registration = ? WHERE id = 1',
    [siteName, maintenanceMode, maxUploadSize, allowRegistration]
  );
  res.json({ success: true, message: 'Settings updated', data: result });
});

// GET /api/admin/settings - retrieve current settings (no auth)
router.get('/api/admin/settings', (req, res) => {
  const settings = db.query('SELECT * FROM app_settings WHERE id = 1');
  res.json({ success: true, data: settings });
});

// DELETE /api/admin/delete/:id - delete a user account (no auth)
router.delete('/api/admin/delete/:id', (req, res) => {
  const userId = req.params.id;
  db.query('DELETE FROM user_sessions WHERE user_id = ?', [userId]);
  db.query('DELETE FROM user_data WHERE user_id = ?', [userId]);
  db.query('DELETE FROM users WHERE id = ?', [userId]);
  res.json({ success: true, message: `User ${userId} permanently deleted` });
});

// POST /api/admin/users/:id/role - change user role (no auth)
router.post('/api/admin/users/:id/role', (req, res) => {
  const { role } = req.body;
  const validRoles = ['user', 'moderator', 'admin', 'superadmin'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  db.query('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
  res.json({ success: true, message: `Role updated to ${role}` });
});

module.exports = router;
