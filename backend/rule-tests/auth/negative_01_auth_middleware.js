// Test: negative for rule AUTH-JS-001
// Expected: should_not_trigger
// Category: auth
// Language: javascript
//
// Description: Express routes for admin endpoints that correctly apply
// authentication and authorization middleware before every handler.
// This file must NOT trigger AUTH-JS-001.

const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { authMiddleware, requireRole } = require('../middleware/auth');

// Apply authMiddleware to every route in this router
router.use(authMiddleware);

// GET /api/admin/users - list all users (auth + admin role required)
router.get('/api/admin/users', requireRole('admin'), async (req, res) => {
  const users = await db.query('SELECT id, email, role, created_at FROM users');
  res.json({ success: true, data: users });
});

// GET /api/admin/users/:id - single user details (auth + admin role)
router.get('/api/admin/users/:id', requireRole('admin'), async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user.length) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ success: true, data: user[0] });
});

// PUT /api/admin/settings - update application settings (auth + superadmin)
router.put('/api/admin/settings', requireRole('superadmin'), async (req, res) => {
  const { siteName, maintenanceMode, maxUploadSize, allowRegistration } = req.body;
  const result = await db.query(
    'UPDATE app_settings SET site_name = ?, maintenance_mode = ?, max_upload_size = ?, allow_registration = ? WHERE id = 1',
    [siteName, maintenanceMode, maxUploadSize, allowRegistration]
  );
  res.json({ success: true, message: 'Settings updated', data: result });
});

// GET /api/admin/settings - retrieve current settings (auth + admin)
router.get('/api/admin/settings', requireRole('admin'), async (req, res) => {
  const settings = await db.query('SELECT * FROM app_settings WHERE id = 1');
  res.json({ success: true, data: settings });
});

// DELETE /api/admin/delete/:id - delete user account (auth + superadmin)
router.delete('/api/admin/delete/:id', requireRole('superadmin'), async (req, res) => {
  const userId = req.params.id;
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  await db.query('DELETE FROM user_sessions WHERE user_id = ?', [userId]);
  await db.query('DELETE FROM user_data WHERE user_id = ?', [userId]);
  await db.query('DELETE FROM users WHERE id = ?', [userId]);
  res.json({ success: true, message: `User ${userId} permanently deleted` });
});

// POST /api/admin/users/:id/role - change user role (auth + superadmin)
router.post('/api/admin/users/:id/role', requireRole('superadmin'), async (req, res) => {
  const { role } = req.body;
  const validRoles = ['user', 'moderator', 'admin', 'superadmin'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  await db.query('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
  res.json({ success: true, message: `Role updated to ${role}` });
});

module.exports = router;
