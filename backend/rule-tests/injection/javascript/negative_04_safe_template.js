// Test: negative for rule JS-INJ-004
// Expected: should_not_trigger
// Category: injection
// Language: javascript

const express = require('express');
const Handlebars = require('handlebars');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Pre-compiled, developer-defined templates stored server-side.
// User input is only ever passed as context data, never as template source.
const templates = new Map();

templates.set('welcome', Handlebars.compile('Hello, {{name}}! Welcome to our platform.'));
templates.set('invoice', Handlebars.compile(
  'Invoice #{{invoiceId}} for {{name}}: Total ${{amount}}'
));
templates.set('notification', Handlebars.compile(
  '<div class="alert alert-{{level}}"><strong>{{title}}</strong><p>{{message}}</p></div>'
));

// Register a safe helper for formatting currency
Handlebars.registerHelper('currency', (value) => {
  const num = parseFloat(value);
  if (isNaN(num)) return '$0.00';
  return `$${num.toFixed(2)}`;
});

// SAFE: Only pre-compiled templates are used. User input is treated as data context,
// not as template source. Handlebars auto-escapes HTML in expressions by default.
router.post('/api/templates/render', authenticateToken, (req, res) => {
  const { templateName, context } = req.body;

  if (!templateName || !context) {
    return res.status(400).json({ success: false, error: 'Template name and context are required' });
  }

  const compiledTemplate = templates.get(templateName);

  if (!compiledTemplate) {
    return res.status(404).json({ success: false, error: `Template "${templateName}" not found` });
  }

  try {
    // Safe: user-supplied context is only interpolated as data values.
    // Handlebars escapes HTML entities by default, preventing XSS.
    // No eval, Function constructor, or dynamic compilation of user input.
    const rendered = compiledTemplate(context);

    logger.info(`Template "${templateName}" rendered for user ${req.user.id}`);
    res.json({ success: true, rendered });
  } catch (err) {
    logger.error(`Template rendering error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Template rendering failed' });
  }
});

// SAFE: report calculations use a whitelist of operations, not eval
router.post('/api/reports/calculate', authenticateToken, requireRole('admin'), (req, res) => {
  const { operation, operands } = req.body;

  const allowedOps = {
    sum: (nums) => nums.reduce((a, b) => a + b, 0),
    average: (nums) => nums.reduce((a, b) => a + b, 0) / nums.length,
    max: (nums) => Math.max(...nums),
    min: (nums) => Math.min(...nums),
  };

  if (!operation || !allowedOps[operation]) {
    return res.status(400).json({
      success: false,
      error: `Invalid operation. Allowed: ${Object.keys(allowedOps).join(', ')}`,
    });
  }

  if (!Array.isArray(operands) || !operands.every((n) => typeof n === 'number')) {
    return res.status(400).json({ success: false, error: 'Operands must be an array of numbers' });
  }

  try {
    const result = allowedOps[operation](operands);
    res.json({ success: true, operation, result });
  } catch (err) {
    logger.error(`Calculation error: ${err.message}`);
    res.status(400).json({ success: false, error: 'Calculation failed' });
  }
});

module.exports = router;
