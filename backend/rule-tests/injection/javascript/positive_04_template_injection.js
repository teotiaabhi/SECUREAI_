// Test: positive for rule JS-INJ-004
// Expected: should_trigger
// Category: injection
// Language: javascript

const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');

// In-memory template store (simulating a CMS template database)
const templateStore = new Map();
templateStore.set('welcome', 'Hello, {{name}}! Welcome to our platform.');
templateStore.set('invoice', 'Invoice #{{invoiceId}} for {{name}}: Total ${{amount}}');

// VULNERABLE: Server-side template injection using eval() on user-supplied template
router.post('/api/templates/render', authenticateToken, (req, res) => {
  const { templateString, context } = req.body;

  if (!templateString || !context) {
    return res.status(400).json({ success: false, error: 'Template and context are required' });
  }

  try {
    // Dangerous: user-supplied template string is evaluated using Function constructor,
    // allowing arbitrary code execution via crafted template input
    const renderTemplate = new Function('context', `
      with (context) {
        return \`${templateString}\`;
      }
    `);

    const rendered = renderTemplate(context);

    logger.info(`Template rendered successfully for user ${req.user.id}`);
    res.json({ success: true, rendered });
  } catch (err) {
    logger.error(`Template rendering error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Template rendering failed' });
  }
});

// VULNERABLE: eval-based dynamic expression evaluation from user input
router.post('/api/reports/calculate', authenticateToken, requireRole('admin'), (req, res) => {
  const { expression, variables } = req.body;

  if (!expression) {
    return res.status(400).json({ success: false, error: 'Expression is required' });
  }

  try {
    // Dangerous: user-supplied expression is passed directly to eval()
    // An attacker can execute arbitrary code: "process.exit(1)" or
    // "require('child_process').execSync('whoami').toString()"
    const scope = { ...variables, Math, Date };
    const keys = Object.keys(scope);
    const values = Object.values(scope);

    const calculate = new Function(...keys, `return eval("${expression}")`);
    const result = calculate(...values);

    res.json({ success: true, expression, result });
  } catch (err) {
    logger.error(`Calculation error: ${err.message}`);
    res.status(400).json({ success: false, error: `Invalid expression: ${err.message}` });
  }
});

module.exports = router;
