// Test: negative for rule JS-INJ-005
// Expected: should_not_trigger
// Category: injection
// Language: javascript

const express = require('express');
const { parseStringPromise } = require('xml2js');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');

// Accept raw XML body
router.use(express.text({ type: ['application/xml', 'text/xml'], limit: '5mb' }));

// Reject XML payloads that contain DOCTYPE declarations (defense-in-depth)
function rejectDoctypeMiddleware(req, res, next) {
  if (typeof req.body === 'string' && /<!DOCTYPE/i.test(req.body)) {
    logger.warn(`Blocked XML with DOCTYPE declaration from ${req.ip}`);
    return res.status(400).json({
      success: false,
      error: 'XML documents with DOCTYPE declarations are not accepted',
    });
  }
  next();
}

// SAFE: XML parsing with xml2js, which does NOT process external entities by default.
// Additional safeguards: DOCTYPE rejection middleware, explicit parser hardening options.
router.post(
  '/api/invoices/import',
  authenticateToken,
  rejectDoctypeMiddleware,
  async (req, res) => {
    const rawXml = req.body;

    if (!rawXml || typeof rawXml !== 'string') {
      return res.status(400).json({ success: false, error: 'XML payload is required' });
    }

    try {
      // Safe: xml2js.parseStringPromise does not support external entities.
      // Explicit options further harden the parser against edge cases.
      const parsed = await parseStringPromise(rawXml, {
        explicitArray: false,
        ignoreAttrs: false,
        tagNameProcessors: [],
        strict: true,
      });

      if (!parsed || !parsed.invoices || !parsed.invoices.invoice) {
        return res.status(400).json({ success: false, error: 'Missing <invoices> root or <invoice> elements' });
      }

      const rawInvoices = Array.isArray(parsed.invoices.invoice)
        ? parsed.invoices.invoice
        : [parsed.invoices.invoice];

      const invoices = rawInvoices.map((inv) => ({
        id: inv.id || null,
        vendor: inv.vendor || null,
        amount: parseFloat(inv.amount) || 0,
        date: inv.date || null,
        description: String(inv.description || '').slice(0, 500),
      }));

      logger.info(`Imported ${invoices.length} invoices from XML upload`);

      res.json({
        success: true,
        message: `${invoices.length} invoices imported`,
        invoices,
      });
    } catch (err) {
      logger.error(`XML parsing error: ${err.message}`);
      res.status(400).json({ success: false, error: 'Invalid XML document' });
    }
  }
);

module.exports = router;
