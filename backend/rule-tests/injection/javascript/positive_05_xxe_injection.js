// Test: positive for rule JS-INJ-005
// Expected: should_trigger
// Category: injection
// Language: javascript

const express = require('express');
const libxmljs = require('libxmljs');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');

// Accept raw XML body
router.use(express.text({ type: ['application/xml', 'text/xml'], limit: '5mb' }));

// VULNERABLE: XML External Entity injection via libxmljs with external entities enabled
// An attacker can craft XML containing entities like:
// <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
// <root>&xxe;</root>
router.post('/api/invoices/import', authenticateToken, (req, res) => {
  const rawXml = req.body;

  if (!rawXml || typeof rawXml !== 'string') {
    return res.status(400).json({ success: false, error: 'XML payload is required' });
  }

  try {
    // Dangerous: parsing user-supplied XML with external entities and network access enabled
    // This allows XXE attacks to read local files and make SSRF requests
    const xmlDoc = libxmljs.parseXml(rawXml, {
      noent: true,       // Substitute entities — enables XXE
      dtdload: true,     // Load external DTD
      dtdvalid: false,
      nocdata: true,
    });

    const invoices = xmlDoc.find('//invoice').map((node) => ({
      id: node.get('id') ? node.get('id').text() : null,
      vendor: node.get('vendor') ? node.get('vendor').text() : null,
      amount: node.get('amount') ? parseFloat(node.get('amount').text()) : 0,
      date: node.get('date') ? node.get('date').text() : null,
      description: node.get('description') ? node.get('description').text() : '',
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
});

module.exports = router;
