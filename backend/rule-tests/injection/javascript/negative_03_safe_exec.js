// Test: negative for rule JS-INJ-003
// Expected: should_not_trigger
// Category: injection
// Language: javascript

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads', 'documents');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // Generate a safe UUID-based filename to avoid path traversal and injection
    const crypto = require('crypto');
    const safeId = crypto.randomUUID();
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${safeId}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.doc', '.docx', '.txt', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error(`File type ${ext} not allowed`));
  },
});

// SAFE: execFile passes arguments as an array, preventing shell injection
router.post('/api/files/convert', authenticateToken, upload.single('document'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  const inputPath = req.file.path;
  const allowedFormats = ['pdf', 'txt', 'html', 'docx'];
  const outputFormat = allowedFormats.includes(req.body.format) ? req.body.format : 'pdf';
  const originalName = req.file.originalname;

  logger.info(`Converting file: ${originalName} to ${outputFormat}`);

  // Safe: execFile does NOT spawn a shell — arguments are passed as a separate array,
  // so metacharacters in filenames cannot break out into command execution
  execFile('libreoffice', [
    '--headless',
    '--convert-to', outputFormat,
    '--outdir', UPLOAD_DIR,
    inputPath,
  ], { timeout: 30000 }, (error, stdout, stderr) => {
    if (error) {
      logger.error(`Conversion failed for ${originalName}: ${error.message}`);
      return res.status(500).json({ success: false, error: 'File conversion failed' });
    }

    if (stderr) {
      logger.warn(`Conversion warnings: ${stderr}`);
    }

    const outputFilename = path.basename(inputPath, path.extname(inputPath)) + `.${outputFormat}`;
    const outputPath = path.join(UPLOAD_DIR, outputFilename);

    res.json({
      success: true,
      message: 'File converted successfully',
      file: { original: originalName, converted: outputFilename, path: outputPath },
    });
  });
});

// SAFE: using fs.readdir instead of shelling out to list files
router.get('/api/files/list', authenticateToken, async (req, res) => {
  try {
    // Safe: no shell command involved — using Node.js fs API directly
    const entries = await fs.promises.readdir(UPLOAD_DIR, { withFileTypes: true });

    const files = entries
      .filter((entry) => entry.isFile())
      .map((entry) => ({
        name: entry.name,
        path: path.join(UPLOAD_DIR, entry.name),
      }));

    res.json({ success: true, files });
  } catch (err) {
    logger.error(`File listing failed: ${err.message}`);
    res.status(500).json({ success: false, error: 'Could not list files' });
  }
});

module.exports = router;
