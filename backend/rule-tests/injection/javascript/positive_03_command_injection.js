// Test: positive for rule JS-INJ-003
// Expected: should_trigger
// Category: injection
// Language: javascript

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads', 'documents');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
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

// VULNERABLE: command injection via concatenated filename in exec()
router.post('/api/files/convert', authenticateToken, upload.single('document'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  const inputPath = req.file.path;
  const outputFormat = req.body.format || 'pdf';
  const originalName = req.file.originalname;

  // Dangerous: user-controlled filename is concatenated directly into a shell command.
  // A filename like "file; rm -rf /" would execute arbitrary commands.
  const convertCommand = `libreoffice --headless --convert-to ${outputFormat} --outdir "${UPLOAD_DIR}" "${inputPath}"`;

  logger.info(`Converting file: ${originalName} to ${outputFormat}`);

  exec(convertCommand, { timeout: 30000 }, (error, stdout, stderr) => {
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

// VULNERABLE: command injection via user-supplied directory name in exec()
router.get('/api/files/list', authenticateToken, (req, res) => {
  const subdir = req.query.directory || '';

  // Dangerous: user-controlled directory name is injected into a shell command
  const listCommand = `ls -la "${UPLOAD_DIR}/${subdir}" | head -50`;

  exec(listCommand, (error, stdout, stderr) => {
    if (error) {
      logger.error(`File listing failed: ${error.message}`);
      return res.status(500).json({ success: false, error: 'Could not list files' });
    }

    const files = stdout.trim().split('\n').filter(Boolean);
    res.json({ success: true, files });
  });
});

module.exports = router;
