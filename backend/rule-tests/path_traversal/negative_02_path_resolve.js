// Test: negative for rule PT-JS-001
// Expected: should_not_trigger
// Category: path_traversal
// Language: javascript

const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const BASE_DIR = path.resolve(__dirname, "public", "assets");

/**
 * Check whether the resolved file path is within the allowed base directory.
 * Returns the safe absolute path or null if traversal is detected.
 */
function safePath(baseDir, userInput) {
  const resolved = path.resolve(baseDir, userInput);

  if (!resolved.startsWith(baseDir + path.sep) && resolved !== baseDir) {
    return null;
  }

  return resolved;
}

/**
 * Serve a static asset file by name.
 * SAFE: path.resolve + base directory prefix check prevents directory traversal.
 */
app.get("/api/assets", (req, res) => {
  const file = req.query.file;

  if (!file) {
    return res.status(400).json({ error: "Missing 'file' query parameter" });
  }

  // SAFE: Resolve to absolute path and verify it remains under BASE_DIR
  const filePath = safePath(BASE_DIR, file);

  if (!filePath) {
    console.warn(`Path traversal attempt blocked: ${file}`);
    return res.status(403).json({ error: "Access denied" });
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === "ENOENT") {
        return res.status(404).json({ error: "File not found" });
      }
      console.error("Error reading file:", err.message);
      return res.status(500).json({ error: "Internal server error" });
    }

    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
      ".html": "text/html",
      ".css": "text/css",
      ".js": "application/javascript",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".svg": "image/svg+xml",
    };

    res.setHeader("Content-Type", mimeTypes[ext] || "application/octet-stream");
    res.send(data);
  });
});

app.listen(PORT, () => {
  console.log(`Asset server running on port ${PORT}`);
});
