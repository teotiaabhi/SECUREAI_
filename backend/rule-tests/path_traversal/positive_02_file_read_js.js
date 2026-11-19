// Test: positive for rule PT-JS-001
// Expected: should_trigger
// Category: path_traversal
// Language: javascript

const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const STATIC_DIR = path.join(__dirname, "public", "assets");

/**
 * Serve a static asset file by name.
 * VULNERABLE: req.query.file is used directly without sanitization.
 */
app.get("/api/assets", (req, res) => {
  const file = req.query.file;

  if (!file) {
    return res.status(400).json({ error: "Missing 'file' query parameter" });
  }

  // VULNERABLE: An attacker can supply '../../etc/passwd' or similar payloads
  // to escape the intended directory and read arbitrary files on the server.
  const filePath = path.join(__dirname, "public", "assets", file);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === "ENOENT") {
        return res.status(404).json({ error: "File not found" });
      }
      console.error("Error reading file:", err.message);
      return res.status(500).json({ error: "Internal server error" });
    }

    const ext = path.extname(file).toLowerCase();
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
