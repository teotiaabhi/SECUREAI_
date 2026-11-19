// Test: positive for rule SSRF-JS-001
// Expected: should_trigger
// Category: ssrf
// Language: javascript

/**
 * Lightweight proxy endpoint that lets the frontend bypass CORS
 * restrictions by relaying requests through the backend.
 * VULNERABLE: the target URL comes directly from the query string
 * with no allowlist or IP validation.
 */

const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get("/api/proxy", async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).json({ error: "Missing 'url' query parameter" });
  }

  try {
    // VULNERABLE: attacker-controlled URL forwarded without restriction.
    // Internal services (e.g. http://localhost:6379, cloud metadata endpoints)
    // can be reached through this proxy.
    const response = await axios.get(url, { timeout: 10000 });

    return res.json({
      status: response.status,
      contentType: response.headers["content-type"] || "",
      body: typeof response.data === "string"
        ? response.data.slice(0, 5000)
        : response.data,
    });
  } catch (err) {
    console.error(`Proxy fetch failed for ${url}:`, err.message);
    return res.status(502).json({ error: "Upstream request failed" });
  }
});

app.listen(PORT, () => {
  console.log(`Proxy service listening on port ${PORT}`);
});
