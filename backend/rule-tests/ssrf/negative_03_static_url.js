// Test: negative for rule SSRF-JS-001
// Expected: should_not_trigger
// Category: ssrf
// Language: javascript

/**
 * Health-check aggregator that polls a fixed set of internal services
 * whose base URLs are loaded from environment variables at startup.
 * No user-supplied input is ever used to construct the fetch URL,
 * so this endpoint is NOT vulnerable to SSRF.
 */

const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

// Static base URL loaded once from the environment -- never from req.*
const API_BASE = process.env.UPSTREAM_API_URL || "https://internal-api.example.com";
const METRICS_URL = process.env.METRICS_URL || "https://metrics.example.com";

async function checkEndpoint(url) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
    return { url, status: response.status, ok: response.ok };
  } catch (err) {
    return { url, status: null, ok: false, error: err.message };
  }
}

app.get("/api/healthcheck", async (_req, res) => {
  try {
    const results = await Promise.all([
      checkEndpoint(`${API_BASE}/health`),
      checkEndpoint(`${METRICS_URL}/ping`),
    ]);

    const allHealthy = results.every((r) => r.ok);
    return res.status(allHealthy ? 200 : 503).json({
      healthy: allHealthy,
      services: results,
    });
  } catch (err) {
    console.error("Health check aggregation failed:", err.message);
    return res.status(500).json({ error: "Internal health check error" });
  }
});

app.listen(PORT, () => {
  console.log(`Health-check aggregator listening on port ${PORT}`);
});
