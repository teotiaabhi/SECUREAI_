# Test: negative for rule SSRF-PY-001
# Expected: should_not_trigger
# Category: ssrf
# Language: python

"""
Secure external-fetch endpoint that only allows requests to a strict
set of known upstream API domains.  The domain allowlist prevents SSRF
by rejecting any URL whose hostname is not explicitly trusted.
"""

import logging
from urllib.parse import urlparse
from flask import Flask, request, jsonify, abort
import requests
from requests.exceptions import RequestException

app = Flask(__name__)
logger = logging.getLogger(__name__)

ALLOWED_DOMAINS = [
    "api.github.com",
    "api.stripe.com",
    "hooks.slack.com",
]


@app.route("/api/fetch-url", methods=["GET"])
def fetch_url():
    """Fetch content from a pre-approved set of upstream API domains."""
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400

    parsed = urlparse(url)

    if parsed.scheme not in ("https",):
        abort(403, description="Only HTTPS URLs are permitted")

    if parsed.hostname not in ALLOWED_DOMAINS:
        logger.warning("Blocked request to disallowed host: %s", parsed.hostname)
        abort(403, description="Domain not in allowlist")

    try:
        response = requests.get(url, timeout=10)
        return jsonify({
            "status_code": response.status_code,
            "body": response.text[:5000],
        })
    except RequestException as exc:
        logger.exception("Upstream request failed: %s", exc)
        return jsonify({"error": "Upstream request failed"}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
