# Test: positive for rule SSRF-PY-001
# Expected: should_trigger
# Category: ssrf
# Language: python

"""
Vulnerable webhook proxy endpoint that forwards requests to arbitrary URLs
provided by the user without any validation or restriction.
"""

import logging
from flask import Flask, request, jsonify
import requests
from requests.exceptions import RequestException

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/api/fetch-url", methods=["GET"])
def fetch_url():
    """
    Proxy endpoint used by the frontend to fetch external webhook payloads
    or preview remote resources. Accepts a URL via query parameter and
    returns the fetched content.
    """
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400

    try:
        # VULNERABLE: directly fetching a user-supplied URL with no validation.
        # An attacker can supply internal URLs such as http://169.254.169.254/
        # to reach cloud metadata services or internal microservices.
        response = requests.get(url, timeout=10)
        return jsonify({
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "body": response.text[:5000],
        })
    except RequestException as exc:
        logger.exception("Failed to fetch URL: %s", url)
        return jsonify({"error": str(exc)}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
