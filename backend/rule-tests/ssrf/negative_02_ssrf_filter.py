# Test: negative for rule SSRF-PY-002
# Expected: should_not_trigger
# Category: ssrf
# Language: python

"""
URL fetcher that resolves the target hostname and blocks requests whose
resolved IP falls within private or link-local address ranges.  This
prevents SSRF attacks that target internal infrastructure or cloud
metadata endpoints (169.254.169.254).
"""

import ipaddress
import logging
import socket
from flask import Flask, request, jsonify
import urllib.request
import urllib.error

app = Flask(__name__)
logger = logging.getLogger(__name__)

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
]


def is_safe_url(url: str) -> bool:
    """Resolve the hostname and verify the IP is not in a blocked range."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except (socket.gaierror, ValueError):
        return False

    return not any(resolved_ip in net for net in BLOCKED_NETWORKS)


@app.route("/api/preview", methods=["POST"])
def preview_link():
    """Fetch a preview of the given URL after validating its resolved IP."""
    target_url = request.form.get("target_url")
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    if not is_safe_url(target_url):
        logger.warning("Blocked SSRF attempt to %s", target_url)
        return jsonify({"error": "URL targets a restricted address"}), 403

    try:
        with urllib.request.urlopen(target_url, timeout=8) as resp:
            body = resp.read(16_384).decode("utf-8", errors="replace")
        return jsonify({"url": target_url, "preview": body[:2000]})
    except urllib.error.URLError as exc:
        logger.warning("Fetch failed for %s: %s", target_url, exc)
        return jsonify({"error": "Could not fetch the provided URL"}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
