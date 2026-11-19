# Test: positive for rule SSRF-PY-002
# Expected: should_trigger
# Category: ssrf
# Language: python

"""
Link preview service that fetches the title and meta description from a
user-supplied URL using urllib.  Vulnerable to SSRF because the target
URL is consumed directly from form data without sanitisation.
"""

import logging
from html.parser import HTMLParser
from flask import Flask, request, jsonify
import urllib.request
import urllib.error

app = Flask(__name__)
logger = logging.getLogger(__name__)


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_data(self, data):
        if self.in_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False


@app.route("/api/preview", methods=["POST"])
def preview_link():
    """Generate a rich-link preview for the given target URL."""
    target_url = request.form.get("target_url")
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    try:
        # VULNERABLE: user-controlled URL passed directly to urlopen.
        # Allows an attacker to probe internal network resources.
        with urllib.request.urlopen(target_url, timeout=8) as resp:
            html = resp.read(16_384).decode("utf-8", errors="replace")

        parser = TitleParser()
        parser.feed(html)
        return jsonify({"url": target_url, "title": parser.title or "Untitled"})
    except urllib.error.URLError as exc:
        logger.warning("Preview fetch failed for %s: %s", target_url, exc)
        return jsonify({"error": "Could not fetch the provided URL"}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
