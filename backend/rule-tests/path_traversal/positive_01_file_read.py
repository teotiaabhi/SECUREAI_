# Test: positive for rule PT-PY-001
# Expected: should_trigger
# Category: path_traversal
# Language: python

import os
import logging
from flask import Flask, request, send_file, abort

app = Flask(__name__)
logger = logging.getLogger(__name__)

UPLOAD_DIRECTORY = "/data/uploads"


@app.route("/download", methods=["GET"])
def download_file():
    """Download a file from the uploads directory."""
    filename = request.args.get("file")

    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # VULNERABLE: User-controlled filename is joined directly without sanitization.
    # An attacker can supply '../../../etc/passwd' to read arbitrary files.
    file_path = os.path.join(UPLOAD_DIRECTORY, filename)

    if not os.path.isfile(file_path):
        abort(404, description="File not found")

    try:
        logger.info("Serving file download: %s", file_path)
        with open(file_path, "rb") as f:
            content = f.read()
        return content, 200, {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename={os.path.basename(file_path)}"
        }
    except PermissionError:
        logger.error("Permission denied reading %s", file_path)
        abort(403, description="Access denied")


@app.route("/preview", methods=["GET"])
def preview_file():
    """Preview a text file's first 1000 characters."""
    filename = request.args.get("file")

    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # VULNERABLE: Same pattern — no path traversal protection
    file_path = os.path.join("/data/uploads", filename)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            preview = f.read(1000)
        return {"filename": filename, "preview": preview}, 200
    except FileNotFoundError:
        abort(404, description="File not found")
