# Test: negative for rule PT-PY-001
# Expected: should_not_trigger
# Category: path_traversal
# Language: python

import os
import logging
from flask import Flask, request, abort, send_file

app = Flask(__name__)
logger = logging.getLogger(__name__)

UPLOAD_DIRECTORY = "/data/uploads"


def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """Verify that the resolved path stays within the allowed base directory."""
    abs_base = os.path.realpath(base_dir)
    abs_requested = os.path.realpath(requested_path)
    return abs_requested.startswith(abs_base + os.sep) or abs_requested == abs_base


@app.route("/download", methods=["GET"])
def download_file():
    """Safely download a file with realpath validation."""
    filename = request.args.get("file")

    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # Construct the candidate file path
    candidate = os.path.join(UPLOAD_DIRECTORY, filename)

    # SAFE: Resolve symlinks and relative components, then verify it stays under base
    if not is_safe_path(UPLOAD_DIRECTORY, candidate):
        logger.warning("Path traversal attempt blocked: %s", filename)
        abort(403, description="Access denied")

    resolved = os.path.realpath(candidate)

    if not os.path.isfile(resolved):
        abort(404, description="File not found")

    logger.info("Serving safe download: %s", resolved)
    return send_file(resolved, as_attachment=True)


@app.route("/preview", methods=["GET"])
def preview_file():
    """Safely preview a text file with realpath validation."""
    filename = request.args.get("file")

    if not filename:
        abort(400, description="Missing 'file' query parameter")

    candidate = os.path.join(UPLOAD_DIRECTORY, filename)

    # SAFE: realpath + startswith check prevents directory escape
    if not is_safe_path(UPLOAD_DIRECTORY, candidate):
        logger.warning("Path traversal attempt blocked: %s", filename)
        abort(403, description="Access denied")

    resolved = os.path.realpath(candidate)

    try:
        with open(resolved, "r", encoding="utf-8") as f:
            preview = f.read(1000)
        return {"filename": os.path.basename(resolved), "preview": preview}, 200
    except FileNotFoundError:
        abort(404, description="File not found")
