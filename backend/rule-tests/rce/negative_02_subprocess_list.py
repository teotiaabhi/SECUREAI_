# Test: negative for rule RCE-PY-001
# Expected: should_not_trigger
# Category: rce
# Language: python

"""
Media conversion endpoint that invokes ffmpeg safely by passing
arguments as a list to subprocess.run with shell=False.  This avoids
command injection because the filename is never interpreted by a shell;
it is passed as a single argument directly to the ffmpeg binary.
"""

import logging
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("/var/uploads")
OUTPUT_DIR = Path("/var/converted")
ALLOWED_EXTENSIONS = {".avi", ".mov", ".mkv", ".webm", ".flv"}


@app.route("/api/convert", methods=["POST"])
def convert_video():
    """Convert an uploaded video file to MP4 using ffmpeg (safe)."""
    filename = request.form.get("filename")
    if not filename:
        return jsonify({"error": "Missing 'filename' field"}), 400

    # Basic filename validation
    if ".." in filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "Invalid filename"}), 400

    input_path = UPLOAD_DIR / filename
    if input_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported file format"}), 400

    if not input_path.exists():
        return jsonify({"error": "Source file not found"}), 404

    output_path = OUTPUT_DIR / f"{input_path.stem}.mp4"

    # SAFE: arguments are passed as a list with shell=False (the default).
    # The filename is never concatenated into a shell command string.
    result = subprocess.run(
        ["ffmpeg", "-y", "-i", str(input_path), str(output_path)],
        shell=False,
        capture_output=True,
        timeout=120,
    )

    if result.returncode != 0:
        logger.error("ffmpeg stderr: %s", result.stderr.decode(errors="replace"))
        return jsonify({"error": "Conversion failed"}), 500

    return jsonify({
        "message": "Conversion complete",
        "output": str(output_path),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
