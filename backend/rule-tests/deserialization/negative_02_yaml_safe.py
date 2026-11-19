# Test: negative for rule DESER-PY-002
# Expected: should_not_trigger
# Category: deserialization
# Language: python

import yaml
import os
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

ALLOWED_CONFIG_KEYS = {"theme", "language", "notifications", "timezone", "page_size"}


def validate_config(config: dict) -> dict:
    """Filter configuration to only include allowed keys."""
    return {k: v for k, v in config.items() if k in ALLOWED_CONFIG_KEYS}


@app.route("/api/settings/import", methods=["POST"])
def import_settings():
    """Import user settings from a YAML file upload."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename.endswith((".yml", ".yaml")):
        return jsonify({"error": "Invalid file type, expected YAML"}), 400

    try:
        raw_content = uploaded_file.read().decode("utf-8")

        # SAFE: yaml.safe_load only constructs basic Python objects
        # (strings, numbers, lists, dicts) and will not execute arbitrary code
        settings = yaml.safe_load(raw_content)

        if not isinstance(settings, dict):
            return jsonify({"error": "YAML root must be a mapping"}), 400

        validated = validate_config(settings)
        logger.info("Imported %d settings keys", len(validated))

        return jsonify({"status": "imported", "keys": list(validated.keys())}), 200

    except yaml.YAMLError as exc:
        logger.warning("Invalid YAML uploaded: %s", exc)
        return jsonify({"error": "Malformed YAML content"}), 400
