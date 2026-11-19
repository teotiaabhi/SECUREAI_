# =============================================================================
# Test:     negative_01_json_safe
# Expected: MUST NOT trigger any deserialization rule
# Category: Deserialization
# Language: Python
# Description: Flask endpoint that safely parses JSON data using json.loads(),
#              which does not support arbitrary object instantiation.
# =============================================================================

import json
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

# In-memory session store (simulated)
session_store = {}

ALLOWED_SESSION_KEYS = {"user_id", "display_name", "theme", "language", "timezone"}


@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    """
    Restore a previously saved user session from a JSON payload.
    This endpoint uses json.loads() which is safe from deserialization attacks.
    """
    try:
        content_type = request.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            return jsonify({"error": "Expected application/json"}), 400

        raw_data = request.data
        if not raw_data:
            return jsonify({"error": "Empty request body"}), 400

        # SAFE: json.loads only produces basic Python types (dict, list, str, etc.)
        session_obj = json.loads(raw_data)

        if not isinstance(session_obj, dict):
            return jsonify({"error": "Expected a JSON object"}), 400

        user_id = session_obj.get("user_id")
        if not user_id or not isinstance(user_id, str):
            return jsonify({"error": "Invalid session: missing or bad user_id"}), 400

        # Filter to only allowed keys
        filtered = {k: v for k, v in session_obj.items() if k in ALLOWED_SESSION_KEYS}
        session_store[user_id] = filtered
        logger.info("Session restored for user %s", user_id)

        return jsonify({
            "status": "restored",
            "user_id": user_id,
            "keys": list(filtered.keys()),
        }), 200

    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in session restore: %s", exc)
        return jsonify({"error": "Invalid JSON"}), 400
    except Exception as exc:
        logger.exception("Unexpected error restoring session")
        return jsonify({"error": "Internal server error"}), 500
