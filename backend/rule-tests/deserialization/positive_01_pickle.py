# =============================================================================
# Test:     positive_01_pickle
# Expected: TRIGGER rule DESER-PY-001
# Category: Deserialization
# Language: Python
# Description: Flask endpoint that deserializes user-uploaded data using
#              pickle.loads() on raw request data, allowing arbitrary code
#              execution via crafted pickle payloads.
# =============================================================================

import pickle
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

# In-memory session store (simulated)
session_store = {}


@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    """
    Restore a previously saved user session from a serialized payload.
    WARNING: This endpoint is vulnerable to arbitrary code execution
    through crafted pickle payloads.
    """
    try:
        content_type = request.headers.get("Content-Type", "")
        if "application/octet-stream" not in content_type:
            return jsonify({"error": "Expected application/octet-stream"}), 400

        raw_data = request.data
        if not raw_data:
            return jsonify({"error": "Empty request body"}), 400

        # VULNERABLE: Deserializing untrusted data with pickle
        session_obj = pickle.loads(raw_data)

        user_id = session_obj.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid session: missing user_id"}), 400

        session_store[user_id] = session_obj
        logger.info("Session restored for user %s", user_id)

        return jsonify({
            "status": "restored",
            "user_id": user_id,
            "keys": list(session_obj.keys()),
        }), 200

    except Exception as exc:
        logger.exception("Failed to restore session")
        return jsonify({"error": str(exc)}), 500
