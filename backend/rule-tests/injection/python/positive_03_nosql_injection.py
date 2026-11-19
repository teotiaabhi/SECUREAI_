# Test: positive for rule PY-INJ-003
# Expected: should_trigger
# Category: injection
# Language: python

"""
Vulnerable Flask/PyMongo endpoint demonstrating NoSQL injection.
User-supplied JSON from the request body is passed directly into
MongoDB query operators without validation or sanitization.
"""

import logging
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.json_util import dumps

app = Flask(__name__)
logger = logging.getLogger(__name__)

mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["ecommerce_db"]
products_collection = db["products"]


@app.route("/api/v1/products/search", methods=["POST"])
def search_products():
    """Search products by user-supplied filter criteria. VULNERABLE to NoSQL injection."""
    body = request.get_json(silent=True)

    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    # VULNERABLE: Passing unsanitized user input directly as a MongoDB query
    # An attacker can send {"price": {"$gt": 0}} or {"$where": "..."} payloads
    try:
        query_filter = body.get("filter", {})
        sort_field = body.get("sort", "name")
        limit = body.get("limit", 50)

        cursor = products_collection.find(query_filter).sort(sort_field, 1).limit(limit)
        results = [doc for doc in cursor]

        logger.info("Product search returned %d results", len(results))
        return jsonify({"products": dumps(results), "count": len(results)}), 200

    except Exception as exc:
        logger.error("Error during product search: %s", exc)
        return jsonify({"error": "Search failed"}), 500


@app.route("/api/v1/users/authenticate", methods=["POST"])
def authenticate_user():
    """Authenticate user by username and password. VULNERABLE to NoSQL injection."""
    credentials = request.get_json(silent=True)

    if not credentials:
        return jsonify({"error": "Credentials required"}), 400

    # VULNERABLE: Direct insertion of user-controlled data into the query
    # Attacker can bypass auth with {"username": "admin", "password": {"$ne": ""}}
    user = db["users"].find_one({
        "username": credentials.get("username"),
        "password": credentials.get("password"),
    })

    if user:
        return jsonify({"authenticated": True, "user_id": str(user["_id"])}), 200

    return jsonify({"authenticated": False}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
