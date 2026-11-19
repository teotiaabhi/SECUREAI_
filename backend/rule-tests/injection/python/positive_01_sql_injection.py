# Test: positive for rule PY-INJ-001
# Expected: should_trigger
# Category: injection
# Language: python

"""
Vulnerable Flask API endpoint demonstrating SQL injection via f-string
interpolation in cursor.execute(). User-supplied values from query
parameters are embedded directly into the SQL statement without
parameterization.
"""

import logging
from flask import Flask, request, jsonify
import psycopg2

app = Flask(__name__)
logger = logging.getLogger(__name__)

DATABASE_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "webapp_db",
    "user": "app_user",
    "password": "s3cret",
}


def get_db_connection():
    """Establish and return a new database connection."""
    conn = psycopg2.connect(**DATABASE_CONFIG)
    conn.autocommit = False
    return conn


@app.route("/api/v1/users/search", methods=["GET"])
def search_users():
    """Search users by username or email. VULNERABLE to SQL injection."""
    username = request.args.get("username", "")
    sort_column = request.args.get("sort", "created_at")

    if not username:
        return jsonify({"error": "username parameter is required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # VULNERABLE: f-string interpolation directly in SQL query
        query = f"SELECT id, username, email, created_at FROM users WHERE username LIKE '%{username}%' ORDER BY {sort_column}"
        cursor.execute(query)

        rows = cursor.fetchall()
        results = [
            {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "created_at": row[3].isoformat(),
            }
            for row in rows
        ]

        logger.info("User search returned %d results for query: %s", len(results), username)
        return jsonify({"users": results, "count": len(results)}), 200

    except psycopg2.Error as db_err:
        logger.error("Database error during user search: %s", db_err)
        return jsonify({"error": "Internal database error"}), 500
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
