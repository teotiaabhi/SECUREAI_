# Test: negative for rule PY-INJ-001
# Expected: should_not_trigger
# Category: injection
# Language: python

"""
Safe Flask API endpoint demonstrating proper use of parameterized queries.
All user-supplied values are passed as query parameters via %s placeholders
and a tuple, preventing SQL injection.
"""

import logging
from flask import Flask, request, jsonify
import psycopg2
from psycopg2 import sql

app = Flask(__name__)
logger = logging.getLogger(__name__)

DATABASE_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "webapp_db",
    "user": "app_user",
    "password": "s3cret",
}

ALLOWED_SORT_COLUMNS = {"username", "email", "created_at", "id"}


def get_db_connection():
    """Establish and return a new database connection."""
    conn = psycopg2.connect(**DATABASE_CONFIG)
    conn.autocommit = False
    return conn


@app.route("/api/v1/users/search", methods=["GET"])
def search_users():
    """Search users by username using parameterized queries. SAFE from SQL injection."""
    username = request.args.get("username", "")
    sort_column = request.args.get("sort", "created_at")

    if not username:
        return jsonify({"error": "username parameter is required"}), 400

    # SAFE: Validate sort column against an allowlist
    if sort_column not in ALLOWED_SORT_COLUMNS:
        sort_column = "created_at"

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # SAFE: Parameterized query with %s placeholder and tuple of values
        query = sql.SQL(
            "SELECT id, username, email, created_at FROM users WHERE username LIKE %s ORDER BY {sort}"
        ).format(sort=sql.Identifier(sort_column))

        search_pattern = f"%{username}%"
        cursor.execute(query, (search_pattern,))

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

        logger.info("User search returned %d results", len(results))
        return jsonify({"users": results, "count": len(results)}), 200

    except psycopg2.Error as db_err:
        logger.error("Database error during user search: %s", db_err)
        return jsonify({"error": "Internal database error"}), 500
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
