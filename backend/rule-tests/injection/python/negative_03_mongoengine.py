# Test: negative for rule PY-INJ-003
# Expected: should_not_trigger
# Category: injection
# Language: python

"""
Safe Flask/MongoEngine endpoint demonstrating secure MongoDB access.
All queries go through MongoEngine's ORM layer, which validates field
types and prevents NoSQL injection by design.
"""

import logging
from flask import Flask, request, jsonify
from mongoengine import connect, Document, StringField, FloatField, IntField, ListField

app = Flask(__name__)
logger = logging.getLogger(__name__)

connect("ecommerce_db", host="localhost", port=27017)


class Product(Document):
    name = StringField(required=True, max_length=200)
    sku = StringField(required=True, unique=True, max_length=50)
    category = StringField(max_length=100)
    price = FloatField(required=True, min_value=0)
    stock_quantity = IntField(default=0, min_value=0)
    tags = ListField(StringField(max_length=50))

    meta = {"collection": "products", "indexes": ["sku", "category"]}


@app.route("/api/v1/products/search", methods=["POST"])
def search_products():
    """Search products using MongoEngine ORM. SAFE from NoSQL injection."""
    body = request.get_json(silent=True)

    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    try:
        # SAFE: MongoEngine ORM methods with explicit typed fields
        query = Product.objects

        if "name" in body and isinstance(body["name"], str):
            query = query.filter(name__icontains=body["name"])

        if "category" in body and isinstance(body["category"], str):
            query = query.filter(category=body["category"])

        if "min_price" in body and isinstance(body["min_price"], (int, float)):
            query = query.filter(price__gte=float(body["min_price"]))

        if "max_price" in body and isinstance(body["max_price"], (int, float)):
            query = query.filter(price__lte=float(body["max_price"]))

        limit = min(int(body.get("limit", 50)), 100)
        results = query.order_by("name").limit(limit)

        products = [
            {
                "name": p.name,
                "sku": p.sku,
                "category": p.category,
                "price": p.price,
                "stock_quantity": p.stock_quantity,
            }
            for p in results
        ]

        logger.info("Product search returned %d results", len(products))
        return jsonify({"products": products, "count": len(products)}), 200

    except Exception as exc:
        logger.error("Error during product search: %s", exc)
        return jsonify({"error": "Search failed"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
