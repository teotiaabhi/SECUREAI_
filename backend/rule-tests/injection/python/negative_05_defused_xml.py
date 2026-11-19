# Test: negative for rule PY-INJ-005
# Expected: should_not_trigger
# Category: injection
# Language: python

"""
Safe Flask endpoint demonstrating secure XML parsing with defusedxml.
The defusedxml library disables external entity resolution, DTD processing,
and other dangerous XML features by default, preventing XXE attacks.
"""

import logging
from flask import Flask, request, jsonify
import defusedxml.ElementTree as ET

app = Flask(__name__)
logger = logging.getLogger(__name__)


def extract_order_details(xml_root):
    """Extract order information from parsed XML tree."""
    order_data = {
        "order_id": xml_root.findtext("order_id", default=""),
        "customer": xml_root.findtext("customer", default=""),
        "items": [],
        "total": xml_root.findtext("total", default="0.00"),
    }
    for item_elem in xml_root.findall(".//item"):
        order_data["items"].append({
            "sku": item_elem.findtext("sku", default=""),
            "quantity": int(item_elem.findtext("quantity", default="0")),
            "price": float(item_elem.findtext("price", default="0.00")),
        })
    return order_data


@app.route("/api/v1/orders/import", methods=["POST"])
def import_order_xml():
    """Import an order from XML payload. SAFE from XXE via defusedxml."""
    raw_xml = request.data

    if not raw_xml:
        return jsonify({"error": "Request body must contain XML data"}), 400

    try:
        # SAFE: defusedxml.ElementTree.fromstring forbids external entities by default
        root = ET.fromstring(raw_xml)

        order = extract_order_details(root)
        logger.info("Imported order %s with %d items", order["order_id"], len(order["items"]))

        return jsonify({"status": "imported", "order": order}), 201

    except ET.ParseError as xml_err:
        logger.warning("Malformed XML received: %s", xml_err)
        return jsonify({"error": "Invalid XML format"}), 400
    except Exception as exc:
        logger.error("Order import failed: %s", exc)
        return jsonify({"error": "Import processing failed"}), 500


@app.route("/api/v1/config/upload", methods=["POST"])
def upload_config_xml():
    """Upload and parse an XML configuration file. SAFE from XXE via defusedxml."""
    xml_file = request.files.get("config_file")

    if not xml_file:
        return jsonify({"error": "config_file is required"}), 400

    try:
        # SAFE: defusedxml.ElementTree.parse prevents entity expansion and DTD loading
        tree = ET.parse(xml_file)
        root = tree.getroot()

        config_entries = {}
        for setting in root.findall(".//setting"):
            key = setting.get("name")
            value = setting.text
            if key:
                config_entries[key] = value

        return jsonify({"status": "loaded", "settings": config_entries}), 200

    except ET.ParseError as xml_err:
        logger.warning("Malformed config XML: %s", xml_err)
        return jsonify({"error": "Invalid XML configuration"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
