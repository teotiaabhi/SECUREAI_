# Test: negative for rule PY-INJ-004
# Expected: should_not_trigger
# Category: injection
# Language: python

"""
Safe Flask application demonstrating proper Jinja2 template rendering.
All user input is passed as context variables to pre-defined templates
using render_template(), ensuring proper auto-escaping and preventing SSTI.
"""

import logging
from flask import Flask, request, jsonify, render_template
from markupsafe import escape

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/api/v1/preview/email", methods=["POST"])
def preview_email_template():
    """Preview a predefined email template with user-supplied variables. SAFE from SSTI."""
    body = request.get_json(silent=True)

    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    template_name = body.get("template_name", "")
    context_vars = body.get("variables", {})

    # SAFE: Only allow selection from predefined template files
    allowed_templates = {
        "welcome": "emails/welcome.html",
        "reset_password": "emails/reset_password.html",
        "order_confirmation": "emails/order_confirmation.html",
        "newsletter": "emails/newsletter.html",
    }

    if template_name not in allowed_templates:
        return jsonify({"error": f"Unknown template: {template_name}"}), 400

    try:
        # SAFE: render_template uses a pre-defined file with auto-escaping enabled
        rendered_output = render_template(allowed_templates[template_name], **context_vars)
        return jsonify({"preview": rendered_output}), 200

    except Exception as exc:
        logger.error("Template rendering failed: %s", exc)
        return jsonify({"error": "Template rendering failed"}), 500


@app.route("/greet", methods=["GET"])
def greet_user():
    """Render a personalized greeting page. SAFE from SSTI."""
    visitor_name = request.args.get("name", "Guest")

    # SAFE: User input passed as a context variable to a static template file
    return render_template("greet.html", visitor_name=escape(visitor_name))


@app.route("/api/v1/reports/generate", methods=["POST"])
def generate_report():
    """Generate a report using a predefined template. SAFE from SSTI."""
    report_type = request.form.get("report_type", "summary")
    report_title = request.form.get("title", "Untitled Report")
    date_range = request.form.get("date_range", "last_30_days")

    allowed_reports = {"summary", "detailed", "financial", "inventory"}

    if report_type not in allowed_reports:
        return jsonify({"error": "Invalid report type"}), 400

    # SAFE: Template file path is determined by server-side logic, not user input
    template_file = f"reports/{report_type}.html"
    rendered = render_template(template_file, title=report_title, date_range=date_range)

    return rendered, 200, {"Content-Type": "text/html"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
