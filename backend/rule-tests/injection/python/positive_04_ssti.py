# Test: positive for rule PY-INJ-004
# Expected: should_trigger
# Category: injection
# Language: python

"""
Vulnerable Flask application demonstrating Server-Side Template Injection (SSTI).
User-supplied input is embedded directly into Jinja2 templates and rendered,
allowing attackers to execute arbitrary Python code on the server.
"""

import logging
from flask import Flask, request, jsonify, render_template_string
from jinja2 import Template

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/api/v1/preview/email", methods=["POST"])
def preview_email_template():
    """Preview a custom email template. VULNERABLE to SSTI."""
    body = request.get_json(silent=True)

    if not body or "template" not in body:
        return jsonify({"error": "template field is required"}), 400

    user_template = body["template"]
    context_vars = body.get("variables", {})

    try:
        # VULNERABLE: User-controlled string passed directly to Template()
        template = Template(user_template)
        rendered_output = template.render(**context_vars)

        return jsonify({"preview": rendered_output}), 200

    except Exception as exc:
        logger.error("Template rendering failed: %s", exc)
        return jsonify({"error": "Template rendering failed"}), 500


@app.route("/greet", methods=["GET"])
def greet_user():
    """Render a personalized greeting page. VULNERABLE to SSTI."""
    visitor_name = request.args.get("name", "Guest")

    # VULNERABLE: render_template_string with user input concatenated into template
    page_html = f"""
    <html>
      <body>
        <h1>Welcome, {visitor_name}!</h1>
        <p>Thank you for visiting our platform.</p>
      </body>
    </html>
    """
    return render_template_string(page_html)


@app.route("/api/v1/reports/generate", methods=["POST"])
def generate_report():
    """Generate a report from a user-defined template string. VULNERABLE to SSTI."""
    report_template = request.form.get("template_body", "")
    report_title = request.form.get("title", "Untitled Report")

    if not report_template:
        return jsonify({"error": "template_body is required"}), 400

    # VULNERABLE: render_template_string with user-supplied content
    full_template = "<h1>" + report_title + "</h1>" + report_template
    rendered = render_template_string(full_template)

    return rendered, 200, {"Content-Type": "text/html"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
