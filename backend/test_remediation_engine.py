"""Validation tests for the Remediation Engine."""

import sys
import json
import time
from engine.models import EngineFinding
from engine.remediation_engine import (
    apply_remediation,
    generate_fix,
    get_remediation_report,
    get_supported_cwe_list,
    get_supported_languages,
    _detect_language,
    _detect_frameworks,
    _resolve_cwe,
)


def make_finding(**kwargs):
    defaults = dict(
        rule_id="TEST-001",
        rule_title="Test Finding",
        vulnerability_type="test",
        severity="Medium",
        confidence=75.0,
        file_name="app/views.py",
        line=10,
        description="Test",
        category="Backend Security",
        owasp="A01",
        cwe="CWE-89",
        matched_pattern="test",
        code_snippet="",
        impact="Low",
        remediation="Fix it",
        requires_ai_validation=False,
        severity_weight=5,
        exploitability_score="Medium",
        detection_id="",
    )
    defaults.update(kwargs)
    f = EngineFinding(**defaults)
    if not f.detection_id:
        f.detection_id = f"{f.rule_id}_{f.file_name}_{f.line}"
    return f


def test_empty():
    result = apply_remediation([])
    assert result == []
    print("  [PASS] Empty findings → empty result")


def test_sqli_python():
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="app/views.py",
        vulnerability_type="SQL Injection",
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    )
    fix = generate_fix(f)
    assert "parameterized" in fix["fix_explanation"].lower() or "parameter" in fix["secure_fix"].lower()
    assert fix["confidence"] >= 85
    assert "vulnerable_code" in fix
    assert "secure_fix" in fix
    assert "security_principle" in fix
    assert "best_practice" in fix
    print(f"  [PASS] SQLi/Python fix generated (confidence={fix['confidence']})")


def test_sqli_java():
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="UserController.java",
        vulnerability_type="SQL Injection",
    )
    fix = generate_fix(f)
    assert "PreparedStatement" in fix["secure_fix"]
    print(f"  [PASS] SQLi/Java fix → PreparedStatement (confidence={fix['confidence']})")


def test_sqli_javascript():
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="routes/users.js",
        vulnerability_type="SQL Injection",
    )
    fix = generate_fix(f)
    assert "?" in fix["secure_fix"] or "parameterized" in fix["fix_explanation"].lower()
    print(f"  [PASS] SQLi/JavaScript fix generated (confidence={fix['confidence']})")


def test_sqli_go():
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="handlers/user.go",
        vulnerability_type="SQL Injection",
    )
    fix = generate_fix(f)
    assert "$1" in fix["secure_fix"]
    print(f"  [PASS] SQLi/Go fix → $1 placeholder (confidence={fix['confidence']})")


def test_xss_python():
    f = make_finding(
        rule_id="XSS-001", cwe="CWE-79",
        file_name="templates/views.py",
        vulnerability_type="Cross-Site Scripting",
    )
    fix = generate_fix(f)
    assert "escape" in fix["secure_fix"].lower() or "encode" in fix["fix_explanation"].lower()
    print(f"  [PASS] XSS/Python fix generated (confidence={fix['confidence']})")


def test_cmdi_python():
    f = make_finding(
        rule_id="CMD-EXEC-001", cwe="CWE-78",
        file_name="utils/convert.py",
        vulnerability_type="Command Injection",
    )
    fix = generate_fix(f)
    assert "subprocess" in fix["secure_fix"].lower() or "shell=False" in fix["secure_fix"]
    print(f"  [PASS] CmdI/Python fix → subprocess (confidence={fix['confidence']})")


def test_path_traversal():
    f = make_finding(
        rule_id="PT-001", cwe="CWE-22",
        file_name="api/download.py",
        vulnerability_type="Path Traversal",
    )
    fix = generate_fix(f)
    assert "realpath" in fix["secure_fix"].lower() or "canonicalize" in fix["secure_fix"].lower()
    print(f"  [PASS] PathTrav/Python fix generated (confidence={fix['confidence']})")


def test_deserialization():
    f = make_finding(
        rule_id="DESER-001", cwe="CWE-502",
        file_name="data/loader.py",
        vulnerability_type="Unsafe Deserialization",
    )
    fix = generate_fix(f)
    assert "json" in fix["secure_fix"].lower()
    print(f"  [PASS] Deserialization/Python fix → JSON (confidence={fix['confidence']})")


def test_weak_crypto():
    f = make_finding(
        rule_id="CRYPTO-001", cwe="CWE-327",
        file_name="auth/password.py",
        vulnerability_type="Weak Cryptography",
    )
    fix = generate_fix(f)
    assert "bcrypt" in fix["secure_fix"].lower()
    print(f"  [PASS] WeakCrypto/Python fix → bcrypt (confidence={fix['confidence']})")


def test_hardcoded_secrets():
    f = make_finding(
        rule_id="SECRET-001", cwe="CWE-798",
        file_name="config/settings.py",
        vulnerability_type="Hardcoded Secret",
    )
    fix = generate_fix(f)
    assert "environ" in fix["secure_fix"].lower() or "env" in fix["secure_fix"].lower()
    print(f"  [PASS] HardcodedSecret/Python fix → env vars (confidence={fix['confidence']})")


def test_ssrf():
    f = make_finding(
        rule_id="SSRF-001", cwe="CWE-918",
        file_name="proxy/forward.py",
        vulnerability_type="SSRF",
    )
    fix = generate_fix(f)
    assert "allowlist" in fix["secure_fix"].lower() or "ALLOWED" in fix["secure_fix"]
    print(f"  [PASS] SSRF/Python fix → allowlist (confidence={fix['confidence']})")


def test_auth_bypass():
    f = make_finding(
        rule_id="AUTH-001", cwe="CWE-287",
        file_name="routes/admin.py",
        vulnerability_type="Authentication Bypass",
    )
    fix = generate_fix(f)
    assert "login_required" in fix["secure_fix"] or "authenticated" in fix["secure_fix"].lower()
    print(f"  [PASS] AuthBypass/Python fix (confidence={fix['confidence']})")


def test_framework_django():
    src = 'from django.db import connection\ncursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="app/views.py",
        code_snippet=src,
    )
    fix = generate_fix(f, file_content=src)
    assert "django" in fix["secure_fix"].lower() or "ORM" in fix["secure_fix"] or "objects" in fix["secure_fix"]
    print(f"  [PASS] Django framework override applied (confidence={fix['confidence']})")


def test_framework_express():
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="routes/api.js",
        code_snippet='const express = require("express");\ndb.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
    )
    fix = generate_fix(f)
    assert "?" in fix["secure_fix"] or "param" in fix["secure_fix"].lower()
    print(f"  [PASS] Express framework context detected (confidence={fix['confidence']})")


def test_framework_spring():
    src = 'import org.springframework.web.bind.annotation.*;\nstatement.executeQuery("SELECT * FROM users WHERE id=" + id)'
    f = make_finding(
        rule_id="SQLI-001", cwe="CWE-89",
        file_name="UserController.java",
        code_snippet=src,
    )
    fix = generate_fix(f, file_content=src)
    assert "Spring" in fix["secure_fix"] or "JPA" in fix["secure_fix"] or "Repository" in fix["secure_fix"]
    print(f"  [PASS] Spring framework override applied (confidence={fix['confidence']})")


def test_terraform_secrets():
    f = make_finding(
        rule_id="SECRET-001", cwe="CWE-798",
        file_name="infrastructure/main.tf",
        vulnerability_type="Hardcoded Secret",
    )
    fix = generate_fix(f)
    assert "variable" in fix["secure_fix"].lower() or "var." in fix["secure_fix"]
    print(f"  [PASS] Terraform fix → sensitive variables (confidence={fix['confidence']})")


def test_dockerfile_secrets():
    f = make_finding(
        rule_id="SECRET-001", cwe="CWE-798",
        file_name="Dockerfile",
        vulnerability_type="Hardcoded Secret",
    )
    fix = generate_fix(f)
    assert "secret" in fix["secure_fix"].lower() or "runtime" in fix["secure_fix"].lower()
    print(f"  [PASS] Dockerfile fix → secrets mount (confidence={fix['confidence']})")


def test_kubernetes_secrets():
    f = make_finding(
        rule_id="SECRET-001", cwe="CWE-798",
        file_name="deploy/app.yaml",
        vulnerability_type="Hardcoded Secret",
    )
    fix = generate_fix(f)
    assert "secretKeyRef" in fix["secure_fix"] or "Secret" in fix["secure_fix"]
    print(f"  [PASS] K8s YAML fix → secretKeyRef (confidence={fix['confidence']})")


def test_rule_id_fallback():
    """CWE missing — should resolve from rule_id prefix."""
    f = make_finding(
        rule_id="SQLI-CONCAT-005", cwe="",
        file_name="query.py",
    )
    fix = generate_fix(f)
    assert fix["confidence"] >= 80
    assert "parameterized" in fix["fix_explanation"].lower() or "parameter" in fix["secure_fix"].lower()
    print(f"  [PASS] Rule-ID fallback: SQLI prefix → CWE-89 fix (confidence={fix['confidence']})")


def test_unknown_vuln():
    """Unknown vuln type should produce generic fix."""
    f = make_finding(
        rule_id="CUSTOM-001", cwe="CWE-999",
        file_name="app.py",
        vulnerability_type="Custom Vulnerability",
        remediation="Apply custom fix",
    )
    fix = generate_fix(f)
    assert fix["confidence"] == 50
    assert "secure coding" in fix["best_practice"].lower() or "validate" in fix["best_practice"].lower()
    print(f"  [PASS] Unknown vuln → generic guidance (confidence={fix['confidence']})")


def test_apply_remediation_enriches():
    """apply_remediation should attach remediation_fix attr."""
    findings = [
        make_finding(rule_id="SQLI-001", cwe="CWE-89", detection_id="ar1"),
        make_finding(rule_id="XSS-001", cwe="CWE-79", detection_id="ar2"),
        make_finding(rule_id="CMD-001", cwe="CWE-78", detection_id="ar3"),
    ]
    result = apply_remediation(findings)
    assert len(result) == 3
    for f in result:
        assert hasattr(f, "remediation_fix"), "Finding should have remediation_fix attr"
        fix = f.remediation_fix
        assert "vulnerable_code" in fix
        assert "secure_fix" in fix
        assert "confidence" in fix
    print(f"  [PASS] apply_remediation enriched {len(result)} findings with fixes")


def test_remediation_report():
    """get_remediation_report returns list of dicts."""
    findings = [
        make_finding(rule_id="SQLI-001", cwe="CWE-89", detection_id="rr1"),
    ]
    report = get_remediation_report(findings)
    assert len(report) == 1
    entry = report[0]
    assert "vulnerable_code" in entry
    assert "secure_fix" in entry
    assert "rule_id" in entry
    assert "severity" in entry
    print(f"  [PASS] Remediation report: {len(report)} entries")


def test_json_serializable():
    """Fix output must be JSON-serializable."""
    f = make_finding(rule_id="SQLI-001", cwe="CWE-89")
    fix = generate_fix(f)
    json_str = json.dumps(fix, indent=2)
    parsed = json.loads(json_str)
    assert parsed["confidence"] >= 80
    print(f"  [PASS] JSON serialization OK ({len(json_str)} bytes)")


def test_supported_coverage():
    cwes = get_supported_cwe_list()
    langs = get_supported_languages()
    assert len(cwes) >= 15
    assert len(langs) >= 12
    print(f"  [PASS] Coverage: {len(cwes)} CWEs × {len(langs)} languages")


def test_performance():
    """Remediation must be under 5ms per finding on average."""
    findings = [
        make_finding(
            rule_id=f"SQLI-{i}", cwe="CWE-89",
            file_name=f"app/module{i}.py",
            detection_id=f"perf_{i}",
            code_snippet=f'cursor.execute(f"SELECT * FROM t WHERE id = {{v{i}}}")',
        )
        for i in range(500)
    ]
    start = time.perf_counter()
    apply_remediation(findings)
    elapsed_ms = (time.perf_counter() - start) * 1000
    per_finding = elapsed_ms / len(findings)
    assert per_finding < 5.0, f"Too slow: {per_finding:.2f}ms per finding"
    print(f"  [PASS] Performance: {elapsed_ms:.1f}ms total, {per_finding:.3f}ms per finding ({len(findings)} findings)")


def test_language_detection():
    assert _detect_language("app.py") == "python"
    assert _detect_language("App.java") == "java"
    assert _detect_language("index.ts") == "typescript"
    assert _detect_language("main.go") == "go"
    assert _detect_language("deploy.tf") == "terraform"
    assert _detect_language("Dockerfile") == "dockerfile"
    assert _detect_language("chart.yaml") == "yaml"
    assert _detect_language("handler.rs") == "rust"
    assert _detect_language("Controller.kt") == "kotlin"
    assert _detect_language("unknown.xyz") == "generic"
    print("  [PASS] Language detection: 10/10 correct")


def test_framework_detection():
    fws = _detect_frameworks("from django.db import models")
    assert "django" in fws
    fws = _detect_frameworks('const express = require("express")')
    assert "express" in fws
    fws = _detect_frameworks("import org.springframework.web.bind.annotation.*")
    assert "spring" in fws
    print("  [PASS] Framework detection: Django, Express, Spring")


def test_determinism():
    f = make_finding(rule_id="SQLI-001", cwe="CWE-89")
    fix1 = json.dumps(generate_fix(f), sort_keys=True)
    fix2 = json.dumps(generate_fix(f), sort_keys=True)
    assert fix1 == fix2
    print("  [PASS] Deterministic output verified")


def test_output_format():
    """Verify output matches required schema."""
    f = make_finding(rule_id="SQLI-001", cwe="CWE-89")
    fix = generate_fix(f)
    required_keys = {"vulnerable_code", "secure_fix", "fix_explanation",
                     "security_principle", "best_practice", "confidence"}
    assert required_keys == set(fix.keys()), f"Missing keys: {required_keys - set(fix.keys())}"
    assert isinstance(fix["confidence"], int)
    assert 0 <= fix["confidence"] <= 100
    print("  [PASS] Output format matches specification")


def test_all_major_cwes():
    """Every CWE in the registry should produce a non-generic Python fix."""
    major_cwes = ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502",
                  "CWE-327", "CWE-798", "CWE-918", "CWE-287"]
    for cwe in major_cwes:
        f = make_finding(rule_id=f"TEST-{cwe}", cwe=cwe, file_name="app.py")
        fix = generate_fix(f)
        assert fix["confidence"] >= 80, f"{cwe}: confidence too low ({fix['confidence']})"
    print(f"  [PASS] All {len(major_cwes)} major CWEs produce high-confidence Python fixes")


def main():
    print("=" * 60)
    print("REMEDIATION ENGINE — VALIDATION TESTS")
    print("=" * 60)
    tests = [
        ("Empty input", test_empty),
        ("SQLi/Python", test_sqli_python),
        ("SQLi/Java", test_sqli_java),
        ("SQLi/JavaScript", test_sqli_javascript),
        ("SQLi/Go", test_sqli_go),
        ("XSS/Python", test_xss_python),
        ("CmdI/Python", test_cmdi_python),
        ("Path Traversal", test_path_traversal),
        ("Deserialization", test_deserialization),
        ("Weak Crypto", test_weak_crypto),
        ("Hardcoded Secrets", test_hardcoded_secrets),
        ("SSRF", test_ssrf),
        ("Auth Bypass", test_auth_bypass),
        ("Django framework", test_framework_django),
        ("Express framework", test_framework_express),
        ("Spring framework", test_framework_spring),
        ("Terraform secrets", test_terraform_secrets),
        ("Dockerfile secrets", test_dockerfile_secrets),
        ("K8s YAML secrets", test_kubernetes_secrets),
        ("Rule-ID fallback", test_rule_id_fallback),
        ("Unknown vuln", test_unknown_vuln),
        ("apply_remediation", test_apply_remediation_enriches),
        ("Remediation report", test_remediation_report),
        ("JSON serializable", test_json_serializable),
        ("Supported coverage", test_supported_coverage),
        ("Performance (<5ms)", test_performance),
        ("Language detection", test_language_detection),
        ("Framework detection", test_framework_detection),
        ("Determinism", test_determinism),
        ("Output format", test_output_format),
        ("All major CWEs", test_all_major_cwes),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            print(f"\n[TEST] {name}")
            fn()
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print(f"{'=' * 60}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
