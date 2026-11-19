"""
Rule Engine — Layer 1 Pattern Detection
Detects common security vulnerabilities using regex pattern matching.
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass
from app.core.logging import get_logger

logger = get_logger("rule_engine")


@dataclass
class RuleFinding:
    rule_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    line: int
    file_name: str
    description: str
    category: str
    owasp: str
    matched_pattern: str


# ─── Rule Definitions ────────────────────────────────────────────────
RULES: List[Dict[str, Any]] = [
    # Backend Security
    {
        "id": "SQL_INJECTION",
        "type": "SQL Injection",
        "severity": "critical",
        "confidence": 85,
        "category": "Backend Security",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r"(?:execute|query|raw)\s*\(\s*f['\"]",
            r"(?:execute|query|raw)\s*\(\s*['\"][^'\"]{0,200}%s",
            r"(?:execute|query)\s*\(\s*[^)]{0,200}\+\s*(?:req|request|params|input|user)",
            r"\.format\s*\([^)]{0,200}(?:req|request|params)\)",
            r"cursor\.execute\s*\(\s*[f'\"][^'\"]{0,200}\{",
        ],
        "desc": "Potential SQL injection via string interpolation or concatenation",
    },
    {
        "id": "NOSQL_INJECTION",
        "type": "NoSQL Injection",
        "severity": "high",
        "confidence": 75,
        "category": "Backend Security",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r"\$where\s*:",
            r"\.find\(\s*\{[^}]{0,200}\$",
            r"eval\s*\([^)]{0,200}(?:req|request|body)",
        ],
        "desc": "NoSQL injection via unsanitized query operators",
    },
    {
        "id": "COMMAND_INJECTION",
        "type": "Command Injection",
        "severity": "critical",
        "confidence": 90,
        "category": "Backend Security",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r"(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|exec)\s*\(",
            r"child_process\.exec\s*\(",
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
            r"shell\s*=\s*True",
        ],
        "desc": "Potential command injection via system command execution",
    },
    {
        "id": "HARDCODED_CREDENTIALS",
        "type": "Hardcoded Credentials",
        "severity": "high",
        "confidence": 80,
        "category": "Backend Security",
        "owasp": "A07:2021 – Auth Failures",
        "patterns": [
            r"(?:password|passwd|secret|api_key|apikey|token|auth)\s*=\s*['\"][^'\"]{6,}['\"]",
            r"(?:AWS_SECRET|PRIVATE_KEY|DB_PASSWORD)\s*=\s*['\"][^'\"]+['\"]",
        ],
        "desc": "Sensitive credentials hardcoded in source code",
    },
    {
        "id": "JWT_MISUSE",
        "type": "JWT Security Issue",
        "severity": "high",
        "confidence": 75,
        "category": "Backend Security",
        "owasp": "A02:2021 – Cryptographic Failures",
        "patterns": [
            r"algorithms?\s*=\s*\[?\s*['\"]none['\"]",
            r"verify\s*=\s*False",
            r"verify_signature\s*=\s*False",
            r"jwt\.decode\([^)]{0,200}verify\s*=\s*False",
        ],
        "desc": "JWT verification disabled or algorithm set to 'none'",
    },
    {
        "id": "MISSING_AUTH",
        "type": "Missing Authentication",
        "severity": "medium",
        "confidence": 60,
        "category": "Backend Security",
        "owasp": "A01:2021 – Broken Access Control",
        "patterns": [
            r"@app\.(?:route|get|post|put|delete|patch)\s*\([^)]*\)\s*\n(?:(?![^\n]{0,200}(?:auth|login_required|jwt_required|Depends|Permission|protect|guard))[^\n]{0,200}\n){0,3}[^\n]{0,200}def\s+",
        ],
        "desc": "Route handler may lack authentication middleware",
    },
    {
        "id": "IDOR",
        "type": "Insecure Direct Object Reference",
        "severity": "high",
        "confidence": 65,
        "category": "Backend Security",
        "owasp": "A01:2021 – Broken Access Control",
        "patterns": [
            r"(?:params|query|request)\[?\.?(?:id|user_id|account_id)\]?",
            r"/(?:users?|accounts?|orders?)/\{?\w*id\w*\}?",
        ],
        "desc": "Direct object reference without ownership validation",
    },
    # Frontend Security
    {
        "id": "XSS",
        "type": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "confidence": 80,
        "category": "Frontend Security",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"dangerouslySetInnerHTML",
            r"v-html\s*=",
            r"\$\(\s*['\"][^'\"]{0,200}\)\.html\s*\(",
        ],
        "desc": "Potential XSS via unsafe HTML injection",
    },
    {
        "id": "EXPOSED_SECRETS_FE",
        "type": "Exposed Frontend Secrets",
        "severity": "critical",
        "confidence": 85,
        "category": "Frontend Security",
        "owasp": "A02:2021 – Cryptographic Failures",
        "patterns": [
            r"(?:const|let|var)\s+\w*(?:SECRET|PRIVATE|API_KEY)\w*\s*=\s*['\"]",
            r"(?:REACT_APP_|NEXT_PUBLIC_)\w*SECRET",
        ],
        "desc": "Secret or private key exposed in frontend code",
    },
    {
        "id": "INSECURE_STORAGE",
        "type": "Insecure Token Storage",
        "severity": "medium",
        "confidence": 70,
        "category": "Frontend Security",
        "owasp": "A04:2021 – Insecure Design",
        "patterns": [
            r"localStorage\.setItem\s*\(\s*['\"](?:token|jwt|access_token|auth)",
            r"sessionStorage\.setItem\s*\(\s*['\"](?:token|jwt|access_token|auth)",
        ],
        "desc": "Authentication tokens stored in browser storage (vulnerable to XSS)",
    },
    # Config & Infra
    {
        "id": "ENV_EXPOSED",
        "type": "Exposed Environment File",
        "severity": "critical",
        "confidence": 90,
        "category": "Config & Infra",
        "owasp": "A05:2021 – Security Misconfiguration",
        "patterns": [
            r"(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET)\s*=\s*\S+",
        ],
        "desc": "Sensitive environment variables exposed in config files",
    },
    {
        "id": "OPEN_CORS",
        "type": "Open CORS Configuration",
        "severity": "medium",
        "confidence": 80,
        "category": "Config & Infra",
        "owasp": "A05:2021 – Security Misconfiguration",
        "patterns": [
            r"(?:Access-Control-Allow-Origin|cors)\s*[=:]\s*['\"]?\*['\"]?",
            r"allow_origins\s*=\s*\[\s*['\"]?\*['\"]?\s*\]",
        ],
        "desc": "CORS allows all origins, enabling cross-origin attacks",
    },
    {
        "id": "DEBUG_ENABLED",
        "type": "Debug Mode Enabled",
        "severity": "medium",
        "confidence": 85,
        "category": "Config & Infra",
        "owasp": "A05:2021 – Security Misconfiguration",
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"debug\s*:\s*true",
            r"NODE_ENV\s*=\s*['\"]?development",
        ],
        "desc": "Application running in debug mode in production config",
    },
    {
        "id": "DOCKER_MISCONFIG",
        "type": "Docker Security Misconfiguration",
        "severity": "medium",
        "confidence": 75,
        "category": "Config & Infra",
        "owasp": "A05:2021 – Security Misconfiguration",
        "patterns": [
            r"(?:USER\s+root|--privileged)",
            r"COPY\s+\.\s+\.",
            r"ADD\s+https?://",
        ],
        "desc": "Docker container running as root or with unsafe directives",
    },
    {
        "id": "WEAK_CRYPTO",
        "type": "Weak Cryptography",
        "severity": "high",
        "confidence": 80,
        "category": "Backend Security",
        "owasp": "A02:2021 – Cryptographic Failures",
        "patterns": [
            r"(?:md5|sha1)\s*\(",
            r"DES\.\w+",
            r"RC4",
            r"Math\.random\s*\(\s*\)[^;]{0,200}(?:token|key|secret|password)",
        ],
        "desc": "Use of weak or deprecated cryptographic algorithms",
    },
    # Dependency Risk
    {
        "id": "KNOWN_VULN_DEP",
        "type": "Dependency Vulnerability Risk",
        "severity": "medium",
        "confidence": 60,
        "category": "Dependency Risk",
        "owasp": "A06:2021 – Vulnerable Components",
        "patterns": [
            r"\"(?:lodash|moment|request|express|django|flask|spring-boot)\":\s*\"[<>=~^]*[0-3]\.",
        ],
        "desc": "Potentially outdated dependency with known security issues",
    },
    # API Security
    {
        "id": "MISSING_RATE_LIMIT",
        "type": "Missing Rate Limiting",
        "severity": "medium",
        "confidence": 55,
        "category": "API Security",
        "owasp": "A04:2021 – Insecure Design",
        "patterns": [
            r"@app\.(?:post|put|patch)\s*\(\s*['\"]/?(?:auth|login|register|signup|password)",
        ],
        "desc": "Authentication endpoint without rate limiting",
    },
    {
        "id": "SSRF",
        "type": "Server-Side Request Forgery",
        "severity": "high",
        "confidence": 70,
        "category": "API Security",
        "owasp": "A10:2021 – SSRF",
        "patterns": [
            r"(?:requests\.get|fetch|axios|httpx|urllib)\s*\(\s*(?:req|request|params|body|input|user)",
            r"(?:requests\.get|fetch|axios|httpx|urllib)\s*\(\s*f['\"]",
        ],
        "desc": "User-controlled URL passed to HTTP client (potential SSRF)",
    },
]


def scan_chunk(content: str, file_name: str) -> List[RuleFinding]:
    """Scan a code chunk against all rules."""
    findings: List[RuleFinding] = []
    lines = content.split("\n")

    for rule in RULES:
        for pattern in rule["patterns"]:
            try:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(RuleFinding(
                            rule_id=rule["id"],
                            vulnerability_type=rule["type"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            line=i,
                            file_name=file_name,
                            description=rule["desc"],
                            category=rule["category"],
                            owasp=rule["owasp"],
                            matched_pattern=pattern,
                        ))
            except re.error as e:
                logger.error("regex_error", rule=rule["id"], pattern=pattern, error=str(e))

    logger.debug("chunk_scanned", file=file_name, findings=len(findings))
    return findings


def scan_all_chunks(chunks: list) -> List[RuleFinding]:
    """Run rule engine across all chunks."""
    all_findings = []
    for chunk in chunks:
        findings = scan_chunk(chunk.content, chunk.file_name)
        all_findings.extend(findings)
    logger.info("rule_scan_complete", total_findings=len(all_findings))
    return all_findings
