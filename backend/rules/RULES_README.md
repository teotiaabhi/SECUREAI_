# SecureAI — Security Rules Engine Reference

> **Version:** 4.0 &nbsp;|&nbsp; **Last Updated:** March 2026 &nbsp;|&nbsp; **Total Rules:** 1,014 &nbsp;|&nbsp; **Languages:** 38 &nbsp;|&nbsp; **Categories:** 11

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Rule Schema](#rule-schema)
4. [Detection Categories](#detection-categories)
   - [Injection (INJ)](#1-injection)
   - [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
   - [Authentication & Authorization (AUTH)](#3-authentication--authorization)
   - [Cryptographic Failures (CRYPTO)](#4-cryptographic-failures)
   - [Insecure Deserialization (DESER)](#5-insecure-deserialization)
   - [Remote Code Execution (RCE)](#6-remote-code-execution)
   - [Server-Side Request Forgery (SSRF)](#7-server-side-request-forgery)
   - [Path Traversal (PT)](#8-path-traversal)
   - [Secrets & Credential Exposure (SEC)](#9-secrets--credential-exposure)
   - [Framework Security Misconfiguration (FW)](#10-framework-security-misconfiguration)
   - [DevOps & Infrastructure (DEVOPS)](#11-devops--infrastructure)
5. [Supported Languages & Frameworks](#supported-languages--frameworks)
6. [OWASP Top 10 (2021) Coverage](#owasp-top-10-2021-coverage)
7. [CWE Coverage Matrix](#cwe-coverage-matrix)
8. [Rule Loading Pipeline](#rule-loading-pipeline)
9. [Severity Model](#severity-model)
10. [False Positive Mitigation](#false-positive-mitigation)
11. [Contributing New Rules](#contributing-new-rules)
12. [File Inventory](#file-inventory)

---

## Overview

The SecureAI Rules Engine is a static analysis rule corpus designed for multi-language security scanning. Rules are authored as declarative YAML definitions and loaded at runtime by the scanning engine. Each rule encodes domain-expert knowledge about vulnerability patterns, including regex-based detection, false-positive suppression via anti-patterns, bypass variant awareness, taint path modeling, and actionable remediation guidance.

### Key Capabilities

| Capability | Description |
|:-----------|:------------|
| **Multi-Language** | 38 languages — Python, Java, JavaScript, TypeScript, Go, C#, PHP, Ruby, Rust, Kotlin, Swift, C/C++, Shell, SQL, YAML, Dockerfile, and universal cross-language rules |
| **Standards Mapping** | Every rule maps to OWASP Top 10 (2021) and CWE identifiers for compliance reporting |
| **Context-Aware** | Anti-patterns suppress false positives from test files, environment variable usage, ORM query builders, and known-safe patterns |
| **Bypass-Aware** | Rules encode known evasion techniques — encoding variants, obfuscation, protocol smuggling, DNS rebinding, etc. |
| **AI-Augmented** | High-severity findings can be flagged for secondary AI validation to further reduce false positives |
| **Scoring** | Weighted severity scoring with exploitability modifiers produces a composite security score per scan |

---

## Architecture

```
backend/rules/
├── auth/                  # Authentication & authorization misconfigurations
│   ├── csharp.yaml
│   ├── go.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── php.yaml
│   ├── python.yaml
│   ├── enterprise_auth.yaml         # JWT, OAuth, SAML, IDOR, race conditions
│   └── business_logic_enterprise.yaml # Rate limiting, payment logic, workflow bypass
├── crypto/                # Weak cryptography & hash algorithm misuse
│   ├── csharp.yaml
│   ├── go.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── php.yaml
│   ├── python.yaml
│   └── universal.yaml
├── deserialization/       # Insecure deserialization leading to RCE
│   ├── csharp.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── php.yaml
│   ├── python.yaml
│   ├── universal.yaml
│   └── enterprise_deserialization.yaml  # XMLDecoder, SnakeYAML, .NET formatters
├── devops/                # Kubernetes, Docker, Helm, CI/CD, cloud, supply chain
│   ├── yaml.yaml
│   ├── advanced_detection.yaml       # CI/CD injection, GitHub Actions, Terraform, Helm, serverless
│   ├── cloud_security_enterprise.yaml # AWS IAM, S3, K8s RBAC, Docker
│   └── supply_chain_enterprise.yaml  # Dependency confusion, lockfile tampering
├── framework_misuse/      # Web framework security misconfigurations
│   ├── aspnet.yaml
│   ├── express_nextjs.yaml
│   ├── flask_django.yaml
│   ├── gin_echo.yaml
│   ├── laravel_symfony.yaml
│   └── spring.yaml
├── injection/             # SQL, command, code, template, LDAP, NoSQL injection
│   ├── cpp.yaml
│   ├── csharp.yaml
│   ├── go.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── php.yaml
│   ├── python.yaml
│   ├── ruby.yaml
│   ├── rust_kotlin_swift.yaml
│   ├── shell.yaml
│   ├── sql.yaml
│   ├── typescript.yaml
│   └── enterprise_injection.yaml     # NoSQL, LDAP, XPath, GraphQL, SSTI, CRLF
├── path_traversal/        # Directory traversal & file inclusion
│   ├── go.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── php.yaml
│   ├── python.yaml
│   └── universal.yaml
├── rce/                   # Remote code execution
│   ├── go.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── python.yaml
│   └── universal.yaml
├── secrets/               # Hardcoded credentials & API key exposure
│   └── universal.yaml
├── ssrf/                  # Server-side request forgery
│   ├── go.yaml
│   ├── java.yaml
│   ├── javascript.yaml
│   ├── python.yaml
│   └── universal.yaml
└── xss/                   # Cross-site scripting (reflected, stored, DOM)
    ├── javascript.yaml
    ├── php.yaml
    └── universal.yaml
```

Rules are organized in a `{category}/{language}.yaml` hierarchy. Files named `universal.yaml` contain cross-language rules that apply to all scans regardless of the target language.

---

## Rule Schema

Every rule follows a standardized YAML schema. Below is the canonical field reference:

```yaml
rules:
  - rule_id: "INJ-PY-001"                    # Unique identifier (CATEGORY-LANG-NNN)
    title: "SQL Injection via String Formatting"
    description: >
      Detailed description of the vulnerability pattern,
      including attack impact and exploitation context.
    language: "python"                         # Target language
    category: "injection"                      # Detection category
    severity: "critical"                       # critical | high | medium | low | info
    confidence: 0.85                           # 0.0–1.0 detection confidence score

    # Standards Mapping
    cwe: "CWE-89"
    owasp: "A03:2021"
    tags: ["sql-injection", "owasp-top-10", "cwe-89"]

    # Detection Patterns (regex)
    patterns:
      - type: "regex"
        pattern: 'cursor\.execute\s*\(\s*f["\']'
        description: "f-string interpolation in cursor.execute()"
      - type: "regex"
        pattern: 'cursor\.execute\s*\(\s*["\'].*%s'
        description: "% formatting in SQL query"
    regex_flags: ["IGNORECASE", "MULTILINE"]   # Optional flag override

    # False Positive Suppression
    anti_patterns:
      - "cursor.execute(query, params)"        # Parameterized query
      - "# nosec"                              # Developer override
      - "test_"                                # Test file context

    # Bypass Variant Awareness
    bypass_variants:
      - description: "Double URL encoding"
        pattern: '%2527'
      - description: "Unicode normalization"
        pattern: '\u0027'

    # Taint Analysis Hooks
    probable_taint_paths:
      - source: "request.args"
        through: ["string.format", "f-string"]
        sink: "cursor.execute"

    # Severity Scoring
    severity_scoring:
      severity_weight: 9
      exploitability_score: "High"

    # Cross-Rule Intelligence
    cross_rule_intelligence:
      requires_ai_validation: false
      related_rules:
        - rule_id: "INJ-PY-013"

    # Actionable Guidance
    impact: >
      Successful exploitation enables unauthorized data access,
      data modification, and potential database takeover.
    remediation:
      steps:
        - "Use parameterized queries with placeholder syntax"
        - "Employ ORM query builders (Django ORM, SQLAlchemy)"
        - "Apply input validation and type checking"
    exploit_scenario: >
      Attacker supplies ' OR 1=1-- as input to login form,
      bypassing authentication via SQL injection.

    # Context Awareness
    context_awareness:
      surrounding_code_check: true
      taint_source_indicators: ["request", "input", "argv"]
      sanitization_patterns: ["parameterized", "prepared"]
```

### Required Fields

| Field | Type | Description |
|:------|:-----|:------------|
| `rule_id` | `string` | Unique identifier in `CATEGORY-LANG-NNN` format |
| `title` | `string` | Human-readable vulnerability name |
| `language` | `string` | Target language (`python`, `java`, `javascript`, `all`, etc.) |
| `category` | `string` | Detection category (maps to DB category via `CATEGORY_MAP`) |
| `severity` | `string` | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `patterns` | `list` | One or more regex detection patterns |

### Optional Fields

| Field | Type | Description |
|:------|:-----|:------------|
| `confidence` | `float` | Detection confidence (0.0–1.0, default: 0.5) |
| `cwe` | `string` | CWE identifier for compliance mapping |
| `owasp` | `string` | OWASP Top 10 (2021) reference |
| `tags` | `list` | Searchable tags for filtering and grouping |
| `anti_patterns` | `list` | Patterns indicating safe usage (suppresses false positives) |
| `bypass_variants` | `list` | Known evasion techniques the rule accounts for |
| `impact` | `string/dict` | Description of exploitation consequences |
| `remediation` | `string/dict/list` | Step-by-step fix guidance |
| `severity_scoring` | `dict` | `severity_weight` (1–10) + `exploitability_score` |
| `cross_rule_intelligence` | `dict` | AI validation flag + related rule links |
| `context_awareness` | `dict` | Taint indicators, sanitization patterns, surrounding code checks |

---

## Detection Categories

### 1. Injection

**Directory:** `rules/injection/` &nbsp;|&nbsp; **Files:** 13 &nbsp;|&nbsp; **Rules:** ~218 &nbsp;|&nbsp; **CWE:** CWE-78, CWE-89, CWE-90, CWE-94, CWE-113, CWE-134, CWE-502, CWE-611, CWE-643, CWE-917, CWE-943, CWE-1333 &nbsp;|&nbsp; **OWASP:** A03:2021

The largest and most diverse rule category, covering all injection vectors across 12 language-specific files.

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **SQL Injection** | String concatenation/formatting in SQL queries, UNION-based, blind boolean/time-based, stacked queries, ORDER BY injection | `PY-INJ-001`, `SQL-INJ-001`–`010`, `JS-INJ-001` |
| **Command Injection** | `os.system()`, `subprocess` with `shell=True`, backtick substitution, unquoted variable expansion | `PY-INJ-002`, `PY-INJ-015`, `SHELL-INJ-001`–`010` |
| **Code Injection** | `eval()`, `exec()`, server-side template injection (SSTI), dynamic code compilation | `PY-INJ-003`, `PY-INJ-004` |
| **XML External Entity (XXE)** | Parsing untrusted XML without disabling external entities | `PY-INJ-005` |
| **NoSQL Injection** | MongoDB/DynamoDB query injection via unsanitized operators | `PY-INJ-008` |
| **XPath Injection** | User input in XPath expressions via `lxml`/`ElementTree` | `PY-INJ-009` |
| **LDAP Injection** | Unsanitized input in LDAP query filters | `PY-INJ-014` |
| **CRLF / Header Injection** | HTTP header manipulation via `\r\n` injection | `PY-INJ-011` |
| **Format String** | `str.format()` with user-controlled format strings | `PY-INJ-010` |
| **ReDoS** | Regular expression denial of service via catastrophic backtracking | `PY-INJ-012` |
| **GraphQL Injection** | Unsanitized inputs in GraphQL resolvers (field injection, nested queries) | `INJ-GQL-JS-001`, `INJ-GQL-PY-001` |
| **Template Injection (SSTI)** | Server-side template injection in Jinja2, Mako, Freemarker, Pebble, EJS, Pug | `INJ-SSTI-PY-001`, `INJ-SSTI-JAVA-001`, `INJ-SSTI-JS-001` |

**Languages covered:** Python, Java, JavaScript, TypeScript, Go, C#, PHP, Ruby, Rust, Kotlin, Swift, C/C++, Shell, SQL

---

### 2. Cross-Site Scripting (XSS)

**Directory:** `rules/xss/` &nbsp;|&nbsp; **Files:** 3 &nbsp;|&nbsp; **Rules:** ~18 &nbsp;|&nbsp; **CWE:** CWE-79 &nbsp;|&nbsp; **OWASP:** A03:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **DOM-based XSS** | `innerHTML`, `document.write()`, `outerHTML` with user-controlled data | `XSS-JS-001`, `XSS-JS-002` |
| **React XSS** | `dangerouslySetInnerHTML` with unsanitized props/state | `XSS-JS-003`, `XSS-REACT-001` |
| **Vue XSS** | `v-html` directive on unsanitized variables | `XSS-JS-004` |
| **Angular XSS** | `bypassSecurityTrust*` on untrusted input | `XSS-JS-005` |
| **Stored XSS** | Database content rendered without output encoding | `XSS-JS-006`, `XSS-PHP-005` |
| **Reflected XSS** | Express `res.send()` reflecting request parameters | `XSS-JS-007` |
| **jQuery XSS** | `.html()`, selector injection, `$.parseHTML()` abuse | `XSS-JS-008` |
| **PHP XSS** | `echo`/`print` of `$_GET`/`$_POST` without `htmlspecialchars()` | `XSS-PHP-001`–`006` |
| **Template XSS** | Jinja2 `|safe` filter, `Markup()`, disabled autoescaping | `XSS-PY-001` |

**Languages covered:** JavaScript/TypeScript (React, Vue, Angular, jQuery), PHP (Laravel, WordPress, Symfony), Python (Jinja2, Django)

---

### 3. Authentication & Authorization

**Directory:** `rules/auth/` &nbsp;|&nbsp; **Files:** 8 &nbsp;|&nbsp; **Rules:** ~178 &nbsp;|&nbsp; **CWE:** CWE-20, CWE-287, CWE-306, CWE-307, CWE-352, CWE-362, CWE-639, CWE-798, CWE-799, CWE-841 &nbsp;|&nbsp; **OWASP:** A01:2021, A04:2021, A07:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **Hardcoded Secrets** | SECRET_KEY, JWT signing keys, API keys embedded in source code | `AUTH-PY-001`, `AUTH-JS-001` |
| **Missing Authentication** | Endpoints without auth middleware, anonymous access to sensitive routes | `AUTH-JAVA-001` |
| **Security Misconfig** | `permitAll` on sensitive endpoints, disabled CSRF, misconfigured OAuth | `AUTH-JAVA-002`–`010` |
| **Weak Password Policy** | Missing password hashing, plaintext credential storage | `AUTH-PY-005` |
| **JWT Bypass** | Algorithm none, RS256/HS256 confusion, weak signing secrets | `AUTH-JWT-001`, `AUTH-JWT-002`, `AUTH-JWT-003` |
| **OAuth Misconfiguration** | Open redirect_uri, missing state parameter | `AUTH-OAUTH-001`, `AUTH-OAUTH-002` |
| **SAML Bypass** | Signature validation bypass, XML wrapping attacks | `AUTH-SAML-001` |
| **Session Security** | Session fixation, missing cookie security flags | `AUTH-SESS-001`, `AUTH-SESS-002` |
| **IDOR** | Missing ownership checks, mass assignment | `AUTH-IDOR-001`, `AUTH-IDOR-002` |
| **Race Conditions** | TOCTOU in financial/state-changing operations | `AUTH-RACE-001`, `AUTH-RACE-002` |
| **Rate Limiting** | Missing rate limiting on login/OTP endpoints | `BIZ-RATE-001`, `BIZ-RATE-002` |
| **Payment Logic** | Client-controlled prices, negative quantity bypass | `BIZ-PAY-001`, `BIZ-PAY-002`, `BIZ-PAY-003` |
| **Workflow Bypass** | Step skipping, missing state validation, coupon replay | `BIZ-FLOW-001`, `BIZ-FLOW-002`, `BIZ-FLOW-003` |

**Languages covered:** Python (Django, Flask, FastAPI), Java (Spring Security), JavaScript (Express, Passport), Go, C#, PHP (Laravel)

---

### 4. Cryptographic Failures

**Directory:** `rules/crypto/` &nbsp;|&nbsp; **Files:** 7 &nbsp;|&nbsp; **Rules:** ~50 &nbsp;|&nbsp; **CWE:** CWE-327, CWE-328 &nbsp;|&nbsp; **OWASP:** A02:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **Weak Hash Algorithms** | MD5, SHA-1 used for security purposes (authentication, integrity) | `CRYPTO-PY-001` |
| **Broken Encryption** | DES, RC4, ECB mode, insufficient key length | `CRYPTO-PY-003` |
| **Weak Password Hashing** | SHA-256 for password storage instead of bcrypt/argon2/scrypt | `CRYPTO-PY-004` |
| **Insecure Random** | `random.random()` / `Math.random()` for security tokens | `CRYPTO-PY-006` |
| **Hardcoded Crypto Keys** | Encryption keys embedded in source code | `CRYPTO-PY-007` |

**Languages covered:** Python, Java, JavaScript, Go, C#, PHP, Rust, C/C++ (universal)

---

### 5. Insecure Deserialization

**Directory:** `rules/deserialization/` &nbsp;|&nbsp; **Files:** 7 &nbsp;|&nbsp; **Rules:** ~58 &nbsp;|&nbsp; **CWE:** CWE-502 &nbsp;|&nbsp; **OWASP:** A08:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **Pickle RCE** | `pickle.loads()` on untrusted data (network, file, user input) | `DESER-PY-001` |
| **Java ObjectInputStream** | `readObject()`/`readUnshared()` without input filtering | `DESER-JAVA-001` |
| **YAML Deserialization** | `yaml.load()` without `SafeLoader` (Python), YAML anchors | `DESER-PY-007` |
| **JSON Deserialization** | `JSON.parse()` with prototype pollution, `json.loads()` to `eval()` | `DESER-JS-001` |
| **PHP Unserialize** | `unserialize()` on user-controlled data, gadget chains | `DESER-PHP-001` |
| **Gadget Chain Detection** | Commons Collections, ysoserial payloads, POP chains | `DESER-JAVA-004` |
| **XMLDecoder** | Java XMLDecoder deserialization of untrusted XML | `ENT-DESER-JAVA-001` |
| **SnakeYAML** | SnakeYAML without SafeConstructor | `ENT-DESER-JAVA-002` |
| **.NET Formatters** | BinaryFormatter, SoapFormatter, NetDataContractSerializer | `ENT-DESER-CS-001` |

**Languages covered:** Python, Java, JavaScript, C#, PHP, and universal cross-language rules

---

### 6. Remote Code Execution

**Directory:** `rules/rce/` &nbsp;|&nbsp; **Files:** 5 &nbsp;|&nbsp; **Rules:** ~27 &nbsp;|&nbsp; **CWE:** CWE-78, CWE-94, CWE-426 &nbsp;|&nbsp; **OWASP:** A03:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **OS Command Execution** | `os.system()`, `os.popen()`, `Runtime.exec()`, `exec.Command()` | `RCE-PY-001`, `RCE-JAVA-001` |
| **Subprocess Shells** | `subprocess.Popen(shell=True)`, `child_process.exec()` | `RCE-PY-002`, `RCE-JS-001` |
| **Dynamic Code Eval** | `eval()`, `exec()`, `compile()` on user input | `RCE-PY-003` |
| **Dynamic Module Loading** | `__import__()`, `importlib` with user-controlled names | `RCE-PY-004` |
| **Native Library Loading** | `ctypes.CDLL()`, `ffi.Library()` with controlled paths | `RCE-PY-005` |
| **Task Queue Injection** | Celery/RQ tasks with unsanitized user arguments | `RCE-PY-006` |

**Languages covered:** Python, Java, JavaScript, Go, PHP, Ruby, Shell (universal)

---

### 7. Server-Side Request Forgery

**Directory:** `rules/ssrf/` &nbsp;|&nbsp; **Files:** 5 &nbsp;|&nbsp; **Rules:** ~25 &nbsp;|&nbsp; **CWE:** CWE-918 &nbsp;|&nbsp; **OWASP:** A10:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **HTTP Client SSRF** | `requests.get()`, `urllib.urlopen()`, `HttpClient` with user URLs | `SSRF-PY-001`, `SSRF-PY-002` |
| **Async HTTP SSRF** | `aiohttp`, `httpx`, `node-fetch` with user-controlled destinations | `SSRF-PY-003` |
| **Cloud Metadata SSRF** | Access to `169.254.169.254` cloud metadata endpoints | `SSRF-PY-004` |
| **DNS Rebinding** | Socket-level DNS rebinding attacks bypassing IP validation | `SSRF-PY-005` |
| **Open Redirect** | Server-side redirects to user-controlled URLs | `SSRF-PY-006` |

**Bypass variants detected:** URL encoding, IPv6 mapped addresses, `gopher://`/`file://` protocol smuggling, redirect chaining, DNS rebinding, decimal/octal IP notation

**Languages covered:** Python, Java, JavaScript, Go, and universal rules

---

### 8. Path Traversal

**Directory:** `rules/path_traversal/` &nbsp;|&nbsp; **Files:** 6 &nbsp;|&nbsp; **Rules:** ~31 &nbsp;|&nbsp; **CWE:** CWE-22 &nbsp;|&nbsp; **OWASP:** A01:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **File Read Traversal** | `open()`, `readFile()` with user-controlled paths | `PT-PY-001` |
| **Path Join Bypass** | `os.path.join()` / `path.join()` ignoring absolute path segments | `PT-PY-002` |
| **Framework File Serving** | Flask `send_file`, Django `FileResponse`, Express `res.sendFile` | `PT-PY-003`, `PT-PY-004` |
| **ZIP Slip** | Archive extraction without path validation | `PT-PY-005` |
| **File Copy/Move** | `shutil.copy()` / `fs.copyFile()` with user paths | `PT-PY-006` |

**Bypass variants detected:** `../` sequences, URL encoding (`%2e%2e`), double encoding, null byte injection (`%00`), Unicode normalization (`..%c0%af`), backslash traversal (Windows)

**Languages covered:** Python, Java, JavaScript, Go, PHP, and universal rules

---

### 9. Secrets & Credential Exposure

**Directory:** `rules/secrets/` &nbsp;|&nbsp; **Files:** 1 &nbsp;|&nbsp; **Rules:** 15 &nbsp;|&nbsp; **CWE:** CWE-798 &nbsp;|&nbsp; **OWASP:** A07:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **AWS Credentials** | Access Key ID (`AKIA`/`ASIA` prefixes) + Secret Access Key | `SEC-001` |
| **Generic API Keys** | API keys, tokens, bearer tokens in source code | `SEC-002` |
| **Database Credentials** | Connection strings with embedded passwords (PostgreSQL, MySQL, MongoDB, Redis) | `SEC-003` |
| **Private Keys** | PEM-encoded private keys, SSH keys, certificates | `SEC-004` |
| **JWT Secrets** | Hardcoded JWT signing secrets | `SEC-005` |
| **OAuth Secrets** | OAuth client secrets in source code | `SEC-006` |
| **Platform Tokens** | NPM, Slack, SendGrid, Twilio, Firebase, GCP, Azure tokens | `SEC-008`–`SEC-014` |
| **High-Entropy Secrets** | Entropy-based detection of unrecognized credential patterns | `SEC-015` |

**Applies to:** All languages (universal rules)

---

### 10. Framework Security Misconfiguration

**Directory:** `rules/framework_misuse/` &nbsp;|&nbsp; **Files:** 6 &nbsp;|&nbsp; **Rules:** ~38 &nbsp;|&nbsp; **CWE:** CWE-306, CWE-489, CWE-693 &nbsp;|&nbsp; **OWASP:** A05:2021

| Framework | Key Detections | Key Rules |
|:----------|:---------------|:----------|
| **Flask** | Debug mode in production, `SECRET_KEY` exposed, missing CSRF | `FW-FLASK-001`–`004` |
| **Django** | `DEBUG=True`, `ALLOWED_HOSTS=["*"]`, insecure middleware | `FW-DJANGO-001`–`004` |
| **Express.js** | Missing `helmet()`, no CORS config, verbose errors in prod | `FW-EXPRESS-001`–`004` |
| **Next.js** | Exposed API routes, insecure headers, missing CSP | `FW-NEXT-001`–`004` |
| **Spring Boot** | `permitAll("/**")`, disabled CSRF, actuator exposure | `FW-SPRING-001`–`006` |
| **ASP.NET** | Missing `[Authorize]`, disabled HTTPS, verbose error pages | `FW-ASPNET-001`–`006` |
| **Laravel / Symfony** | `APP_DEBUG=true`, mass assignment, missing middleware | `FW-LARAVEL-001`+ |
| **Gin / Echo (Go)** | Missing security middleware, CORS wildcards | `FW-GIN-001`+ |

---

### 11. DevOps & Infrastructure

**Directory:** `rules/devops/` &nbsp;|&nbsp; **Files:** 4 &nbsp;|&nbsp; **Rules:** ~134 &nbsp;|&nbsp; **CWE:** CWE-78, CWE-94, CWE-250, CWE-269, CWE-306, CWE-312, CWE-532, CWE-798, CWE-918 &nbsp;|&nbsp; **OWASP:** A01:2021, A03:2021, A05:2021, A07:2021, A08:2021

| Sub-Type | Description | Key Rules |
|:---------|:------------|:----------|
| **Privileged Containers** | `privileged: true`, `capabilities: ALL`, missing securityContext | `DEVOPS-YAML-001` |
| **Host Namespace** | `hostPID`, `hostNetwork`, `hostIPC` sharing | `DEVOPS-YAML-002` |
| **Sensitive Volume Mounts** | hostPath mounts to `/`, `/etc`, Docker socket mounts | `DEVOPS-YAML-003` |
| **Pod Security** | Missing Pod Security Standards, runAsRoot, no readOnlyRootFilesystem | `DEVOPS-YAML-004`–`015` |
| **CI/CD Pipeline Injection** | Untrusted inputs (PR titles, commit messages) interpolated into shell commands | `CICD-PIPE-001`, `CICD-PIPE-002` |
| **GitHub Actions Security** | Excessive permissions, pwn-request (pull_request_target + checkout), token leakage | `CICD-GHA-001`, `CICD-GHA-002` |
| **Terraform Security** | State file exposure, hardcoded provider credentials | `CICD-TF-001`, `CICD-TF-002` |
| **Helm Template Injection** | Unquoted values in sensitive Helm fields | `CICD-HELM-001` |
| **Container Escape** | Dockerfile running as root, dangerous Linux capabilities (SYS_ADMIN, SYS_PTRACE) | `CICD-DOCKER-001`, `CICD-DOCKER-002` |
| **Serverless Security** | Overprivileged Lambda IAM roles, unauthenticated API endpoints | `CICD-SLESS-001`, `CICD-SLESS-002` |
| **Supply Chain** | Dependency confusion (npm/pip), malicious lifecycle scripts, lockfile tampering | `SUPPLY-DEP-001`–`002`, `SUPPLY-SCRIPT-001`, `SUPPLY-LOCK-001` |
| **Cloud IAM** | AWS IAM privilege escalation, admin access, S3 public buckets | `CLOUD-IAM-001`, `CLOUD-IAM-002`, `CLOUD-S3-001` |
| **Kubernetes RBAC** | Wildcard ClusterRole, privileged containers, Docker socket mount | `CLOUD-K8S-001`, `CLOUD-K8S-002`, `CLOUD-DOCKER-001` |
| **Cross-Rule Correlation** | Attack chain correlation rules (auth+SQLi, upload+deser, SSRF+metadata, CI/CD+secrets) | `CORR-CHAIN-001`–`004` |

**Platforms:** Kubernetes, Docker Compose, Helm Charts, GitHub Actions, GitLab CI, Terraform, Serverless Framework, CloudFormation

---

## Supported Languages & Frameworks

| Language | Frameworks Covered | Rule Categories |
|:---------|:-------------------|:----------------|
| **Python** | Django, Flask, FastAPI, Celery, Jinja2 | auth, crypto, deser, injection, path_traversal, rce, ssrf, xss, framework_misuse |
| **Java** | Spring Boot, Spring Security, Hibernate | auth, crypto, deser, injection, path_traversal, rce, ssrf, framework_misuse |
| **JavaScript** | Express.js, React, Vue, Angular, jQuery, Node.js | auth, crypto, deser, injection, path_traversal, rce, ssrf, xss, framework_misuse |
| **TypeScript** | Next.js, Angular, NestJS | injection, xss, framework_misuse |
| **Go** | Gin, Echo, net/http | auth, crypto, injection, path_traversal, rce, ssrf, framework_misuse |
| **C#** | ASP.NET Core, Entity Framework | auth, crypto, deser, injection, framework_misuse |
| **PHP** | Laravel, Symfony, WordPress | auth, crypto, deser, injection, path_traversal, rce, xss, framework_misuse |
| **Ruby** | Rails, Sinatra | injection, rce |
| **Rust** | Actix, Rocket | crypto, injection |
| **Kotlin** | Spring, Ktor | injection |
| **Swift** | Vapor | injection |
| **C/C++** | OpenSSL, system APIs | crypto, injection |
| **Shell** | Bash, sh, POSIX | injection, rce |
| **SQL** | MySQL, PostgreSQL, MSSQL, Oracle | injection |
| **YAML** | Kubernetes, Docker, Helm, CI/CD | devops |
| **Universal** | All languages | secrets, crypto, deser, path_traversal, rce, ssrf, xss |

---

## OWASP Top 10 (2021) Coverage

| OWASP ID | Category | Rule Coverage |
|:---------|:---------|:--------------|
| **A01:2021** | Broken Access Control | Path Traversal (`PT-*`), Framework Auth misconfiguration |
| **A02:2021** | Cryptographic Failures | All `CRYPTO-*` rules (weak hashing, broken encryption, insecure random) |
| **A03:2021** | Injection | All `INJ-*`, `SQL-INJ-*`, `SHELL-INJ-*`, `XSS-*`, `RCE-*` rules |
| **A04:2021** | Insecure Design | `BIZ-*` (business logic), `AUTH-IDOR-*`, `AUTH-RACE-*`, framework misconfiguration rules |
| **A05:2021** | Security Misconfiguration | `FW-*` (framework misuse), `DEVOPS-*` (infrastructure) |
| **A06:2021** | Vulnerable Components | Dependency scanning (separate module, not rule-based) |
| **A07:2021** | Auth Failures | All `AUTH-*` rules, `SEC-*` (secrets/credentials) |
| **A08:2021** | Software & Data Integrity | All `DESER-*` (insecure deserialization) rules |
| **A09:2021** | Logging & Monitoring | `CICD-PIPE-002` (secret exposure in logs), framework misconfiguration rules |
| **A10:2021** | Server-Side Request Forgery | All `SSRF-*` rules |

---

## CWE Coverage Matrix

| CWE ID | Name | Rule Categories |
|:-------|:-----|:----------------|
| CWE-22 | Path Traversal | `PT-*` |
| CWE-78 | OS Command Injection | `RCE-*`, `SHELL-INJ-*`, `PY-INJ-002/015` |
| CWE-79 | Cross-Site Scripting | `XSS-*` |
| CWE-89 | SQL Injection | `PY-INJ-001/013`, `SQL-INJ-*` |
| CWE-90 | LDAP Injection | `PY-INJ-014` |
| CWE-94 | Code Injection | `PY-INJ-003/004`, `RCE-*-003` |
| CWE-113 | HTTP Response Splitting | `PY-INJ-011` |
| CWE-134 | Format String | `PY-INJ-010` |
| CWE-250 | Excessive Privileges | `DEVOPS-YAML-*` |
| CWE-287 | Improper Authentication | `AUTH-*` |
| CWE-306 | Missing Auth for Critical Function | `AUTH-*`, `FW-SPRING-*` |
| CWE-327 | Broken Cryptographic Algorithm | `CRYPTO-*` |
| CWE-328 | Weak Hash | `CRYPTO-*-001` |
| CWE-426 | Untrusted Search Path | `RCE-*-005` |
| CWE-489 | Active Debug Code | `FW-FLASK-001`, `FW-DJANGO-001` |
| CWE-502 | Deserialization of Untrusted Data | `DESER-*` |
| CWE-611 | XXE | `PY-INJ-005` |
| CWE-643 | XPath Injection | `PY-INJ-009` |
| CWE-693 | Protection Mechanism Failure | `FW-EXPRESS-001` |
| CWE-798 | Hardcoded Credentials | `SEC-*`, `AUTH-*-001` |
| CWE-918 | Server-Side Request Forgery | `SSRF-*` |
| CWE-943 | NoSQL Injection | `PY-INJ-008`, `INJ-NOSQL-*` |
| CWE-1333 | ReDoS | `PY-INJ-012` |
| CWE-20 | Improper Input Validation | `BIZ-PAY-*`, `BIZ-FLOW-*` |
| CWE-269 | Improper Privilege Management | `CICD-GHA-001`, `CICD-SLESS-001`, `CLOUD-IAM-*` |
| CWE-307 | Brute Force | `BIZ-RATE-*` |
| CWE-312 | Cleartext Storage of Sensitive Info | `CICD-TF-001` |
| CWE-352 | Cross-Site Request Forgery | `AUTH-OAUTH-002` |
| CWE-362 | Race Condition | `AUTH-RACE-*` |
| CWE-532 | Info Exposure Through Log Files | `CICD-PIPE-002` |
| CWE-639 | Authorization Bypass (IDOR) | `AUTH-IDOR-*` |
| CWE-799 | Improper Control of Interaction Frequency | `BIZ-FLOW-003` |
| CWE-841 | Improper Enforcement of Behavioral Workflow | `BIZ-FLOW-001`, `BIZ-FLOW-002` |
| CWE-917 | Expression Language Injection | `INJ-SSTI-*` |

---

## Rule Loading Pipeline

Rules are loaded at engine startup via `engine/rule_loader.py`:

```
Startup
  │
  ▼
get_rule_index()                 ← LRU-cached singleton
  │
  ▼
load_rules(rules_dir)            ← Globs **/*.yaml + **/*.yml
  │
  ├─ yaml.safe_load_all()        ← Parse each YAML file
  ├─ _parse_rule()               ← Validate required fields
  │    ├─ Extract regex patterns  ← Validate compilability, store as strings
  │    ├─ Normalize confidence    ← Accept 0–1 or 0–100 range
  │    ├─ Parse anti-patterns     ← False positive suppression
  │    ├─ Map category            ← CATEGORY_MAP → DB category
  │    └─ Build EngineRule        ← Immutable rule object
  │
  ▼
RuleIndex                        ← Indexed by language, category, rule_id
  ├─ rules_for_language(lang)    ← Language-specific + universal rules
  ├─ rules_for_category(cat)     ← All rules in a category
  └─ get_rule(rule_id)           ← Lookup by ID
```

### Category → DB Category Mapping

| YAML Category | DB Category |
|:--------------|:------------|
| `injection` | Backend Security |
| `auth` | Backend Security |
| `crypto` | Backend Security |
| `rce` | Backend Security |
| `deserialization` | Backend Security |
| `framework_misuse` | Backend Security |
| `path_traversal` | Backend Security |
| `xss` | Frontend Security |
| `ssrf` | API Security |
| `secrets` | Config & Infra |
| `devops` | Config & Infra |

---

## Severity Model

Rules use a four-tier severity classification with weighted scoring:

| Severity | Weight | Typical Findings | Score Impact |
|:---------|:------:|:-----------------|:------------|
| **Critical** | 9–10 | RCE, SQL injection, hardcoded AWS keys, privileged containers | Maximum deduction |
| **High** | 7–8 | XSS, weak crypto, SSRF, path traversal, deserialization | Major deduction |
| **Medium** | 4–6 | Format string bugs, ReDoS, missing headers, LIKE injection | Moderate deduction |
| **Low** | 1–3 | Informational findings, best practice violations | Minor deduction |

### Exploitability Scores

Each rule includes an exploitability assessment:

| Score | Meaning |
|:------|:--------|
| **Critical** | Trivially exploitable, no authentication required, public-facing |
| **High** | Exploitable with minimal effort, common attack tooling available |
| **Medium** | Requires specific conditions or partial knowledge |
| **Low** | Requires significant effort, insider access, or unusual circumstances |

### Composite Security Score

The scan engine computes a **0–100 security score** based on:

```
score = 100 - Σ(severity_weight × exploitability_modifier × confidence)
```

Scores map to letter grades:

| Score Range | Grade |
|:------------|:------|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

---

## False Positive Mitigation

Every rule includes **anti-patterns** — regex strings that, when matched in surrounding context, suppress the detection. This is the primary mechanism for reducing false positives.

### Anti-Pattern Categories

| Category | Examples |
|:---------|:---------|
| **Parameterized Queries** | `cursor.execute(query, params)`, `PreparedStatement`, `$1, $2` placeholders |
| **Environment Variables** | `os.environ`, `process.env`, `System.getenv()`, `.env` file loaders |
| **Secret Managers** | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager |
| **Test Context** | `test_`, `_test.py`, `spec/`, `__tests__/`, mock/fixture data |
| **Developer Overrides** | `# nosec`, `# noqa`, `@SuppressWarnings`, `// NOLINT` |
| **Safe API Usage** | ORM query builders, `htmlspecialchars()`, `DOMPurify.sanitize()`, `shlex.quote()` |
| **Non-Security Usage** | `usedforsecurity=False`, checksum/etag contexts, cache key generation |

### Context Awareness

Advanced rules include `context_awareness` blocks with:

- **`surrounding_code_check`** — Examines lines before/after the match for sanitization
- **`taint_source_indicators`** — Identifies user input sources (`request`, `argv`, `$_GET`)
- **`sanitization_patterns`** — Recognizes applied sanitization that neutralizes the threat

---

## Contributing New Rules

### Rule ID Convention

```
{CATEGORY}-{LANG}-{NNN}

Examples:
  INJ-PY-016          (Python injection rule #16)
  AUTH-GO-011          (Go authentication rule #11)
  CRYPTO-JAVA-009      (Java cryptography rule #9)
  SEC-016              (Universal secrets rule #16)
  DEVOPS-YAML-016      (DevOps YAML rule #16)
```

### Checklist for New Rules

- [ ] **Unique `rule_id`** following the naming convention
- [ ] **All required fields** populated: `rule_id`, `title`, `language`, `category`, `severity`, `patterns`
- [ ] **At least one regex pattern** that compiles successfully
- [ ] **Anti-patterns** for known false positive scenarios
- [ ] **CWE and OWASP mapping** for compliance reporting
- [ ] **Impact description** explaining exploitation consequences
- [ ] **Remediation steps** with concrete code examples
- [ ] **Bypass variants** for known evasion techniques (if applicable)
- [ ] **Tested** against real-world vulnerable code samples and safe code counterexamples
- [ ] **Placed in correct directory**: `rules/{category}/{language}.yaml`

### Validation

Rules are automatically validated on load by the `rule_loader`:

1. Required fields are checked
2. Regex patterns are test-compiled
3. Duplicate `rule_id` values trigger warnings (last one wins)
4. Rules with all-invalid patterns are skipped entirely
5. Confidence values are normalized to 0.0–1.0 range

---

## File Inventory

### Summary Statistics

| Metric | Count |
|:-------|------:|
| **Total YAML rule files** | 112 |
| **Total individual rules** | 1,014 |
| **Detection categories** | 11 |
| **Target languages** | 38 |
| **CWEs covered** | 35+ |
| **OWASP Top 10 items** | 10 of 10 |
| **Web frameworks** | 14 |

### Rules per Category

| Category | YAML Files | Rules | Primary CWEs |
|:---------|:-----------|------:|:-------------|
| Injection | 13 | 218 | CWE-78, 89, 90, 94, 643, 917, 943 |
| Authentication | 8 | 178 | CWE-20, 287, 306, 307, 362, 639, 798, 841 |
| DevOps | 4 | 134 | CWE-78, 94, 250, 269, 312, 798 |
| Cryptography | 7 | 104 | CWE-327, 328 |
| Framework Misuse | 6 | 87 | CWE-306, 489, 693 |
| Deserialization | 7 | 58 | CWE-502 |
| RCE | 5 | 51 | CWE-78, 94 |
| Secrets | 1 | 50 | CWE-798 |
| Path Traversal | 6 | 47 | CWE-22 |
| XSS | 3 | 47 | CWE-79 |
| SSRF | 5 | 40 | CWE-918 |

---

<div align="center">

**SecureAI Rules Engine** — Multi-language static analysis for modern application security.

*Built for depth. Engineered for accuracy.*

</div>
