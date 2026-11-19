# ═══════════════════════════════════════════════════════════════════════════
# SAST RULEBASE AUDIT REPORT
# Generated: 2026-03-05
# Scope: 949 rules, 38 languages, 11 categories, 105 YAML files
# ═══════════════════════════════════════════════════════════════════════════
#
# ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
#
# Current State:
#   - 949 rules across 11 categories and 38 languages
#   - Good OWASP Top 10 coverage (9/10 categories)
#   - 23 CWEs actively mapped
#   - Rich metadata: taint paths, exploit scenarios, context awareness
#
# Issues Found:
#   P0 (Critical):  3 issues  — silent anti-pattern failures, duplicate findings
#   P1 (High):      5 issues  — backtracking risks, over-broad patterns
#   P2 (Medium):    6 issues  — missing anchors, unneeded duplication
#   P3 (Low):       4 issues  — generic remediation, copy-paste metadata
#
# ── P0: CRITICAL ISSUES ──────────────────────────────────────────────────
#
# 1. BROKEN ANTI-PATTERNS (AUTH-PY-001, AUTH-PY-002)
#    Anti-patterns are structured as dicts {pattern:..., description:...}
#    but rule_loader converts them with str(), producing un-matchable strings.
#    → FIX: rule_loader.py now extracts .get("pattern") from dict entries.
#
# 2. DUPLICATE FINDINGS: PY-INJ-002 ↔ RCE-PY-001
#    Both detect os.system()/os.popen() with user input. A single finding
#    triggers both rules, inflating counts. 
#    → FIX: Added vulnerability_family + related_rules for deduplication.
#
# 3. DUPLICATE FINDINGS: JS-INJ-001 ↔ XSS-JS-001
#    Both detect innerHTML assignment from user-controlled input.
#    → FIX: Added vulnerability_family + related_rules for deduplication.
#
# ── P1: HIGH SEVERITY ISSUES ─────────────────────────────────────────────
#
# 4. QUADRATIC BACKTRACKING: PY-INJ-001 WHERE-clause patterns
#    Pattern: \.execute\(.*\bWHERE\b.*\{
#    Two adjacent .* with \b creates O(n²) behavior on non-matching input.
#    → FIX: Replaced .* with bounded [^'"]{0,200} quantifiers.
#
# 5. TRIPLE .*? BACKTRACKING: RCE-PY-001 first pattern
#    Three .*? branches in alternation followed by another .*? creates
#    exponential backtracking on certain non-matching inputs.
#    → FIX: Replaced with bounded [^)]{0,150} quantifiers.
#
# 6. OVER-BROAD TERRAFORM PATTERNS: TF-SEC-001, -006, -008
#    Match ANY resource of a type, relying on anti-patterns to exclude.
#    Generates findings for every S3 bucket / RDS instance / EC2 instance.
#    → FIX: Tightened patterns to detect absence of security config.
#
# 7. [\s\S]*? IN FW-FLASK-001
#    Can match entire file contents when searching for config patterns.
#    → FIX: Replaced with bounded {0,500} quantifiers.
#
# 8. SEC-001 / TF-SEC-004 DUPLICATE AWS KEY DETECTION
#    Identical AKIA[0-9A-Z]{16} pattern in both rules.
#    → FIX: Added related_rules cross-reference for deduplication.
#
# ── P2: MEDIUM SEVERITY ISSUES ───────────────────────────────────────────
#
# 9.  UNANCHORED SECRET PATTERNS: SEC-001, SEC-002
#     Missing \b word boundaries allow partial-match false positives.
#     → FIX: Added \b anchors to all secret detection patterns.
#
# 10. MISSING ANTI-PATTERNS: TF-SEC-005
#     Only 2 anti-patterns for IAM wildcard detection. Missing NotAction,
#     Condition blocks, policy document data sources.
#     → FIX: Added 6 new anti-patterns.
#
# 11. DESER-JAVA-001 OVER-BROAD .readObject() PATTERN
#     Matches any readObject() regardless of input source.
#     → FIX: Narrowed pattern + added internal-use anti-patterns.
#
# ── P3: LOW SEVERITY ISSUES ──────────────────────────────────────────────
#
# 12. GENERIC REMEDIATION: 6 Terraform rules share identical text
# 13. COPY-PASTE METADATA across TF-SEC-002 through TF-SEC-008
# 14. OUTDATED README: States "500+ rules" when actual count is 949
# 15. privilege_context_flags inconsistency (dict vs list)
#
# ── COVERAGE GAPS ─────────────────────────────────────────────────────────
#
# Missing Enterprise Attack Categories:
#   - NoSQL injection (MongoDB, Redis)
#   - LDAP injection
#   - XPath injection
#   - GraphQL injection
#   - Template injection (Jinja2, Twig, Freemarker, Pebble)
#   - CRLF injection
#   - JWT signature bypass
#   - OAuth misconfiguration
#   - SAML validation bypass
#   - Session fixation / replay
#   - IDOR patterns
#   - Race conditions / TOCTOU
#   - Supply chain attacks (dependency confusion, typosquatting)
#   - CI/CD pipeline attacks
#   - Serverless IAM escalation
#   - Container escape patterns
#   - Business logic flaws (rate limiting, payment)
#
# ═══════════════════════════════════════════════════════════════════════════
