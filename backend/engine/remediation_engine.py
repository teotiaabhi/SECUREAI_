"""
Secure Code Fix Generator — produces professional remediation code for
every vulnerability finding using template-based, language-aware fix
generation with context-sensitive adaptation.

Pipeline position:
    … → Exploit Graph → Severity Normalization
    → **Remediation Engine** → Developer Learning → Report Generation

Architecture:
    1. Fix Template Library — vulnerability-class → (vulnerable, secure, explanation)
    2. Language Adapter — maps templates to idiomatic target-language syntax
    3. Context Analyser — inspects code_snippet / matched_pattern for
       variable names, framework hints, function signatures
    4. Fix Renderer — merges template + language + context into final output
    5. Pipeline Integration — apply_remediation(findings, file_contents)

Output per finding (attached as finding.remediation_fix dict):
    {
      "vulnerable_code": "...",
      "secure_fix": "...",
      "fix_explanation": "...",
      "security_principle": "...",
      "best_practice": "...",
      "confidence": 0-100
    }

Constraints:
    - Deterministic: NO AI, NO randomness, NO external calls
    - Performance: <5 ms per finding (pure dict lookup + string format)
    - Template-based: all fixes come from static lookup tables
    - Thread-safe: no shared mutable state
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.remediation_engine")


# ═══════════════════════════════════════════════════════════════════════
# LANGUAGE DETECTION HELPERS
# ═══════════════════════════════════════════════════════════════════════

# File extension → normalised language key
_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php", ".phtml": "php",
    ".cs": "csharp",
    ".rb": "ruby", ".erb": "ruby",
    ".rs": "rust",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "cpp", ".h": "cpp", ".hpp": "cpp",
    ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".tf": "terraform", ".tfvars": "terraform", ".hcl": "terraform",
    ".yaml": "yaml", ".yml": "yaml",
    ".dockerfile": "dockerfile",
    ".scala": "scala",
    ".groovy": "groovy", ".gradle": "groovy",
    ".vue": "javascript", ".svelte": "javascript",
}


def _detect_language(file_name: str) -> str:
    """Detect language from file extension.  Falls back to 'generic'."""
    if not file_name:
        return "generic"

    lower = file_name.lower()

    # Special whole-name matches
    if lower.endswith("dockerfile") or "/dockerfile" in lower:
        return "dockerfile"

    # Extension lookup
    for ext, lang in _EXT_TO_LANG.items():
        if lower.endswith(ext):
            return lang

    return "generic"


# ═══════════════════════════════════════════════════════════════════════
# FRAMEWORK DETECTION
# ═══════════════════════════════════════════════════════════════════════

# (regex_pattern, framework_name) — tested against code_snippet + file content
_FRAMEWORK_SIGNALS: List[Tuple[str, str]] = [
    # Python
    (r"\bfrom\s+django\b", "django"),
    (r"\bfrom\s+flask\b", "flask"),
    (r"\bfrom\s+fastapi\b", "fastapi"),
    (r"\bfrom\s+sqlalchemy\b", "sqlalchemy"),
    (r"\bimport\s+psycopg2\b", "psycopg2"),
    (r"\bimport\s+pymysql\b", "pymysql"),
    (r"\bimport\s+aiohttp\b", "aiohttp"),
    # JavaScript / TypeScript
    (r"\bexpress\s*\(", "express"),
    (r"\brequire\s*\(\s*['\"]express['\"]", "express"),
    (r"\bfrom\s+['\"]next", "nextjs"),
    (r"\bfrom\s+['\"]react", "react"),
    (r"\bfrom\s+['\"]@angular", "angular"),
    (r"\bfrom\s+['\"]sequelize", "sequelize"),
    (r"\bfrom\s+['\"]typeorm", "typeorm"),
    (r"\bfrom\s+['\"]prisma", "prisma"),
    (r"\bfrom\s+['\"]knex", "knex"),
    # Java
    (r"\bimport\s+org\.springframework\b", "spring"),
    (r"\bimport\s+javax\.persistence\b", "jpa"),
    (r"\bimport\s+jakarta\.persistence\b", "jpa"),
    (r"\bimport\s+org\.hibernate\b", "hibernate"),
    # Go
    (r"\b\"net/http\"\b", "net_http"),
    (r"\b\"github\.com/gin-gonic/gin\"", "gin"),
    (r"\b\"github\.com/gorilla/mux\"", "gorilla"),
    (r"\b\"database/sql\"", "database_sql"),
    # PHP
    (r"\bLaravel\b|\bIlluminate\\\\", "laravel"),
    (r"\bSymfony\\\\", "symfony"),
    # Ruby
    (r"\bRails\b|\bActiveRecord\b", "rails"),
    (r"\bSinatra\b", "sinatra"),
    # C#
    (r"\busing\s+Microsoft\.AspNetCore\b", "aspnet"),
    (r"\busing\s+System\.Data\.SqlClient\b", "aboret"),
    (r"\busing\s+Microsoft\.EntityFrameworkCore\b", "efcore"),
    # Rust
    (r"\buse\s+actix_web\b", "actix"),
    (r"\buse\s+rocket\b", "rocket"),
    (r"\buse\s+sqlx\b", "sqlx"),
    # Kotlin
    (r"\bimport\s+io\.ktor\b", "ktor"),
    (r"\bimport\s+org\.springframework\b", "spring"),
]

_COMPILED_FRAMEWORK_SIGNALS = [
    (re.compile(pat, re.IGNORECASE), fw) for pat, fw in _FRAMEWORK_SIGNALS
]


def _detect_frameworks(snippet: str, file_content: str = "") -> List[str]:
    """Return detected framework names from code context."""
    combined = (snippet or "") + "\n" + (file_content[:4000] if file_content else "")
    if not combined.strip():
        return []

    found: List[str] = []
    for regex, name in _COMPILED_FRAMEWORK_SIGNALS:
        if regex.search(combined):
            found.append(name)
    return found


# ═══════════════════════════════════════════════════════════════════════
# CONTEXT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

# Common variable-name patterns for context-aware substitution
_VAR_PATTERNS: Dict[str, re.Pattern] = {
    "user_input": re.compile(
        r"\b(user_?(?:input|data|name|id|email|param)|"
        r"req(?:uest)?\.(?:body|query|params|GET|POST|data|form)|"
        r"request\.(?:args|values|json)|"
        r"params\[|argv)\b",
        re.IGNORECASE,
    ),
    "query_var": re.compile(
        r"\b(query|sql|stmt|statement|cmd|command|q)\s*[=+]",
        re.IGNORECASE,
    ),
    "file_var": re.compile(
        r"\b(file_?(?:name|path|dir)|path|filename|upload|dest)\b",
        re.IGNORECASE,
    ),
    "url_var": re.compile(
        r"\b(url|uri|endpoint|href|link|target_?url|redirect_?url)\b",
        re.IGNORECASE,
    ),
}


def _extract_context(finding: EngineFinding, file_content: str = "") -> Dict[str, Any]:
    """Extract contextual hints from a finding for template substitution."""
    snippet = finding.code_snippet or finding.matched_pattern or ""
    lang = _detect_language(finding.file_name)
    frameworks = _detect_frameworks(snippet, file_content)

    # Try to extract variable names
    variables: Dict[str, str] = {}
    for role, pattern in _VAR_PATTERNS.items():
        m = pattern.search(snippet)
        if m:
            variables[role] = m.group(1)

    return {
        "language": lang,
        "frameworks": frameworks,
        "variables": variables,
        "snippet": snippet,
        "file_name": finding.file_name,
    }


# ═══════════════════════════════════════════════════════════════════════
# FIX TEMPLATE LIBRARY
# ═══════════════════════════════════════════════════════════════════════
#
# Structure:  CWE → { lang → FixTemplate }
# Each FixTemplate contains vulnerable/secure examples, explanation,
# principle, and best practice.  A "generic" language key is always
# present as fallback.
# ═══════════════════════════════════════════════════════════════════════


class _T:
    """Lightweight namespace for a fix template."""
    __slots__ = ("vulnerable", "secure", "explanation", "principle", "practice", "confidence")

    def __init__(self, vulnerable: str, secure: str, explanation: str,
                 principle: str, practice: str, confidence: int = 85):
        self.vulnerable = vulnerable
        self.secure = secure
        self.explanation = explanation
        self.principle = principle
        self.practice = practice
        self.confidence = confidence


# ─── SQL Injection (CWE-89) ──────────────────────────────────────────

_SQLI_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — string concatenation in SQL\n'
            'query = "SELECT * FROM users WHERE id = " + user_id\n'
            'cursor.execute(query)'
        ),
        secure=(
            '# SECURE — parameterized query\n'
            'cursor.execute(\n'
            '    "SELECT * FROM users WHERE id = %s",\n'
            '    (user_id,)\n'
            ')'
        ),
        explanation=(
            "Replace string concatenation with parameterized queries. "
            "The database driver handles escaping, preventing injection."
        ),
        principle="Never concatenate user input into SQL — use parameterized queries.",
        practice=(
            "Use ORM methods (Django ORM, SQLAlchemy) for routine queries. "
            "For raw SQL, always use placeholder syntax (%s, :name). "
            "Apply least-privilege DB credentials."
        ),
        confidence=92,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — string concatenation\n'
            'String query = "SELECT * FROM users WHERE id = " + userId;\n'
            'Statement stmt = conn.createStatement();\n'
            'ResultSet rs = stmt.executeQuery(query);'
        ),
        secure=(
            '// SECURE — PreparedStatement\n'
            'PreparedStatement stmt = conn.prepareStatement(\n'
            '    "SELECT * FROM users WHERE id = ?"\n'
            ');\n'
            'stmt.setString(1, userId);\n'
            'ResultSet rs = stmt.executeQuery();'
        ),
        explanation=(
            "Use PreparedStatement instead of Statement. The JDBC driver "
            "binds parameters safely, preventing SQL injection."
        ),
        principle="Never use Statement with concatenated input — use PreparedStatement.",
        practice=(
            "Use JPA/Hibernate named queries for common operations. "
            "For native SQL, always use PreparedStatement with positional "
            "or named parameters. Validate input type before binding."
        ),
        confidence=92,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — template literal in query\n'
            'const query = `SELECT * FROM users WHERE id = ${userId}`;\n'
            'db.query(query);'
        ),
        secure=(
            '// SECURE — parameterized query\n'
            'db.query(\n'
            '    "SELECT * FROM users WHERE id = ?",\n'
            '    [userId]\n'
            ');'
        ),
        explanation=(
            "Use parameterized queries with placeholder ?. The database "
            "driver properly escapes the value, preventing injection."
        ),
        principle="Never interpolate user input into SQL strings — use placeholders.",
        practice=(
            "Use an ORM (Sequelize, TypeORM, Prisma) or query builder "
            "(Knex) for type-safe queries. For raw SQL, always use "
            "parameterized bindings. Validate input types."
        ),
        confidence=90,
    ),
    "typescript": _T(
        vulnerable=(
            '// VULNERABLE — template literal in query\n'
            'const query = `SELECT * FROM users WHERE id = ${userId}`;\n'
            'await db.query(query);'
        ),
        secure=(
            '// SECURE — parameterized query\n'
            'await db.query(\n'
            '    "SELECT * FROM users WHERE id = $1",\n'
            '    [userId]\n'
            ');'
        ),
        explanation=(
            "Use parameterized queries with numbered placeholders ($1, $2). "
            "The driver handles escaping, preventing injection."
        ),
        principle="Never interpolate user input into SQL — use parameterized queries.",
        practice=(
            "Prefer Prisma or TypeORM for type-safe database access. "
            "For raw queries, always use driver parameterization. "
            "Define input validation schemas with Zod or class-validator."
        ),
        confidence=90,
    ),
    "go": _T(
        vulnerable=(
            '// VULNERABLE — fmt.Sprintf in SQL\n'
            'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)\n'
            'rows, err := db.Query(query)'
        ),
        secure=(
            '// SECURE — parameterized query\n'
            'rows, err := db.Query(\n'
            '    "SELECT * FROM users WHERE id = $1",\n'
            '    userID,\n'
            ')'
        ),
        explanation=(
            "Use db.Query with positional $1 parameters. The database/sql "
            "driver binds values safely, preventing injection."
        ),
        principle="Never use fmt.Sprintf for SQL — use db.Query with placeholders.",
        practice=(
            "Use sqlx or GORM for structured queries. Always validate "
            "and type-assert user input. Use context-aware queries with "
            "db.QueryContext for proper timeout handling."
        ),
        confidence=90,
    ),
    "php": _T(
        vulnerable=(
            '// VULNERABLE — variable interpolation\n'
            '$query = "SELECT * FROM users WHERE id = " . $userId;\n'
            '$result = mysqli_query($conn, $query);'
        ),
        secure=(
            '// SECURE — prepared statement\n'
            '$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");\n'
            '$stmt->bind_param("s", $userId);\n'
            '$stmt->execute();\n'
            '$result = $stmt->get_result();'
        ),
        explanation=(
            "Use prepared statements with bind_param(). MySQLi and PDO "
            "handle escaping, preventing injection."
        ),
        principle="Never concatenate variables into SQL — use prepared statements.",
        practice=(
            "Use Laravel Eloquent or Doctrine ORM for safe queries. "
            "For raw SQL, always use PDO prepared statements. Set "
            "PDO::ATTR_EMULATE_PREPARES to false for true server-side prep."
        ),
        confidence=90,
    ),
    "csharp": _T(
        vulnerable=(
            '// VULNERABLE — string concatenation\n'
            'string query = "SELECT * FROM Users WHERE Id = " + userId;\n'
            'var cmd = new SqlCommand(query, conn);'
        ),
        secure=(
            '// SECURE — parameterized command\n'
            'var cmd = new SqlCommand(\n'
            '    "SELECT * FROM Users WHERE Id = @id", conn\n'
            ');\n'
            'cmd.Parameters.AddWithValue("@id", userId);'
        ),
        explanation=(
            "Use SqlCommand.Parameters to bind values. ADO.NET handles "
            "type-safe escaping, preventing injection."
        ),
        principle="Never concatenate input into SQL — use SqlParameter bindings.",
        practice=(
            "Use Entity Framework Core for type-safe queries. For raw SQL, "
            "use FromSqlInterpolated() or parameterized SqlCommand. "
            "Apply [FromQuery] attribute validation in ASP.NET."
        ),
        confidence=90,
    ),
    "ruby": _T(
        vulnerable=(
            '# VULNERABLE — string interpolation\n'
            'query = "SELECT * FROM users WHERE id = #{user_id}"\n'
            'ActiveRecord::Base.connection.execute(query)'
        ),
        secure=(
            '# SECURE — parameterized query\n'
            'User.where(id: user_id).first\n'
            '\n'
            '# Or with raw SQL:\n'
            'ActiveRecord::Base.connection.exec_query(\n'
            '  "SELECT * FROM users WHERE id = $1",\n'
            '  "SQL", [[nil, user_id]]\n'
            ')'
        ),
        explanation=(
            "Use ActiveRecord query methods or parameterized raw SQL. "
            "The ORM handles escaping, preventing injection."
        ),
        principle="Never interpolate into SQL — use ActiveRecord methods or placeholders.",
        practice=(
            "Use ActiveRecord scopes and where() for safe queries. "
            "Use find_by() for single-record lookups. Validate input "
            "types with Strong Parameters."
        ),
        confidence=88,
    ),
    "rust": _T(
        vulnerable=(
            '// VULNERABLE — format! in SQL\n'
            'let query = format!("SELECT * FROM users WHERE id = {}", user_id);\n'
            'client.query(&query, &[]).await?;'
        ),
        secure=(
            '// SECURE — parameterized query\n'
            'let rows = client.query(\n'
            '    "SELECT * FROM users WHERE id = $1",\n'
            '    &[&user_id],\n'
            ').await?;'
        ),
        explanation=(
            "Use parameterized queries with $1 placeholders. The database "
            "driver binds values safely, preventing injection."
        ),
        principle="Never use format!() for SQL — use parameterized queries.",
        practice=(
            "Use sqlx with compile-time checked queries (sqlx::query!). "
            "Use Diesel ORM for type-safe database access. Validate input "
            "with strong Rust types before query binding."
        ),
        confidence=90,
    ),
    "kotlin": _T(
        vulnerable=(
            '// VULNERABLE — string template\n'
            'val query = "SELECT * FROM users WHERE id = $userId"\n'
            'statement.executeQuery(query)'
        ),
        secure=(
            '// SECURE — PreparedStatement\n'
            'val stmt = conn.prepareStatement(\n'
            '    "SELECT * FROM users WHERE id = ?"\n'
            ')\n'
            'stmt.setString(1, userId)\n'
            'val rs = stmt.executeQuery()'
        ),
        explanation=(
            "Use PreparedStatement with positional ? parameters. The JDBC "
            "driver binds values safely, preventing injection."
        ),
        principle="Never use string templates for SQL — use PreparedStatement.",
        practice=(
            "Use Exposed or Ktorm for type-safe queries. "
            "For Spring Data JPA, use @Query with named parameters. "
            "Validate input with Kotlin data classes."
        ),
        confidence=90,
    ),
    "swift": _T(
        vulnerable=(
            '// VULNERABLE — string interpolation\n'
            'let query = "SELECT * FROM users WHERE id = \\(userId)"\n'
            'try db.execute(query)'
        ),
        secure=(
            '// SECURE — parameterized query\n'
            'let rows = try db.prepare(\n'
            '    "SELECT * FROM users WHERE id = ?"\n'
            ').run(userId)'
        ),
        explanation=(
            "Use prepared statements with ? placeholders. The SQLite.swift "
            "driver binds values safely, preventing injection."
        ),
        principle="Never use string interpolation for SQL — use prepared statements.",
        practice=(
            "Use Core Data or GRDB for type-safe database access in Swift. "
            "For raw SQL, always use prepared statements. Validate input "
            "types before query binding."
        ),
        confidence=88,
    ),
    "sql": _T(
        vulnerable=(
            '-- VULNERABLE — dynamic SQL\n'
            "EXEC('SELECT * FROM users WHERE id = ' + @userId)"
        ),
        secure=(
            '-- SECURE — sp_executesql with params\n'
            "EXEC sp_executesql\n"
            "    N'SELECT * FROM users WHERE id = @id',\n"
            "    N'@id NVARCHAR(50)',\n"
            "    @id = @userId"
        ),
        explanation=(
            "Use sp_executesql with typed parameters instead of EXEC with "
            "concatenation. The engine handles proper escaping."
        ),
        principle="Never concatenate into dynamic SQL — use sp_executesql with parameters.",
        practice=(
            "Prefer stored procedures with typed parameters. Use "
            "QUOTENAME() for identifiers that must be dynamic. "
            "Apply EXECUTE AS with least-privilege principals."
        ),
        confidence=85,
    ),
    "generic": _T(
        vulnerable=(
            '# VULNERABLE — string concatenation in SQL query\n'
            'query = "SELECT * FROM users WHERE id = " + user_input'
        ),
        secure=(
            '# SECURE — use parameterized/prepared statement\n'
            '# Replace string concatenation with driver-native placeholders\n'
            'query = "SELECT * FROM users WHERE id = ?"\n'
            'execute(query, [user_input])'
        ),
        explanation=(
            "Use parameterized queries instead of string concatenation. "
            "Database drivers handle proper escaping of bound values."
        ),
        principle="Never build SQL from user input — use parameterized queries.",
        practice=(
            "Always use an ORM or query builder for standard operations. "
            "For raw SQL, use the driver's native placeholder syntax. "
            "Apply least-privilege database accounts."
        ),
        confidence=80,
    ),
}


# ─── XSS (CWE-79) ───────────────────────────────────────────────────

_XSS_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — raw interpolation into HTML\n'
            'return f"<div>{user_input}</div>"'
        ),
        secure=(
            '# SECURE — escape output\n'
            'from markupsafe import escape\n'
            'return f"<div>{escape(user_input)}</div>"\n'
            '\n'
            '# Or use Django/Jinja2 auto-escaping templates:\n'
            '# {{ user_input }}  ← auto-escaped by default'
        ),
        explanation=(
            "Apply context-aware output encoding before rendering user data "
            "in HTML. Framework template engines auto-escape by default."
        ),
        principle="Always encode output — never trust user input in HTML context.",
        practice=(
            "Enable auto-escaping in Jinja2/Django templates. Use "
            "markupsafe.escape() for manual rendering. Set Content-Security-Policy "
            "headers. Never use |safe or Markup() on user data."
        ),
        confidence=90,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — innerHTML with user data\n'
            'element.innerHTML = userInput;'
        ),
        secure=(
            '// SECURE — use textContent\n'
            'element.textContent = userInput;\n'
            '\n'
            '// Or with DOMPurify for rich content:\n'
            'element.innerHTML = DOMPurify.sanitize(userInput);'
        ),
        explanation=(
            "Use textContent instead of innerHTML to prevent script execution. "
            "For rich HTML, sanitize with DOMPurify before insertion."
        ),
        principle="Never assign user input to innerHTML — use textContent or sanitize.",
        practice=(
            "Use React JSX (auto-escapes by default). Avoid "
            "dangerouslySetInnerHTML. Set Content-Security-Policy headers. "
            "Use DOMPurify for any HTML that must be rendered."
        ),
        confidence=90,
    ),
    "typescript": _T(
        vulnerable=(
            '// VULNERABLE — dangerouslySetInnerHTML in React\n'
            'return <div dangerouslySetInnerHTML={{__html: userInput}} />;'
        ),
        secure=(
            '// SECURE — render as text (auto-escaped)\n'
            'return <div>{userInput}</div>;\n'
            '\n'
            '// If HTML needed, sanitize first:\n'
            'import DOMPurify from "dompurify";\n'
            'return <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />;'
        ),
        explanation=(
            "Let React JSX auto-escape user data. Only use "
            "dangerouslySetInnerHTML with sanitized content."
        ),
        principle="Let the framework auto-escape — never bypass with raw HTML insertion.",
        practice=(
            "Use React/Angular template binding (auto-escaped). "
            "Set strict Content-Security-Policy. Sanitize with DOMPurify "
            "when rich HTML is absolutely necessary."
        ),
        confidence=90,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — direct output of user input\n'
            'response.getWriter().write("<div>" + userInput + "</div>");'
        ),
        secure=(
            '// SECURE — OWASP encoder\n'
            'import org.owasp.encoder.Encode;\n'
            'response.getWriter().write(\n'
            '    "<div>" + Encode.forHtml(userInput) + "</div>"\n'
            ');'
        ),
        explanation=(
            "Use the OWASP Java Encoder for context-specific output encoding. "
            "JSP EL expressions use fn:escapeXml() or JSTL <c:out>."
        ),
        principle="Always HTML-encode user output — use OWASP Encoder or JSTL.",
        practice=(
            "Use Thymeleaf (auto-escapes by default) or JSP with <c:out>. "
            "Add OWASP Java Encoder for programmatic output. Set "
            "Content-Security-Policy in Spring Security."
        ),
        confidence=88,
    ),
    "php": _T(
        vulnerable=(
            '// VULNERABLE — direct echo\n'
            'echo "<div>" . $userInput . "</div>";'
        ),
        secure=(
            '// SECURE — htmlspecialchars\n'
            'echo "<div>" . htmlspecialchars($userInput, ENT_QUOTES, "UTF-8") . "</div>";'
        ),
        explanation=(
            "Use htmlspecialchars() with ENT_QUOTES and UTF-8 encoding. "
            "Blade templates (Laravel) auto-escape with {{ }}."
        ),
        principle="Always escape output with htmlspecialchars() — use {{ }} in Blade.",
        practice=(
            "Use Laravel Blade {{ }} (auto-escaped). Avoid {!! !!} "
            "unless content is sanitized. Set Content-Security-Policy. "
            "Use HTMLPurifier for rich content."
        ),
        confidence=90,
    ),
    "go": _T(
        vulnerable=(
            '// VULNERABLE — raw output\n'
            'fmt.Fprintf(w, "<div>%s</div>", userInput)'
        ),
        secure=(
            '// SECURE — html/template auto-escaping\n'
            'tmpl := template.Must(template.New("").Parse("<div>{{.}}</div>"))\n'
            'tmpl.Execute(w, userInput)'
        ),
        explanation=(
            "Use html/template (not text/template) which auto-escapes "
            "all interpolated values in HTML context."
        ),
        principle="Always use html/template — never text/template — for HTML output.",
        practice=(
            "Use html/template for all web output. Set Content-Security-Policy "
            "headers. Validate and normalize input with Go validators."
        ),
        confidence=88,
    ),
    "csharp": _T(
        vulnerable=(
            '// VULNERABLE — raw output\n'
            'return Content($"<div>{userInput}</div>", "text/html");'
        ),
        secure=(
            '// SECURE — Razor auto-escaping\n'
            '// In .cshtml: <div>@Model.UserInput</div>\n'
            '// Or manual:\n'
            'using System.Net;\n'
            'return Content($"<div>{WebUtility.HtmlEncode(userInput)}</div>", "text/html");'
        ),
        explanation=(
            "Use Razor view engine (@-syntax auto-escapes). For manual "
            "encoding, use WebUtility.HtmlEncode()."
        ),
        principle="Let Razor auto-escape — use @Html.Raw() only for trusted content.",
        practice=(
            "Use Razor Pages/MVC views (auto-escaped). Add Content-Security-Policy "
            "via middleware. Use AntiXSS library for complex scenarios."
        ),
        confidence=88,
    ),
    "ruby": _T(
        vulnerable=(
            '# VULNERABLE — raw interpolation\n'
            '"<div>#{user_input}</div>".html_safe'
        ),
        secure=(
            '# SECURE — ERB auto-escaping\n'
            '# In .erb: <div><%= user_input %></div>\n'
            '# (auto-escaped by default in Rails 3+)\n'
            '\n'
            '# Or manual:\n'
            '"<div>#{ERB::Util.html_escape(user_input)}</div>"'
        ),
        explanation=(
            "Rails ERB auto-escapes <%= %> output. Never call .html_safe "
            "on user-controlled strings."
        ),
        principle="Let Rails auto-escape — never use .html_safe on user input.",
        practice=(
            "Use <%= %> in ERB (auto-escaped). Avoid raw(). "
            "Use sanitize() helper for rich content. Set "
            "Content-Security-Policy in Rails config."
        ),
        confidence=88,
    ),
    "generic": _T(
        vulnerable=(
            '# VULNERABLE — user input rendered directly in HTML\n'
            'output = "<div>" + user_input + "</div>"'
        ),
        secure=(
            '# SECURE — HTML-encode before output\n'
            '# Use your framework\'s auto-escaping template engine\n'
            '# Or apply html_encode(user_input) before rendering'
        ),
        explanation=(
            "Apply context-aware output encoding before rendering user "
            "data in HTML, JavaScript, URL, or CSS contexts."
        ),
        principle="Encode all output in the correct context — HTML, JS, URL, or CSS.",
        practice=(
            "Use auto-escaping template engines. Set Content-Security-Policy "
            "headers. Sanitize rich content with a whitelist library. "
            "Set HttpOnly and SameSite on cookies."
        ),
        confidence=75,
    ),
}


# ─── Command Injection (CWE-78, CWE-77) ─────────────────────────────

_CMDI_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — f-string in os.system\n'
            'os.system(f"convert {user_file} output.pdf")'
        ),
        secure=(
            '# SECURE — subprocess with list args, no shell\n'
            'subprocess.run(\n'
            '    ["convert", user_file, "output.pdf"],\n'
            '    shell=False,\n'
            '    check=True\n'
            ')'
        ),
        explanation=(
            "Use subprocess.run() with shell=False and arguments as a list. "
            "Never pass user input to os.system() or shell=True."
        ),
        principle="Avoid shell commands — use libraries. If needed, shell=False with list args.",
        practice=(
            "Prefer language-native libraries over shelling out. "
            "If shell is required, use subprocess.run(cmd_list, shell=False). "
            "Validate input against an allowlist of expected values."
        ),
        confidence=92,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — Runtime.exec with concatenation\n'
            'Runtime.getRuntime().exec("convert " + userFile + " output.pdf");'
        ),
        secure=(
            '// SECURE — ProcessBuilder with separate args\n'
            'ProcessBuilder pb = new ProcessBuilder(\n'
            '    "convert", userFile, "output.pdf"\n'
            ');\n'
            'Process p = pb.start();'
        ),
        explanation=(
            "Use ProcessBuilder with separate arguments. Never concatenate "
            "user input into a single command string."
        ),
        principle="Use ProcessBuilder with split arguments — never concatenate commands.",
        practice=(
            "Prefer Java libraries (Apache PDFBox, ImageIO) over "
            "exec. Validate filenames against a whitelist pattern. "
            "Run processes with minimal privileges."
        ),
        confidence=90,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — exec with template literal\n'
            'const { exec } = require("child_process");\n'
            'exec(`convert ${userFile} output.pdf`);'
        ),
        secure=(
            '// SECURE — execFile with separate args\n'
            'const { execFile } = require("child_process");\n'
            'execFile("convert", [userFile, "output.pdf"], (err, stdout) => {\n'
            '    if (err) throw err;\n'
            '});'
        ),
        explanation=(
            "Use execFile() or spawn() with arguments array instead of "
            "exec() which runs through a shell."
        ),
        principle="Use execFile/spawn with args array — never exec with user input.",
        practice=(
            "Avoid child_process entirely when possible — use npm packages. "
            "If needed, use execFile() with separate arguments. "
            "Validate filenames against allowed patterns."
        ),
        confidence=90,
    ),
    "go": _T(
        vulnerable=(
            '// VULNERABLE — exec.Command with shell\n'
            'cmd := exec.Command("sh", "-c", "convert "+userFile+" output.pdf")\n'
            'cmd.Run()'
        ),
        secure=(
            '// SECURE — exec.Command with separate args\n'
            'cmd := exec.Command("convert", userFile, "output.pdf")\n'
            'if err := cmd.Run(); err != nil {\n'
            '    log.Fatal(err)\n'
            '}'
        ),
        explanation=(
            "Use exec.Command with separate arguments. Never pass user "
            "input through sh -c or bash -c."
        ),
        principle="Use exec.Command with split args — never pass through sh -c.",
        practice=(
            "Prefer Go libraries over exec. Validate input against "
            "expected patterns. Use context.WithTimeout for process "
            "execution limits."
        ),
        confidence=90,
    ),
    "php": _T(
        vulnerable=(
            '// VULNERABLE — shell_exec with variable\n'
            '$output = shell_exec("convert " . $userFile . " output.pdf");'
        ),
        secure=(
            '// SECURE — escapeshellarg\n'
            '$output = shell_exec("convert " . escapeshellarg($userFile) . " output.pdf");\n'
            '\n'
            '// BEST — use a library instead:\n'
            '// $imagick = new Imagick($userFile);\n'
            '// $imagick->setImageFormat("pdf");'
        ),
        explanation=(
            "Use escapeshellarg() for each argument. Better yet, use "
            "a PHP library (Imagick, GD) instead of shelling out."
        ),
        principle="Use escapeshellarg() per argument — prefer PHP libraries over shell.",
        practice=(
            "Avoid exec(), system(), shell_exec(), passthru(). Use "
            "escapeshellarg() if shell is unavoidable. Disable dangerous "
            "functions in php.ini. Validate against allowlists."
        ),
        confidence=88,
    ),
    "ruby": _T(
        vulnerable=(
            '# VULNERABLE — backtick interpolation\n'
            '`convert #{user_file} output.pdf`'
        ),
        secure=(
            '# SECURE — Open3 with separate args\n'
            'require "open3"\n'
            'Open3.capture2("convert", user_file, "output.pdf")'
        ),
        explanation=(
            "Use Open3.capture2/capture3 with separate arguments. "
            "Never use backtick or system() with interpolation."
        ),
        principle="Use Open3 with split arguments — avoid backticks and system().",
        practice=(
            "Prefer Ruby libraries (MiniMagick, RMagick) over shell. "
            "Use Shellwords.shellescape() if interpolation is unavoidable. "
            "Validate inputs against allowlists."
        ),
        confidence=88,
    ),
    "csharp": _T(
        vulnerable=(
            '// VULNERABLE — Process.Start with concatenated args\n'
            'Process.Start("cmd", $"/c convert {userFile} output.pdf");'
        ),
        secure=(
            '// SECURE — ProcessStartInfo with separate args\n'
            'var psi = new ProcessStartInfo("convert")\n'
            '{\n'
            '    Arguments = $"{userFile} output.pdf",\n'
            '    UseShellExecute = false\n'
            '};\n'
            'Process.Start(psi);'
        ),
        explanation=(
            "Use ProcessStartInfo with UseShellExecute=false and pass "
            "arguments separately. Never route through cmd /c."
        ),
        principle="Use ProcessStartInfo(UseShellExecute=false) — never use cmd /c.",
        practice=(
            "Prefer .NET libraries over Process.Start. Validate "
            "filenames with Path.GetFileName(). Run processes with "
            "minimal privileges."
        ),
        confidence=88,
    ),
    "generic": _T(
        vulnerable=(
            '# VULNERABLE — user input in shell command\n'
            'execute("convert " + user_input + " output.pdf")'
        ),
        secure=(
            '# SECURE — use language-native process API with separate args\n'
            'execute(["convert", user_input, "output.pdf"])'
        ),
        explanation=(
            "Pass command arguments as a list/array, not as a single "
            "concatenated string. Never route through a shell interpreter."
        ),
        principle="Separate command from arguments — never concatenate user input.",
        practice=(
            "Use language-native libraries instead of shell. "
            "If shell is required, use process APIs with argument arrays. "
            "Validate input against allowlists."
        ),
        confidence=75,
    ),
}


# ─── Path Traversal (CWE-22) ────────────────────────────────────────

_PATH_TRAV_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — direct join without validation\n'
            'path = os.path.join(UPLOAD_DIR, user_filename)\n'
            'return open(path).read()'
        ),
        secure=(
            '# SECURE — resolve real path and validate prefix\n'
            'path = os.path.realpath(os.path.join(UPLOAD_DIR, user_filename))\n'
            'if not path.startswith(os.path.realpath(UPLOAD_DIR)):\n'
            '    raise ValueError("Path traversal detected")\n'
            'return open(path).read()'
        ),
        explanation=(
            "Resolve the canonical path with os.path.realpath() then verify "
            "it stays within the expected base directory."
        ),
        principle="Always canonicalize paths and verify the prefix.",
        practice=(
            "Use pathlib.Path.resolve() for modern Python. Apply a "
            "whitelist of allowed filenames when possible. Never serve "
            "files from user-controlled paths without validation."
        ),
        confidence=92,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — direct file access\n'
            'File file = new File(uploadDir, userFilename);\n'
            'return Files.readAllBytes(file.toPath());'
        ),
        secure=(
            '// SECURE — canonical path check\n'
            'File file = new File(uploadDir, userFilename).getCanonicalFile();\n'
            'if (!file.toPath().startsWith(new File(uploadDir).getCanonicalFile().toPath())) {\n'
            '    throw new SecurityException("Path traversal detected");\n'
            '}\n'
            'return Files.readAllBytes(file.toPath());'
        ),
        explanation=(
            "Use getCanonicalFile() to resolve symlinks and .., then "
            "verify the path starts within the expected directory."
        ),
        principle="Canonicalize paths with getCanonicalFile() and verify the prefix.",
        practice=(
            "Use Spring Resource abstraction for file serving. "
            "Validate filenames with a whitelist regex. Never expose "
            "absolute paths to users."
        ),
        confidence=90,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — direct path join\n'
            'const filePath = path.join(uploadDir, userFilename);\n'
            'res.sendFile(filePath);'
        ),
        secure=(
            '// SECURE — resolve and validate\n'
            'const filePath = path.resolve(uploadDir, userFilename);\n'
            'if (!filePath.startsWith(path.resolve(uploadDir))) {\n'
            '    return res.status(403).send("Forbidden");\n'
            '}\n'
            'res.sendFile(filePath);'
        ),
        explanation=(
            "Use path.resolve() to canonicalize, then verify the resolved "
            "path stays within the expected base directory."
        ),
        principle="Resolve to absolute path and verify it starts within the safe base.",
        practice=(
            "Use express.static() for serving public files. Validate "
            "filenames with a whitelist regex. Never include user input "
            "in file paths without validation."
        ),
        confidence=90,
    ),
    "go": _T(
        vulnerable=(
            '// VULNERABLE — filepath.Join without check\n'
            'path := filepath.Join(uploadDir, userFilename)\n'
            'http.ServeFile(w, r, path)'
        ),
        secure=(
            '// SECURE — Clean + prefix check\n'
            'cleanPath := filepath.Clean(filepath.Join(uploadDir, userFilename))\n'
            'if !strings.HasPrefix(cleanPath, filepath.Clean(uploadDir)) {\n'
            '    http.Error(w, "Forbidden", http.StatusForbidden)\n'
            '    return\n'
            '}\n'
            'http.ServeFile(w, r, cleanPath)'
        ),
        explanation=(
            "Use filepath.Clean() to normalize, then verify the cleaned "
            "path starts with the expected base directory."
        ),
        principle="Clean paths with filepath.Clean() and verify the prefix.",
        practice=(
            "Use http.FileServer with http.Dir for safe static serving. "
            "Validate filenames against allowlist patterns. Never "
            "expose absolute paths."
        ),
        confidence=90,
    ),
    "php": _T(
        vulnerable=(
            '// VULNERABLE — direct concatenation\n'
            '$path = $uploadDir . "/" . $_GET["file"];\n'
            'readfile($path);'
        ),
        secure=(
            '// SECURE — realpath prefix check\n'
            '$path = realpath($uploadDir . "/" . $_GET["file"]);\n'
            'if ($path === false || strpos($path, realpath($uploadDir)) !== 0) {\n'
            '    http_response_code(403);\n'
            '    exit("Forbidden");\n'
            '}\n'
            'readfile($path);'
        ),
        explanation=(
            "Use realpath() to resolve the canonical path, then verify "
            "it starts with the expected base directory."
        ),
        principle="Resolve with realpath() and verify the prefix before file access.",
        practice=(
            "Use Laravel Storage facade for file operations. Validate "
            "filenames with a whitelist. Disable allow_url_fopen and "
            "allow_url_include in php.ini."
        ),
        confidence=90,
    ),
    "generic": _T(
        vulnerable=(
            '# VULNERABLE — user filename used directly in file path\n'
            'read_file(base_dir + "/" + user_filename)'
        ),
        secure=(
            '# SECURE — canonicalize path and verify prefix\n'
            'real_path = canonicalize(base_dir + "/" + user_filename)\n'
            'if not real_path.startswith(canonicalize(base_dir)):\n'
            '    raise SecurityError("Path traversal")\n'
            'read_file(real_path)'
        ),
        explanation=(
            "Resolve the canonical/real path and verify it stays within "
            "the expected base directory before any file operation."
        ),
        principle="Canonicalize then verify — never trust user paths directly.",
        practice=(
            "Use framework file-serving APIs. Validate filenames "
            "against an allowlist. Never expose internal paths to users."
        ),
        confidence=75,
    ),
}


# ─── Unsafe Deserialization (CWE-502) ────────────────────────────────

_DESER_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — pickle from untrusted source\n'
            'import pickle\n'
            'data = pickle.loads(user_data)'
        ),
        secure=(
            '# SECURE — use JSON for untrusted data\n'
            'import json\n'
            'data = json.loads(user_data)\n'
            '\n'
            '# If pickle is required, sign with HMAC first:\n'
            '# itsdangerous.URLSafeSerializer(secret).loads(user_data)'
        ),
        explanation=(
            "Never use pickle/marshal/shelve on untrusted data — they "
            "execute arbitrary code. Use JSON or signed serialization."
        ),
        principle="Never deserialize untrusted data with pickle — use JSON or signed formats.",
        practice=(
            "Use json for data exchange. Use itsdangerous or PyJWT for "
            "signed tokens. If pickle is needed, sign payloads with HMAC. "
            "Apply input size limits."
        ),
        confidence=92,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — ObjectInputStream from untrusted source\n'
            'ObjectInputStream ois = new ObjectInputStream(userInputStream);\n'
            'Object obj = ois.readObject();'
        ),
        secure=(
            '// SECURE — use JSON with Jackson and type validation\n'
            'ObjectMapper mapper = new ObjectMapper();\n'
            'mapper.activateDefaultTyping(\n'
            '    mapper.getPolymorphicTypeValidator(),\n'
            '    ObjectMapper.DefaultTyping.NON_FINAL\n'
            ');\n'
            'MyDto dto = mapper.readValue(userInput, MyDto.class);'
        ),
        explanation=(
            "Avoid ObjectInputStream for untrusted data. Use JSON "
            "deserialization with explicit type validation."
        ),
        principle="Never use ObjectInputStream on untrusted data — use JSON with type checks.",
        practice=(
            "Use Jackson/Gson with explicit target types. Add "
            "serialization filters (JEP 290). Use NotSoSerial or "
            "Apache Commons IO ValidatingObjectInputStream."
        ),
        confidence=90,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — eval or Function for deserialization\n'
            'const data = eval("(" + userInput + ")");'
        ),
        secure=(
            '// SECURE — JSON.parse with validation\n'
            'const data = JSON.parse(userInput);\n'
            '// Validate schema with Joi, Zod, or ajv\n'
            '// const validated = schema.parse(data);'
        ),
        explanation=(
            "Use JSON.parse() instead of eval(). Validate the parsed "
            "structure against an expected schema."
        ),
        principle="Never use eval() for data parsing — use JSON.parse() with schema validation.",
        practice=(
            "Use JSON.parse() for all data deserialization. Validate "
            "with Zod, Joi, or ajv. Avoid node-serialize and similar "
            "libraries with known RCE gadgets."
        ),
        confidence=90,
    ),
    "csharp": _T(
        vulnerable=(
            '// VULNERABLE — BinaryFormatter\n'
            'var formatter = new BinaryFormatter();\n'
            'var obj = formatter.Deserialize(stream);'
        ),
        secure=(
            '// SECURE — System.Text.Json with typed model\n'
            'var dto = JsonSerializer.Deserialize<MyDto>(jsonString);\n'
            '// Validate with DataAnnotations'
        ),
        explanation=(
            "BinaryFormatter is inherently unsafe. Use System.Text.Json "
            "with explicit target types."
        ),
        principle="Never use BinaryFormatter — use System.Text.Json with typed models.",
        practice=(
            "Use System.Text.Json or Newtonsoft.Json with explicit types. "
            "Enable TypeNameHandling.None (never Auto/All). Validate "
            "with DataAnnotations."
        ),
        confidence=90,
    ),
    "php": _T(
        vulnerable=(
            '// VULNERABLE — unserialize untrusted data\n'
            '$data = unserialize($_POST["data"]);'
        ),
        secure=(
            '// SECURE — use json_decode\n'
            '$data = json_decode($_POST["data"], true);\n'
            '\n'
            '// If unserialize needed, restrict classes:\n'
            '// $data = unserialize($input, ["allowed_classes" => [MyClass::class]]);'
        ),
        explanation=(
            "Use json_decode() instead of unserialize(). If unserialize "
            "is required, restrict allowed classes."
        ),
        principle="Never unserialize untrusted data — use json_decode with validation.",
        practice=(
            "Use json_decode() for all external data. If unserialize "
            "is needed, use allowed_classes restriction. Validate "
            "with Laravel Form Requests or Symfony Validators."
        ),
        confidence=90,
    ),
    "ruby": _T(
        vulnerable=(
            '# VULNERABLE — YAML.load with untrusted data\n'
            'data = YAML.load(user_input)'
        ),
        secure=(
            '# SECURE — YAML.safe_load\n'
            'data = YAML.safe_load(user_input)\n'
            '\n'
            '# Or use JSON:\n'
            'data = JSON.parse(user_input)'
        ),
        explanation=(
            "YAML.load can instantiate arbitrary Ruby objects. Use "
            "YAML.safe_load or switch to JSON."
        ),
        principle="Never YAML.load untrusted data — use YAML.safe_load or JSON.",
        practice=(
            "Use YAML.safe_load or JSON.parse. Use permitted_classes "
            "in Ruby 3.1+. Validate with Strong Parameters. Apply "
            "input size limits."
        ),
        confidence=90,
    ),
    "generic": _T(
        vulnerable='# VULNERABLE — deserializing untrusted binary/object data\ndata = deserialize(untrusted_input)',
        secure='# SECURE — use JSON and validate schema\ndata = json_parse(untrusted_input)\nvalidate(data, expected_schema)',
        explanation="Never deserialize untrusted data with binary/object serializers. Use JSON with schema validation.",
        principle="Use data-only formats (JSON) — never object serialization for untrusted input.",
        practice="Prefer JSON for all external data exchange. Validate against schemas. Apply input size limits.",
        confidence=75,
    ),
}


# ─── Weak Cryptography (CWE-327, CWE-328) ───────────────────────────

_CRYPTO_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — MD5/SHA1 for passwords\n'
            'import hashlib\n'
            'password_hash = hashlib.md5(password.encode()).hexdigest()'
        ),
        secure=(
            '# SECURE — bcrypt for password hashing\n'
            'import bcrypt\n'
            'password_hash = bcrypt.hashpw(\n'
            '    password.encode(), bcrypt.gensalt(rounds=12)\n'
            ')\n'
            '\n'
            '# For general hashing, use SHA-256+:\n'
            'digest = hashlib.sha256(data.encode()).hexdigest()'
        ),
        explanation=(
            "MD5 and SHA1 are cryptographically broken. Use bcrypt/Argon2 "
            "for passwords and SHA-256+ for integrity checks."
        ),
        principle="Use bcrypt/Argon2 for passwords — SHA-256+ for integrity hashing.",
        practice=(
            "Use bcrypt or argon2-cffi for password hashing. Use PBKDF2 "
            "as a fallback (≥100k iterations). Use secrets module for "
            "token generation. Use Fernet for symmetric encryption."
        ),
        confidence=90,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — MD5 digest\n'
            'MessageDigest md = MessageDigest.getInstance("MD5");\n'
            'byte[] hash = md.digest(password.getBytes());'
        ),
        secure=(
            '// SECURE — BCrypt for passwords\n'
            'import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;\n'
            'BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\n'
            'String hash = encoder.encode(password);'
        ),
        explanation=(
            "Use BCryptPasswordEncoder (Spring Security) or jBCrypt "
            "for password hashing instead of MD5/SHA1."
        ),
        principle="Use BCrypt for passwords — SHA-256+ for general hashing.",
        practice=(
            "Use Spring Security PasswordEncoder interface. "
            "Use SecureRandom for token generation. Use AES-GCM for "
            "symmetric encryption via javax.crypto."
        ),
        confidence=88,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — MD5 hash\n'
            'const hash = crypto.createHash("md5").update(password).digest("hex");'
        ),
        secure=(
            '// SECURE — bcrypt for passwords\n'
            'const bcrypt = require("bcrypt");\n'
            'const hash = await bcrypt.hash(password, 12);'
        ),
        explanation=(
            "Use bcrypt for password hashing. MD5/SHA1 are broken for "
            "security-sensitive operations."
        ),
        principle="Use bcrypt for passwords — crypto.createHash('sha256') for integrity.",
        practice=(
            "Use bcrypt or scrypt for password hashing. Use "
            "crypto.randomBytes() for token generation. Use "
            "crypto.createCipheriv('aes-256-gcm') for encryption."
        ),
        confidence=88,
    ),
    "generic": _T(
        vulnerable='# VULNERABLE — weak hash algorithm (MD5/SHA1)\nhash = md5(password)',
        secure='# SECURE — use bcrypt/argon2 for passwords\nhash = bcrypt_hash(password, cost=12)',
        explanation="MD5 and SHA1 are broken for security use. Use bcrypt/Argon2 for passwords.",
        principle="Use bcrypt/Argon2/scrypt for passwords — SHA-256+ for integrity.",
        practice="Use adaptive password hashing (bcrypt ≥ cost 12). Use CSPRNG for tokens. Use AES-GCM for encryption.",
        confidence=75,
    ),
}


# ─── Hardcoded Secrets (CWE-798, CWE-259) ───────────────────────────

_SECRETS_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — hardcoded credentials\n'
            'API_KEY = "sk-abc123def456"\n'
            'DB_PASSWORD = "admin123"'
        ),
        secure=(
            '# SECURE — load from environment\n'
            'import os\n'
            'API_KEY = os.environ["API_KEY"]\n'
            'DB_PASSWORD = os.environ["DB_PASSWORD"]\n'
            '\n'
            '# Or use a secrets manager:\n'
            '# from aws_secretsmanager import get_secret\n'
            '# API_KEY = get_secret("api-key")'
        ),
        explanation=(
            "Move secrets to environment variables or a secrets manager. "
            "Never commit credentials to source code."
        ),
        principle="Store secrets in environment variables or vault — never in source code.",
        practice=(
            "Use .env files for local dev (add to .gitignore). Use AWS "
            "Secrets Manager, HashiCorp Vault, or Azure Key Vault in "
            "production. Rotate credentials regularly. Use pre-commit "
            "hooks to detect secrets."
        ),
        confidence=92,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — hardcoded API key\n'
            'const API_KEY = "sk-abc123def456";\n'
            'const DB_PASSWORD = "admin123";'
        ),
        secure=(
            '// SECURE — load from environment\n'
            'const API_KEY = process.env.API_KEY;\n'
            'const DB_PASSWORD = process.env.DB_PASSWORD;\n'
            '\n'
            '// Use dotenv for local development:\n'
            '// require("dotenv").config();'
        ),
        explanation=(
            "Load secrets from environment variables. Use dotenv for "
            "local development and a secrets manager in production."
        ),
        principle="Use process.env for secrets — never hardcode in source.",
        practice=(
            "Use dotenv for local dev (.env in .gitignore). Use AWS "
            "Secrets Manager or Vault in production. Add secrets "
            "scanning to CI/CD pipeline."
        ),
        confidence=92,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — hardcoded password\n'
            'private static final String DB_PASS = "admin123";'
        ),
        secure=(
            '// SECURE — load from environment or properties\n'
            'String dbPass = System.getenv("DB_PASSWORD");\n'
            '\n'
            '// Or Spring Boot application.yml:\n'
            '// spring.datasource.password: ${DB_PASSWORD}'
        ),
        explanation=(
            "Load credentials from environment variables or external "
            "configuration. Use Spring Cloud Config or Vault."
        ),
        principle="Externalize secrets — use env vars, Spring Config, or Vault.",
        practice=(
            "Use Spring Boot externalized configuration. Use "
            "spring-cloud-vault for HashiCorp Vault integration. "
            "Use Jasypt for encrypted properties. Rotate regularly."
        ),
        confidence=90,
    ),
    "go": _T(
        vulnerable=(
            '// VULNERABLE — hardcoded secret\n'
            'const apiKey = "sk-abc123def456"'
        ),
        secure=(
            '// SECURE — load from environment\n'
            'apiKey := os.Getenv("API_KEY")\n'
            'if apiKey == "" {\n'
            '    log.Fatal("API_KEY not set")\n'
            '}'
        ),
        explanation=(
            "Load secrets from environment variables. Use Viper for "
            "configuration management in Go."
        ),
        principle="Use os.Getenv for secrets — never hardcode in source.",
        practice=(
            "Use Viper or envconfig for configuration. Use Vault SDK "
            "for production secrets. Validate required vars at startup."
        ),
        confidence=90,
    ),
    "terraform": _T(
        vulnerable=(
            '# VULNERABLE — hardcoded credentials in .tf\n'
            'resource "aws_db_instance" "db" {\n'
            '  password = "admin123"\n'
            '}'
        ),
        secure=(
            '# SECURE — use variables with sensitive flag\n'
            'variable "db_password" {\n'
            '  type      = string\n'
            '  sensitive = true\n'
            '}\n'
            '\n'
            'resource "aws_db_instance" "db" {\n'
            '  password = var.db_password\n'
            '}'
        ),
        explanation=(
            "Use Terraform variables marked sensitive for credentials. "
            "Pass values via TF_VAR_ environment variables or Vault."
        ),
        principle="Use sensitive variables — never hardcode secrets in .tf files.",
        practice=(
            "Use terraform-provider-vault for dynamic credentials. "
            "Mark variables as sensitive. Use terraform-docs to "
            "document required variables. Store state in encrypted backend."
        ),
        confidence=90,
    ),
    "dockerfile": _T(
        vulnerable=(
            '# VULNERABLE — secrets in Dockerfile\n'
            'ENV DB_PASSWORD=admin123\n'
            'ENV API_KEY=sk-abc123def456'
        ),
        secure=(
            '# SECURE — use build secrets or runtime env\n'
            '# Use --mount=type=secret for build-time access:\n'
            'RUN --mount=type=secret,id=db_pass cat /run/secrets/db_pass\n'
            '\n'
            '# Or pass at runtime:\n'
            '# docker run -e DB_PASSWORD=$DB_PASSWORD myimage'
        ),
        explanation=(
            "Never bake secrets into Docker images. Use build secrets "
            "or pass environment variables at runtime."
        ),
        principle="Never embed secrets in Dockerfiles — use secrets mounts or runtime env.",
        practice=(
            "Use Docker BuildKit secrets for build-time needs. Pass "
            "secrets as env vars at runtime. Use Docker Secrets or "
            "Vault Agent sidecar in orchestration."
        ),
        confidence=90,
    ),
    "yaml": _T(
        vulnerable=(
            '# VULNERABLE — plain-text secret in K8s manifest\n'
            'apiVersion: v1\n'
            'kind: Pod\n'
            'spec:\n'
            '  containers:\n'
            '  - name: app\n'
            '    env:\n'
            '    - name: DB_PASSWORD\n'
            '      value: "admin123"'
        ),
        secure=(
            '# SECURE — reference K8s Secret\n'
            'apiVersion: v1\n'
            'kind: Pod\n'
            'spec:\n'
            '  containers:\n'
            '  - name: app\n'
            '    env:\n'
            '    - name: DB_PASSWORD\n'
            '      valueFrom:\n'
            '        secretKeyRef:\n'
            '          name: app-secrets\n'
            '          key: db-password'
        ),
        explanation=(
            "Use Kubernetes Secrets (secretKeyRef) instead of plain-text "
            "values. Encrypt secrets at rest with EncryptionConfiguration."
        ),
        principle="Use K8s Secrets or external-secrets-operator — never plain-text values.",
        practice=(
            "Use ExternalSecrets or Sealed Secrets for GitOps. "
            "Enable encryption at rest for etcd. Use RBAC to restrict "
            "Secret access. Rotate secrets automatically."
        ),
        confidence=90,
    ),
    "generic": _T(
        vulnerable='# VULNERABLE — hardcoded credential\nPASSWORD = "admin123"',
        secure='# SECURE — load from environment\nPASSWORD = env("PASSWORD")',
        explanation="Move all secrets to environment variables or a secrets manager.",
        principle="Never store secrets in source code — use external configuration.",
        practice="Use environment variables for secrets. Use a secrets manager in production. Add pre-commit secret scanning.",
        confidence=80,
    ),
}


# ─── SSRF (CWE-918) ─────────────────────────────────────────────────

_SSRF_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — user-controlled URL\n'
            'response = requests.get(user_url)'
        ),
        secure=(
            '# SECURE — URL allowlist validation\n'
            'from urllib.parse import urlparse\n'
            '\n'
            'ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}\n'
            '\n'
            'parsed = urlparse(user_url)\n'
            'if parsed.hostname not in ALLOWED_HOSTS:\n'
            '    raise ValueError("URL not in allowlist")\n'
            'if parsed.scheme not in ("https",):\n'
            '    raise ValueError("Only HTTPS allowed")\n'
            'response = requests.get(user_url, timeout=5)'
        ),
        explanation=(
            "Validate URLs against an allowlist of permitted hostnames. "
            "Block internal/private IP ranges and enforce HTTPS only."
        ),
        principle="Allowlist target hosts — block private IPs and non-HTTPS schemes.",
        practice=(
            "Validate URL scheme, hostname, and port against allowlists. "
            "Block RFC1918 addresses (10.x, 172.16-31.x, 192.168.x) and "
            "link-local (169.254.x). Use DNS resolution checks. Set timeouts."
        ),
        confidence=88,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — user-controlled URL\n'
            'URL url = new URL(userUrl);\n'
            'HttpURLConnection conn = (HttpURLConnection) url.openConnection();'
        ),
        secure=(
            '// SECURE — validate URL against allowlist\n'
            'URL url = new URL(userUrl);\n'
            'if (!ALLOWED_HOSTS.contains(url.getHost())) {\n'
            '    throw new SecurityException("URL not allowed");\n'
            '}\n'
            'if (!"https".equals(url.getProtocol())) {\n'
            '    throw new SecurityException("Only HTTPS allowed");\n'
            '}\n'
            'HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n'
            'conn.setConnectTimeout(5000);'
        ),
        explanation=(
            "Validate URL hostname against an allowlist before making "
            "requests. Block internal addresses and enforce HTTPS."
        ),
        principle="Allowlist target hosts — block private IPs, enforce HTTPS.",
        practice=(
            "Use a URL validation library. Block private IP ranges and "
            "cloud metadata IPs (169.254.169.254). Set connection "
            "timeouts. Use Spring Security's SSRF protection."
        ),
        confidence=88,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — user-controlled URL fetch\n'
            'const response = await fetch(userUrl);'
        ),
        secure=(
            '// SECURE — validate against allowlist\n'
            'const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);\n'
            'const parsed = new URL(userUrl);\n'
            'if (!ALLOWED_HOSTS.has(parsed.hostname)) {\n'
            '    throw new Error("URL not in allowlist");\n'
            '}\n'
            'if (parsed.protocol !== "https:") {\n'
            '    throw new Error("Only HTTPS allowed");\n'
            '}\n'
            'const response = await fetch(userUrl, { signal: AbortSignal.timeout(5000) });'
        ),
        explanation=(
            "Parse and validate the URL hostname against an allowlist. "
            "Block internal addresses and enforce HTTPS."
        ),
        principle="Parse and allowlist-check URLs before fetching — block private ranges.",
        practice=(
            "Use URL constructor for parsing. Block 169.254.169.254 "
            "(cloud metadata). Set request timeouts. Use a proxy for "
            "outbound requests in production."
        ),
        confidence=88,
    ),
    "generic": _T(
        vulnerable='# VULNERABLE — user-controlled URL request\nresponse = http_get(user_url)',
        secure='# SECURE — validate URL against allowlist\nif parsed_url.host not in ALLOWED_HOSTS:\n    raise Error("Blocked")\nresponse = http_get(user_url)',
        explanation="Validate URLs against an allowlist. Block private/internal IPs and metadata endpoints.",
        principle="Allowlist target hosts — block private IPs, cloud metadata, and non-HTTPS.",
        practice="Validate scheme + host. Block RFC1918, link-local, and metadata IPs. Set timeouts. Use proxy.",
        confidence=75,
    ),
}


# ─── Authentication Bypass (CWE-287, CWE-306) ───────────────────────

_AUTH_BYPASS_TEMPLATES: Dict[str, _T] = {
    "python": _T(
        vulnerable=(
            '# VULNERABLE — missing authentication check\n'
            '@app.route("/admin")\n'
            'def admin_panel():\n'
            '    return render_template("admin.html")'
        ),
        secure=(
            '# SECURE — require authentication\n'
            'from functools import wraps\n'
            'def login_required(f):\n'
            '    @wraps(f)\n'
            '    def wrapper(*args, **kwargs):\n'
            '        if not current_user.is_authenticated:\n'
            '            return redirect(url_for("login"))\n'
            '        return f(*args, **kwargs)\n'
            '    return wrapper\n'
            '\n'
            '@app.route("/admin")\n'
            '@login_required\n'
            'def admin_panel():\n'
            '    return render_template("admin.html")'
        ),
        explanation=(
            "Apply authentication checks to all protected routes. Use "
            "framework decorators (Flask @login_required, Django @login_required)."
        ),
        principle="Apply authentication to every protected endpoint — default-deny.",
        practice=(
            "Use Flask-Login or Django auth decorators. Apply default-deny "
            "middleware. Implement rate limiting on auth endpoints. Use "
            "MFA for privileged operations."
        ),
        confidence=85,
    ),
    "java": _T(
        vulnerable=(
            '// VULNERABLE — no authentication on endpoint\n'
            '@GetMapping("/admin")\n'
            'public String adminPanel() {\n'
            '    return "admin";\n'
            '}'
        ),
        secure=(
            '// SECURE — Spring Security configuration\n'
            '@Configuration\n'
            '@EnableWebSecurity\n'
            'public class SecurityConfig {\n'
            '    @Bean\n'
            '    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n'
            '        return http\n'
            '            .authorizeHttpRequests(auth -> auth\n'
            '                .requestMatchers("/admin/**").hasRole("ADMIN")\n'
            '                .requestMatchers("/api/**").authenticated()\n'
            '                .anyRequest().permitAll()\n'
            '            )\n'
            '            .build();\n'
            '    }\n'
            '}'
        ),
        explanation=(
            "Configure Spring Security to require authentication and "
            "authorization for protected endpoints."
        ),
        principle="Use Spring Security with default-deny — explicitly permit only public paths.",
        practice=(
            "Use @PreAuthorize for method-level security. Configure "
            "role hierarchies. Apply CSRF protection. Use Spring "
            "Security's authentication providers."
        ),
        confidence=85,
    ),
    "javascript": _T(
        vulnerable=(
            '// VULNERABLE — no auth middleware\n'
            'app.get("/admin", (req, res) => {\n'
            '    res.render("admin");\n'
            '});'
        ),
        secure=(
            '// SECURE — auth middleware\n'
            'function requireAuth(req, res, next) {\n'
            '    if (!req.session?.userId) {\n'
            '        return res.status(401).json({ error: "Unauthorized" });\n'
            '    }\n'
            '    next();\n'
            '}\n'
            '\n'
            'app.get("/admin", requireAuth, (req, res) => {\n'
            '    res.render("admin");\n'
            '});'
        ),
        explanation=(
            "Apply authentication middleware to protected routes. "
            "Verify session or JWT token before processing."
        ),
        principle="Apply auth middleware to all protected routes — default-deny.",
        practice=(
            "Use Passport.js or express-session for auth. Apply "
            "middleware globally and whitelist public routes. Use "
            "JWT with proper validation (algorithm, expiry, audience)."
        ),
        confidence=85,
    ),
    "generic": _T(
        vulnerable='# VULNERABLE — no authentication check\ndef admin_panel():\n    return sensitive_data',
        secure='# SECURE — verify authentication first\ndef admin_panel():\n    if not is_authenticated(request):\n        raise UnauthorizedError()\n    return sensitive_data',
        explanation="Always verify authentication before processing requests to protected resources.",
        principle="Default-deny — require valid authentication for all non-public endpoints.",
        practice="Apply auth middleware globally. Implement rate limiting. Use MFA for admin routes. Log auth failures.",
        confidence=75,
    ),
}


# ═══════════════════════════════════════════════════════════════════════
# MASTER CWE → TEMPLATE REGISTRY
# ═══════════════════════════════════════════════════════════════════════

# Maps primary CWE to its fix template dict.
# Secondary CWEs alias to the same templates.

_CWE_TEMPLATE_REGISTRY: Dict[str, Dict[str, _T]] = {
    # SQL Injection
    "CWE-89": _SQLI_TEMPLATES,
    "CWE-564": _SQLI_TEMPLATES,   # Hibernate injection
    # XSS
    "CWE-79": _XSS_TEMPLATES,
    "CWE-80": _XSS_TEMPLATES,     # Basic XSS
    # Command Injection
    "CWE-78": _CMDI_TEMPLATES,
    "CWE-77": _CMDI_TEMPLATES,
    # Path Traversal
    "CWE-22": _PATH_TRAV_TEMPLATES,
    "CWE-23": _PATH_TRAV_TEMPLATES,
    "CWE-36": _PATH_TRAV_TEMPLATES,
    # Deserialization
    "CWE-502": _DESER_TEMPLATES,
    # Weak Crypto
    "CWE-327": _CRYPTO_TEMPLATES,
    "CWE-328": _CRYPTO_TEMPLATES,
    "CWE-326": _CRYPTO_TEMPLATES,  # Inadequate encryption strength
    # Hardcoded Secrets
    "CWE-798": _SECRETS_TEMPLATES,
    "CWE-259": _SECRETS_TEMPLATES,
    "CWE-321": _SECRETS_TEMPLATES,  # Hardcoded crypto key
    # SSRF
    "CWE-918": _SSRF_TEMPLATES,
    # Auth Bypass
    "CWE-287": _AUTH_BYPASS_TEMPLATES,
    "CWE-306": _AUTH_BYPASS_TEMPLATES,
    "CWE-862": _AUTH_BYPASS_TEMPLATES,
    "CWE-863": _AUTH_BYPASS_TEMPLATES,
}


# ═══════════════════════════════════════════════════════════════════════
# RULE-ID FALLBACK MAPPING
# ═══════════════════════════════════════════════════════════════════════
#
# When CWE is missing or not in registry, fall back to rule_id prefix
# matching.

_RULE_PREFIX_TO_CWE: List[Tuple[str, str]] = [
    ("SQLI", "CWE-89"),
    ("SQL", "CWE-89"),
    ("XSS", "CWE-79"),
    ("CMD", "CWE-78"),
    ("RCE", "CWE-78"),
    ("EXEC", "CWE-78"),
    ("SHELL", "CWE-78"),
    ("PT-", "CWE-22"),
    ("PATH_TRAV", "CWE-22"),
    ("TRAV", "CWE-22"),
    ("DESER", "CWE-502"),
    ("PICKLE", "CWE-502"),
    ("MARSHAL", "CWE-502"),
    ("CRED", "CWE-798"),
    ("SECRET", "CWE-798"),
    ("HARDCODED", "CWE-798"),
    ("KEY-", "CWE-798"),
    ("TOKEN", "CWE-798"),
    ("PASSWORD", "CWE-798"),
    ("SSRF", "CWE-918"),
    ("AUTH", "CWE-287"),
    ("JWT", "CWE-287"),
    ("LOGIN", "CWE-287"),
    ("CRYPTO", "CWE-327"),
    ("HASH", "CWE-327"),
    ("MD5", "CWE-327"),
    ("SHA1", "CWE-327"),
    ("WEAK_CIPHER", "CWE-327"),
    ("UPLOAD", "CWE-434"),
]


# ═══════════════════════════════════════════════════════════════════════
# FRAMEWORK-SPECIFIC OVERRIDES
# ═══════════════════════════════════════════════════════════════════════
#
# When a specific framework is detected, provide a more tailored fix.

_FRAMEWORK_OVERRIDES: Dict[str, Dict[str, Dict[str, str]]] = {
    # CWE → { framework → { field_overrides } }
    "CWE-89": {
        "django": {
            "secure": (
                '# SECURE — Django ORM (auto-parameterized)\n'
                'user = User.objects.filter(id=user_id).first()\n'
                '\n'
                '# If raw SQL needed:\n'
                'User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])'
            ),
            "explanation": (
                "Use Django ORM methods which auto-parameterize. "
                "For raw SQL, use Model.objects.raw() with params list."
            ),
            "practice": (
                "Use Django ORM .filter(), .exclude(), .get() for queries. "
                "Use F() and Q() for complex conditions. For raw SQL, "
                "always pass params as second argument."
            ),
        },
        "sqlalchemy": {
            "secure": (
                '# SECURE — SQLAlchemy with bound parameters\n'
                'from sqlalchemy import text\n'
                'result = session.execute(\n'
                '    text("SELECT * FROM users WHERE id = :id"),\n'
                '    {"id": user_id}\n'
                ')\n'
                '\n'
                '# Or ORM style:\n'
                'user = session.query(User).filter(User.id == user_id).first()'
            ),
            "explanation": (
                "Use SQLAlchemy text() with named parameters or ORM "
                "query().filter() for type-safe queries."
            ),
        },
        "fastapi": {
            "secure": (
                '# SECURE — FastAPI + SQLAlchemy\n'
                'from sqlalchemy import text\n'
                '\n'
                '@app.get("/users/{user_id}")\n'
                'async def get_user(user_id: int, db: Session = Depends(get_db)):\n'
                '    user = db.query(User).filter(User.id == user_id).first()\n'
                '    if not user:\n'
                '        raise HTTPException(status_code=404)\n'
                '    return user'
            ),
            "explanation": (
                "Use FastAPI path parameter type validation with SQLAlchemy "
                "ORM queries. FastAPI auto-validates the int type."
            ),
        },
        "spring": {
            "secure": (
                '// SECURE — Spring Data JPA\n'
                '@Repository\n'
                'public interface UserRepository extends JpaRepository<User, Long> {\n'
                '    // Auto-generated parameterized query\n'
                '    Optional<User> findById(Long id);\n'
                '\n'
                '    // Named query with params\n'
                '    @Query("SELECT u FROM User u WHERE u.id = :id")\n'
                '    Optional<User> findByUserId(@Param("id") Long id);\n'
                '}'
            ),
            "explanation": (
                "Use Spring Data JPA repository methods. Query derivation "
                "and @Query named parameters are auto-parameterized."
            ),
        },
        "express": {
            "secure": (
                '// SECURE — Express with parameterized query\n'
                'app.get("/users/:id", async (req, res) => {\n'
                '    const { id } = req.params;\n'
                '    const [rows] = await db.query(\n'
                '        "SELECT * FROM users WHERE id = ?",\n'
                '        [id]\n'
                '    );\n'
                '    res.json(rows);\n'
                '});'
            ),
            "explanation": (
                "Use parameterized queries in Express route handlers. "
                "Pass values as array in second argument."
            ),
        },
        "sequelize": {
            "secure": (
                '// SECURE — Sequelize ORM\n'
                'const user = await User.findByPk(userId);\n'
                '\n'
                '// Or with conditions:\n'
                'const users = await User.findAll({\n'
                '    where: { id: userId }\n'
                '});'
            ),
            "explanation": (
                "Use Sequelize model methods which auto-parameterize. "
                "findByPk(), findAll(), findOne() are safe by default."
            ),
        },
        "prisma": {
            "secure": (
                '// SECURE — Prisma ORM (type-safe)\n'
                'const user = await prisma.user.findUnique({\n'
                '    where: { id: userId }\n'
                '});'
            ),
            "explanation": (
                "Prisma generates type-safe queries with auto-parameterization. "
                "findUnique, findMany, create, update are safe."
            ),
        },
        "rails": {
            "secure": (
                '# SECURE — ActiveRecord (auto-parameterized)\n'
                'user = User.find(user_id)\n'
                '\n'
                '# Or with conditions:\n'
                'users = User.where(id: user_id)\n'
                '\n'
                '# If raw SQL needed:\n'
                'User.find_by_sql(["SELECT * FROM users WHERE id = ?", user_id])'
            ),
            "explanation": (
                "Use ActiveRecord methods which auto-parameterize. "
                "find(), where(), find_by() are safe by default."
            ),
        },
        "laravel": {
            "secure": (
                '// SECURE — Laravel Eloquent\n'
                '$user = User::find($userId);\n'
                '\n'
                '// Or with query builder:\n'
                '$user = DB::table("users")->where("id", $userId)->first();'
            ),
            "explanation": (
                "Use Eloquent ORM or Query Builder which auto-parameterize. "
                "find(), where(), first() are safe by default."
            ),
        },
        "efcore": {
            "secure": (
                '// SECURE — Entity Framework Core (LINQ)\n'
                'var user = await context.Users.FindAsync(userId);\n'
                '\n'
                '// Or with LINQ:\n'
                'var user = await context.Users\n'
                '    .Where(u => u.Id == userId)\n'
                '    .FirstOrDefaultAsync();'
            ),
            "explanation": (
                "Use EF Core LINQ queries which generate parameterized SQL. "
                "FindAsync(), Where(), FirstOrDefault() are safe."
            ),
        },
    },
    "CWE-79": {
        "react": {
            "secure": (
                '// SECURE — React JSX auto-escaping\n'
                'function UserGreeting({ name }) {\n'
                '    return <div>Hello, {name}</div>;\n'
                '}\n'
                '\n'
                '// If HTML needed, sanitize:\n'
                'import DOMPurify from "dompurify";\n'
                'function RichContent({ html }) {\n'
                '    return <div dangerouslySetInnerHTML={{\n'
                '        __html: DOMPurify.sanitize(html)\n'
                '    }} />;\n'
                '}'
            ),
            "explanation": (
                "React JSX auto-escapes all interpolated values. "
                "Only use dangerouslySetInnerHTML with DOMPurify-sanitized content."
            ),
        },
        "angular": {
            "secure": (
                '// SECURE — Angular auto-escaping\n'
                '// In template:\n'
                '// <div>{{ userInput }}</div>\n'
                '//\n'
                '// Angular sanitizes by default.\n'
                '// For trusted HTML:\n'
                'import { DomSanitizer } from "@angular/platform-browser";\n'
                'this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(cleanedHtml);'
            ),
            "explanation": (
                "Angular auto-escapes template interpolation. Use "
                "DomSanitizer only for pre-sanitized content."
            ),
        },
        "django": {
            "secure": (
                '# SECURE — Django template auto-escaping\n'
                '# In template: {{ user_input }}  ← auto-escaped\n'
                '#\n'
                '# For rich HTML (pre-sanitized):\n'
                '# {{ rich_content|safe }}\n'
                '#\n'
                '# Server-side sanitization:\n'
                'import bleach\n'
                'clean_html = bleach.clean(user_html, tags=ALLOWED_TAGS)'
            ),
            "explanation": (
                "Django templates auto-escape {{ }} by default. Use "
                "bleach for server-side HTML sanitization."
            ),
        },
    },
    "CWE-78": {
        "flask": {
            "secure": (
                '# SECURE — Flask without shell commands\n'
                'import subprocess\n'
                '\n'
                '@app.route("/convert", methods=["POST"])\n'
                'def convert_file():\n'
                '    filename = secure_filename(request.form["file"])\n'
                '    subprocess.run(\n'
                '        ["convert", filename, "output.pdf"],\n'
                '        shell=False, check=True, timeout=30\n'
                '    )\n'
                '    return send_file("output.pdf")'
            ),
            "explanation": (
                "Use werkzeug.utils.secure_filename() and subprocess.run() "
                "with shell=False and a timeout."
            ),
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════
# FIX GENERATION CORE
# ═══════════════════════════════════════════════════════════════════════


def _resolve_cwe(finding: EngineFinding) -> str:
    """Resolve the primary CWE for a finding.

    Tries: explicit CWE field → rule_id prefix heuristic → empty string.
    """
    cwe = (finding.cwe or "").strip().upper()
    if "," in cwe:
        cwe = cwe.split(",")[0].strip()

    if cwe in _CWE_TEMPLATE_REGISTRY:
        return cwe

    # Fallback: rule_id prefix matching
    rid = finding.rule_id.upper()
    for prefix, mapped_cwe in _RULE_PREFIX_TO_CWE:
        if prefix in rid:
            return mapped_cwe

    # Fallback: vulnerability_type keywords
    vtype = (finding.vulnerability_type or "").lower()
    keyword_map = {
        "sql injection": "CWE-89", "sqli": "CWE-89",
        "xss": "CWE-79", "cross-site scripting": "CWE-79",
        "command injection": "CWE-78", "os command": "CWE-78",
        "path traversal": "CWE-22", "directory traversal": "CWE-22",
        "deserialization": "CWE-502",
        "ssrf": "CWE-918",
        "hardcoded": "CWE-798", "secret": "CWE-798",
        "weak crypto": "CWE-327", "md5": "CWE-327", "sha1": "CWE-327",
        "auth": "CWE-287",
    }
    for kw, mapped_cwe in keyword_map.items():
        if kw in vtype:
            return mapped_cwe

    return cwe  # May be empty or unregistered


def _select_template(
    cwe: str,
    lang: str,
    frameworks: List[str],
) -> Optional[_T]:
    """Select the best fix template for a CWE + language + framework."""
    templates = _CWE_TEMPLATE_REGISTRY.get(cwe)
    if not templates:
        return None

    # Try exact language match, then fallback to generic
    tmpl = templates.get(lang) or templates.get("generic")
    return tmpl


def _apply_framework_override(
    cwe: str,
    frameworks: List[str],
    fix: Dict[str, Any],
) -> Dict[str, Any]:
    """Override template fields if a framework-specific fix exists."""
    overrides = _FRAMEWORK_OVERRIDES.get(cwe)
    if not overrides:
        return fix

    # Map short override keys to fix-dict keys
    _KEY_MAP = {
        "secure": "secure_fix",
        "explanation": "fix_explanation",
        "practice": "best_practice",
        "principle": "security_principle",
        "vulnerable": "vulnerable_code",
        "confidence": "confidence",
        # Also allow full names
        "secure_fix": "secure_fix",
        "fix_explanation": "fix_explanation",
        "best_practice": "best_practice",
        "security_principle": "security_principle",
        "vulnerable_code": "vulnerable_code",
    }

    for fw in frameworks:
        fw_override = overrides.get(fw)
        if fw_override:
            for key, value in fw_override.items():
                mapped = _KEY_MAP.get(key, key)
                if mapped in fix and value:
                    fix[mapped] = value
            break  # Use first matching framework

    return fix


def generate_fix(
    finding: EngineFinding,
    file_content: str = "",
) -> Dict[str, Any]:
    """Generate a secure code fix dict for a single finding.

    Returns:
        {
          "vulnerable_code": "...",
          "secure_fix": "...",
          "fix_explanation": "...",
          "security_principle": "...",
          "best_practice": "...",
          "confidence": 0-100
        }
    """
    ctx = _extract_context(finding, file_content)
    cwe = _resolve_cwe(finding)
    tmpl = _select_template(cwe, ctx["language"], ctx["frameworks"])

    if tmpl is None:
        # No template available — return generic guidance from remediation field
        return {
            "vulnerable_code": finding.code_snippet or finding.matched_pattern or "",
            "secure_fix": finding.remediation or "Apply secure coding practices.",
            "fix_explanation": finding.description or "See vulnerability details.",
            "security_principle": "Follow the principle of least privilege and defense in depth.",
            "best_practice": (
                "Validate all input, encode all output, use parameterized "
                "queries, and follow your framework's security guidelines."
            ),
            "confidence": 50,
        }

    # Build base fix from template
    fix: Dict[str, Any] = {
        "vulnerable_code": tmpl.vulnerable,
        "secure_fix": tmpl.secure,
        "fix_explanation": tmpl.explanation,
        "security_principle": tmpl.principle,
        "best_practice": tmpl.practice,
        "confidence": tmpl.confidence,
    }

    # Apply framework-specific overrides
    fix = _apply_framework_override(cwe, ctx["frameworks"], fix)

    # If finding has actual code_snippet, prepend it to vulnerable_code
    if finding.code_snippet and len(finding.code_snippet) > 10:
        fix["vulnerable_code"] = (
            f"# Your code (line {finding.line}):\n"
            f"{finding.code_snippet.strip()}\n\n"
            f"# Template example:\n"
            f"{fix['vulnerable_code']}"
        )

    return fix


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC PIPELINE INTERFACE
# ═══════════════════════════════════════════════════════════════════════


def apply_remediation(
    findings: List[EngineFinding],
    file_contents: Optional[Dict[str, str]] = None,
) -> List[EngineFinding]:
    """Attach remediation fixes to findings — main pipeline entry point.

    Called after severity normalization, before developer learning mode.
    Attaches a `remediation_fix` dict to each finding.

    Args:
        findings: List of EngineFinding objects.
        file_contents: Optional file content map.

    Returns:
        Same findings list with `remediation_fix` attribute attached.
    """
    if not findings:
        return findings

    file_contents = file_contents or {}
    enriched = 0

    for finding in findings:
        content = file_contents.get(finding.file_name, "")
        fix = generate_fix(finding, content)
        finding.remediation_fix = fix  # type: ignore[attr-defined]
        enriched += 1

    logger.info(
        "Remediation engine: %d findings enriched with secure code fixes.",
        enriched,
    )

    return findings


def get_remediation_report(
    findings: List[EngineFinding],
    file_contents: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Generate a standalone remediation report.

    Returns a list of dicts — one per finding — with full fix details
    plus finding metadata. For use by report generators or API endpoints.
    """
    file_contents = file_contents or {}
    report: List[Dict[str, Any]] = []

    for finding in findings:
        content = file_contents.get(finding.file_name, "")
        fix = generate_fix(finding, content)

        report.append({
            "rule_id": finding.rule_id,
            "rule_title": finding.rule_title,
            "vulnerability_type": finding.vulnerability_type,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "file": finding.file_name,
            "line": finding.line,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            **fix,
        })

    return report


def get_supported_cwe_list() -> List[str]:
    """Return list of CWEs with fix templates."""
    return sorted(_CWE_TEMPLATE_REGISTRY.keys())


def get_supported_languages() -> List[str]:
    """Return list of languages with fix templates."""
    langs: set = set()
    for templates in _CWE_TEMPLATE_REGISTRY.values():
        langs.update(k for k in templates.keys() if k != "generic")
    return sorted(langs)
