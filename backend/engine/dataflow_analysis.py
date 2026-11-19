"""
Lightweight Dataflow Analysis Engine — taint tracking without AST parsing.

Performs regex-based source → variable → sink taint propagation to detect
data flow chains and boost (or reduce) confidence on findings that
correlate with actual user-controlled data flows.

Pipeline position:
    Detection → Rule Intelligence → Logic Detectors
    → **Dataflow Analysis** → False Positive Control → Clustering

Design Constraints:
    - Deterministic: NO AI, NO randomness, NO external calls
    - Performance: O(n × L) where n = findings, L = avg file lines
    - No AST/CFG/SSA: purely text/regex-based heuristics
    - Multi-language: source/sink/propagation patterns per language
    - Thread-safe: operates on mutable EngineFinding objects in main process

Architecture:
    1. Source Detection — identify user-controlled input origins per line
    2. Variable Propagation — track taint through assignments
    3. Sink Detection — identify dangerous function calls per line
    4. Chain Validation — connect source → propagation → sink to form
       taint chains, then adjust finding confidence accordingly

Taint Chain Confidence Adjustments:
    - Source+Sink confirmed chain:    +20 confidence
    - Source detected, no sink path:  +5  confidence (partial evidence)
    - Sink detected, no source:       -10 confidence (likely safe input)
    - Neither source nor sink:        no adjustment
"""

import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.dataflow_analysis")

# ═══════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class TaintSource:
    """A detected user-controlled input source."""
    line: int          # 1-based line number
    variable: str      # assigned variable name (if extractable)
    source_type: str   # e.g. "http_param", "cookie", "env_var"
    raw_match: str     # the matched text


@dataclass
class TaintSink:
    """A detected dangerous sink invocation."""
    line: int          # 1-based line number
    sink_type: str     # e.g. "sql_exec", "command_exec", "eval"
    raw_match: str     # the matched text
    arguments: str     # extracted argument text (approximate)


@dataclass
class TaintPropagation:
    """A variable assignment that propagates taint."""
    line: int          # 1-based line number
    target_var: str    # variable being assigned to
    source_var: str    # variable being read from (tainted)


@dataclass
class TaintChain:
    """A complete taint chain from source through propagation to sink."""
    source: TaintSource
    propagations: List[TaintPropagation]
    sink: TaintSink
    chain_length: int   # number of hops
    confidence_boost: float  # how much to increase finding confidence


@dataclass
class FileTaintMap:
    """Taint analysis results for a single file."""
    file_name: str
    sources: List[TaintSource] = field(default_factory=list)
    sinks: List[TaintSink] = field(default_factory=list)
    propagations: List[TaintPropagation] = field(default_factory=list)
    chains: List[TaintChain] = field(default_factory=list)
    tainted_vars: Set[str] = field(default_factory=set)


# ═══════════════════════════════════════════════════════════════════════
# 1. SOURCE DETECTION PATTERNS
# ═══════════════════════════════════════════════════════════════════════

# Language → list of (compiled_regex, source_type, variable_group_index)
# variable_group_index: which regex group captures the assigned variable
# (0 = no variable extraction)

_SOURCE_PATTERNS_RAW: Dict[str, List[Tuple[str, str, int]]] = {
    "python": [
        # Flask/Django request parameters
        (r"(\w+)\s*=\s*request\.(args|form|values|json|data|cookies|headers)\b", "http_param", 1),
        (r"(\w+)\s*=\s*request\.(args|form|values|json|data|cookies|headers)\s*\.\s*get\s*\(", "http_param", 1),
        (r"(\w+)\s*=\s*request\.(args|form|values|json|data|cookies|headers)\s*\[", "http_param", 1),
        # Django
        (r"(\w+)\s*=\s*request\.(GET|POST|FILES|META|COOKIES)\b", "http_param", 1),
        (r"(\w+)\s*=\s*request\.(GET|POST|FILES|META|COOKIES)\s*\.\s*get\s*\(", "http_param", 1),
        (r"(\w+)\s*=\s*request\.(GET|POST|FILES|META|COOKIES)\s*\[", "http_param", 1),
        # Environment variables
        (r"(\w+)\s*=\s*os\.environ\b", "env_var", 1),
        (r"(\w+)\s*=\s*os\.environ\s*\.\s*get\s*\(", "env_var", 1),
        (r"(\w+)\s*=\s*os\.getenv\s*\(", "env_var", 1),
        # File input
        (r"(\w+)\s*=\s*(?:open|read)\s*\(", "file_input", 1),
        # sys.argv
        (r"(\w+)\s*=\s*sys\.argv\b", "cli_arg", 1),
        # input() builtin
        (r"(\w+)\s*=\s*input\s*\(", "user_input", 1),
    ],
    "java": [
        # Servlet request
        (r"(\w+)\s*=\s*\w*request\.getParameter\s*\(", "http_param", 1),
        (r"(\w+)\s*=\s*\w*request\.getParameterValues\s*\(", "http_param", 1),
        (r"(\w+)\s*=\s*\w*request\.getHeader\s*\(", "http_header", 1),
        (r"(\w+)\s*=\s*\w*request\.getCookies\s*\(", "cookie", 1),
        (r"(\w+)\s*=\s*\w*request\.getInputStream\s*\(", "http_body", 1),
        (r"(\w+)\s*=\s*\w*request\.getReader\s*\(", "http_body", 1),
        (r"(\w+)\s*=\s*\w*request\.getQueryString\s*\(", "http_param", 1),
        (r"(\w+)\s*=\s*\w*request\.getRequestURI\s*\(", "http_param", 1),
        # Spring MVC
        (r"@RequestParam\b.*?\b(\w+)\s*[,\)]", "http_param", 1),
        (r"@PathVariable\b.*?\b(\w+)\s*[,\)]", "http_param", 1),
        (r"@RequestBody\b.*?\b(\w+)\s*[,\)]", "http_body", 1),
        (r"@RequestHeader\b.*?\b(\w+)\s*[,\)]", "http_header", 1),
        (r"@CookieValue\b.*?\b(\w+)\s*[,\)]", "cookie", 1),
        # Environment
        (r"(\w+)\s*=\s*System\.getenv\s*\(", "env_var", 1),
        (r"(\w+)\s*=\s*System\.getProperty\s*\(", "env_var", 1),
    ],
    "javascript": [
        # Express.js
        (r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(body|query|params|cookies|headers)\b", "http_param", 1),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(body|query|params|cookies|headers)\s*\[", "http_param", 1),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(body|query|params|cookies|headers)\s*\.\s*\w+", "http_param", 1),
        (r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)", "http_param", 1),
        # URL / search params
        (r"(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+)?URL\b", "url_param", 1),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*\w*\.searchParams\.\w+\s*\(", "url_param", 1),
        # Environment
        (r"(?:const|let|var)\s+(\w+)\s*=\s*process\.env\b", "env_var", 1),
        # Destructured body
        (r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*req\.body", "http_param", 1),
        # window.location
        (r"(?:const|let|var)\s+(\w+)\s*=\s*(?:window\.)?location\.(search|hash|href|pathname)", "url_param", 1),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*document\.cookie\b", "cookie", 1),
    ],
    "typescript": [
        # Same as JavaScript plus typed patterns
        (r"(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*req\.(body|query|params|cookies|headers)\b", "http_param", 1),
        (r"(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*req\.(body|query|params|cookies|headers)\s*\[", "http_param", 1),
        (r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)", "http_param", 1),
        (r"(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*process\.env\b", "env_var", 1),
        (r"(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:window\.)?location\.(search|hash|href)", "url_param", 1),
    ],
    "php": [
        (r"(\$\w+)\s*=\s*\$_GET\s*\[", "http_param", 1),
        (r"(\$\w+)\s*=\s*\$_POST\s*\[", "http_param", 1),
        (r"(\$\w+)\s*=\s*\$_REQUEST\s*\[", "http_param", 1),
        (r"(\$\w+)\s*=\s*\$_COOKIE\s*\[", "cookie", 1),
        (r"(\$\w+)\s*=\s*\$_SERVER\s*\[", "http_header", 1),
        (r"(\$\w+)\s*=\s*\$_FILES\s*\[", "file_upload", 1),
        (r"(\$\w+)\s*=\s*\$_ENV\s*\[", "env_var", 1),
        (r"(\$\w+)\s*=\s*file_get_contents\s*\(\s*['\"]php://input", "http_body", 1),
        (r"(\$\w+)\s*=\s*getenv\s*\(", "env_var", 1),
    ],
    "ruby": [
        (r"(\w+)\s*=\s*params\s*\[", "http_param", 1),
        (r"(\w+)\s*=\s*params\.\w+\s*\(", "http_param", 1),
        (r"(\w+)\s*=\s*request\.(headers|cookies|body|query_string)\b", "http_param", 1),
        (r"(\w+)\s*=\s*cookies\s*\[", "cookie", 1),
        (r"(\w+)\s*=\s*ENV\s*\[", "env_var", 1),
    ],
    "go": [
        (r"(\w+)\s*:?=\s*r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get|Cookie)\s*\(", "http_param", 1),
        (r"(\w+)\s*:?=\s*c\.(?:Query|Param|FormValue|GetHeader|Cookie)\s*\(", "http_param", 1),
        (r"(\w+)\s*:?=\s*os\.Getenv\s*\(", "env_var", 1),
        (r"(\w+)\s*:?=\s*r\.Body\b", "http_body", 1),
    ],
    "csharp": [
        (r"(\w+)\s*=\s*Request\.(Query|Form|QueryString|Cookies|Headers)\s*\[", "http_param", 1),
        (r"(\w+)\s*=\s*HttpContext\.\w*\.Request\.\w+", "http_param", 1),
        (r"(\w+)\s*=\s*Environment\.GetEnvironmentVariable\s*\(", "env_var", 1),
        # ASP.NET Core model binding
        (r"\[FromQuery\]\s*\w+\s+(\w+)", "http_param", 1),
        (r"\[FromBody\]\s*\w+\s+(\w+)", "http_body", 1),
        (r"\[FromHeader\]\s*\w+\s+(\w+)", "http_header", 1),
        (r"\[FromRoute\]\s*\w+\s+(\w+)", "http_param", 1),
    ],
    "kotlin": [
        (r"(?:val|var)\s+(\w+)\s*=\s*request\.\w*(?:getParameter|getHeader|getCookies)\s*\(", "http_param", 1),
        (r"@RequestParam\b.*?\b(\w+)\s*[,:\)]", "http_param", 1),
        (r"@PathVariable\b.*?\b(\w+)\s*[,:\)]", "http_param", 1),
        (r"@RequestBody\b.*?\b(\w+)\s*[,:\)]", "http_body", 1),
        (r"(?:val|var)\s+(\w+)\s*=\s*System\.getenv\s*\(", "env_var", 1),
    ],
    "swift": [
        (r"(?:let|var)\s+(\w+)\s*=\s*request\.\w+", "http_param", 1),
        (r"(?:let|var)\s+(\w+)\s*=\s*ProcessInfo\.processInfo\.environment\b", "env_var", 1),
        (r"(?:let|var)\s+(\w+)\s*=\s*URLComponents\b", "url_param", 1),
    ],
    "rust": [
        (r"let\s+(?:mut\s+)?(\w+)\s*=\s*(?:req|request)\.\w+\s*\(", "http_param", 1),
        (r"let\s+(?:mut\s+)?(\w+)\s*=\s*std::env::var\s*\(", "env_var", 1),
        (r"let\s+(?:mut\s+)?(\w+)\s*=\s*std::env::args\s*\(", "cli_arg", 1),
    ],
}

# Compiled source patterns (lazy)
_SOURCE_COMPILED: Dict[str, List[Tuple[re.Pattern, str, int]]] = {}


# ═══════════════════════════════════════════════════════════════════════
# 2. SINK DETECTION PATTERNS
# ═══════════════════════════════════════════════════════════════════════

# Language → list of (pattern, sink_type)
_SINK_PATTERNS_RAW: Dict[str, List[Tuple[str, str]]] = {
    "python": [
        # SQL
        (r"cursor\.execute\s*\(", "sql_exec"),
        (r"\.execute\s*\(.*%", "sql_exec"),
        (r"\.raw\s*\(", "sql_exec"),
        (r"connection\.execute\s*\(", "sql_exec"),
        # Command execution
        (r"os\.system\s*\(", "command_exec"),
        (r"os\.popen\s*\(", "command_exec"),
        (r"subprocess\.\w+\s*\(", "command_exec"),
        (r"commands\.\w+\s*\(", "command_exec"),
        # Eval / code injection
        (r"\beval\s*\(", "eval"),
        (r"\bexec\s*\(", "eval"),
        (r"compile\s*\(", "eval"),
        # Deserialization
        (r"pickle\.loads?\s*\(", "deserialization"),
        (r"yaml\.(?:load|unsafe_load)\s*\(", "deserialization"),
        (r"marshal\.loads?\s*\(", "deserialization"),
        # Template rendering
        (r"render_template\s*\(", "template_render"),
        (r"render_template_string\s*\(", "template_render"),
        (r"Markup\s*\(", "template_render"),
        # File operations
        (r"open\s*\([^)]*['\"]w", "file_write"),
        (r"\.write\s*\(", "file_write"),
        # LDAP
        (r"\.search_s?\s*\(", "ldap_query"),
        # SSRF
        (r"requests\.\w+\s*\(", "http_request"),
        (r"urllib\.\w+\.urlopen\s*\(", "http_request"),
    ],
    "java": [
        # SQL
        (r"Statement\.\w*execute\w*\s*\(", "sql_exec"),
        (r"createStatement\s*\(", "sql_exec"),
        (r"\.executeQuery\s*\(", "sql_exec"),
        (r"\.executeUpdate\s*\(", "sql_exec"),
        # Command execution
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "command_exec"),
        (r"ProcessBuilder\s*\(", "command_exec"),
        # Eval / JNDI
        (r"ScriptEngine\.\w*eval\s*\(", "eval"),
        (r"\.lookup\s*\(", "jndi_lookup"),
        # SpEL
        (r"parseExpression\s*\(", "expression_eval"),
        (r"ExpressionParser\b", "expression_eval"),
        # Deserialization
        (r"ObjectInputStream\s*\(", "deserialization"),
        (r"\.readObject\s*\(", "deserialization"),
        (r"XMLDecoder\s*\(", "deserialization"),
        # File
        (r"FileWriter\s*\(", "file_write"),
        (r"FileOutputStream\s*\(", "file_write"),
        # SSRF
        (r"URL\s*\(", "http_request"),
        (r"HttpURLConnection\b", "http_request"),
        (r"HttpClient\.\w+\s*\(", "http_request"),
    ],
    "javascript": [
        # SQL
        (r"\.query\s*\(", "sql_exec"),
        (r"\.execute\s*\(", "sql_exec"),
        (r"knex\.raw\s*\(", "sql_exec"),
        (r"sequelize\.query\s*\(", "sql_exec"),
        # Command execution
        (r"child_process\.\w+\s*\(", "command_exec"),
        (r"\bexec\s*\(", "command_exec"),
        (r"\bexecSync\s*\(", "command_exec"),
        # Eval
        (r"\beval\s*\(", "eval"),
        (r"new\s+Function\s*\(", "eval"),
        (r"setTimeout\s*\(\s*['\"]", "eval"),
        (r"setInterval\s*\(\s*['\"]", "eval"),
        # DOM sinks (XSS)
        (r"\.innerHTML\s*=", "dom_xss"),
        (r"\.outerHTML\s*=", "dom_xss"),
        (r"document\.write\s*\(", "dom_xss"),
        (r"\.insertAdjacentHTML\s*\(", "dom_xss"),
        # Deserialization
        (r"node-serialize\b", "deserialization"),
        (r"\.deserialize\s*\(", "deserialization"),
        # SSRF
        (r"fetch\s*\(", "http_request"),
        (r"axios\.\w+\s*\(", "http_request"),
        (r"http\.request\s*\(", "http_request"),
        # Template
        (r"\.render\s*\(", "template_render"),
        (r"\.compile\s*\(", "template_compile"),
    ],
    "typescript": [
        # Inherits JavaScript patterns plus typed constructors
        (r"\.query\s*\(", "sql_exec"),
        (r"\.execute\s*\(", "sql_exec"),
        (r"\beval\s*\(", "eval"),
        (r"new\s+Function\s*\(", "eval"),
        (r"\.innerHTML\s*=", "dom_xss"),
        (r"document\.write\s*\(", "dom_xss"),
        (r"child_process\.\w+\s*\(", "command_exec"),
        (r"fetch\s*\(", "http_request"),
        (r"axios\.\w+\s*\(", "http_request"),
        (r"\.render\s*\(", "template_render"),
    ],
    "php": [
        # SQL
        (r"mysql_query\s*\(", "sql_exec"),
        (r"mysqli_query\s*\(", "sql_exec"),
        (r"\->query\s*\(", "sql_exec"),
        (r"pg_query\s*\(", "sql_exec"),
        # Command execution
        (r"\bsystem\s*\(", "command_exec"),
        (r"\bexec\s*\(", "command_exec"),
        (r"\bpassthru\s*\(", "command_exec"),
        (r"\bshell_exec\s*\(", "command_exec"),
        (r"\bpopen\s*\(", "command_exec"),
        (r"\bproc_open\s*\(", "command_exec"),
        (r"`[^`]*`", "command_exec"),
        # Eval
        (r"\beval\s*\(", "eval"),
        (r"\bassert\s*\(", "eval"),
        (r"\bpreg_replace\s*\(\s*['\"]/.*/e", "eval"),
        # File
        (r"\binclude\s*\(", "file_include"),
        (r"\brequire\s*\(", "file_include"),
        (r"\bfile_put_contents\s*\(", "file_write"),
        (r"\bfwrite\s*\(", "file_write"),
        # Deserialization
        (r"\bunserialize\s*\(", "deserialization"),
        # SSRF
        (r"\bfile_get_contents\s*\(", "http_request"),
        (r"\bcurl_exec\s*\(", "http_request"),
    ],
    "ruby": [
        # SQL
        (r"\.execute\s*\(", "sql_exec"),
        (r"\.find_by_sql\s*\(", "sql_exec"),
        (r"ActiveRecord::Base\.connection\.execute", "sql_exec"),
        (r"\.where\s*\(\s*['\"]", "sql_exec"),
        # Command execution
        (r"\bsystem\s*\(", "command_exec"),
        (r"\bexec\s*\(", "command_exec"),
        (r"`[^`]*`", "command_exec"),
        (r"%x\{", "command_exec"),
        (r"Open3\.\w+\s*\(", "command_exec"),
        # Eval
        (r"\beval\s*\(", "eval"),
        (r"\.send\s*\(", "eval"),
        (r"\.constantize\b", "eval"),
        # Deserialization
        (r"Marshal\.load\s*\(", "deserialization"),
        (r"YAML\.load\s*\(", "deserialization"),
        # Template
        (r"\.render\s*\(", "template_render"),
        (r"ERB\.new\s*\(", "template_render"),
    ],
    "go": [
        # SQL
        (r"\.Query\s*\(", "sql_exec"),
        (r"\.QueryRow\s*\(", "sql_exec"),
        (r"\.Exec\s*\(", "sql_exec"),
        (r"db\.Raw\s*\(", "sql_exec"),
        # Command execution
        (r"exec\.Command\s*\(", "command_exec"),
        (r"exec\.CommandContext\s*\(", "command_exec"),
        # Template
        (r"template\.HTML\s*\(", "template_render"),
        (r"\.Execute\s*\(", "template_render"),
        # SSRF
        (r"http\.Get\s*\(", "http_request"),
        (r"http\.Post\s*\(", "http_request"),
        (r"http\.NewRequest\s*\(", "http_request"),
    ],
    "csharp": [
        # SQL
        (r"SqlCommand\s*\(", "sql_exec"),
        (r"\.ExecuteReader\s*\(", "sql_exec"),
        (r"\.ExecuteNonQuery\s*\(", "sql_exec"),
        (r"\.ExecuteScalar\s*\(", "sql_exec"),
        (r"\.FromSqlRaw\s*\(", "sql_exec"),
        # Command execution
        (r"Process\.Start\s*\(", "command_exec"),
        (r"ProcessStartInfo\s*\(", "command_exec"),
        # Deserialization
        (r"BinaryFormatter\s*\(", "deserialization"),
        (r"\.Deserialize\s*\(", "deserialization"),
        (r"JsonConvert\.DeserializeObject\s*\(", "deserialization"),
        # File
        (r"File\.WriteAllText\s*\(", "file_write"),
        (r"StreamWriter\s*\(", "file_write"),
        # SSRF
        (r"HttpClient\.\w+Async\s*\(", "http_request"),
        (r"WebClient\.\w+\s*\(", "http_request"),
    ],
    "kotlin": [
        (r"\.execute\s*\(", "sql_exec"),
        (r"\.executeQuery\s*\(", "sql_exec"),
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "command_exec"),
        (r"ProcessBuilder\s*\(", "command_exec"),
        (r"ObjectInputStream\s*\(", "deserialization"),
    ],
    "swift": [
        (r"\.execute\s*\(", "sql_exec"),
        (r"Process\s*\(", "command_exec"),
        (r"NSTask\b", "command_exec"),
        (r"URLSession\.\w+\.\w+\s*\(", "http_request"),
    ],
    "rust": [
        (r"\.execute\s*\(", "sql_exec"),
        (r"sqlx::query\s*!?\s*\(", "sql_exec"),
        (r"Command::new\s*\(", "command_exec"),
        (r"\.spawn\s*\(", "command_exec"),
    ],
}

# Compiled sink patterns (lazy)
_SINK_COMPILED: Dict[str, List[Tuple[re.Pattern, str]]] = {}


# ═══════════════════════════════════════════════════════════════════════
# 3. VARIABLE PROPAGATION PATTERNS
# ═══════════════════════════════════════════════════════════════════════

# Generic assignment patterns — extract (target_var, source_expression)
_ASSIGNMENT_PATTERNS: Dict[str, List[str]] = {
    "python": [
        r"(\w+)\s*=\s*(.+?)$",
    ],
    "java": [
        r"(?:(?:String|int|long|Object|var|final)\s+)?(\w+)\s*=\s*(.+?)\s*;",
    ],
    "javascript": [
        r"(?:const|let|var)\s+(\w+)\s*=\s*(.+?)\s*;?$",
    ],
    "typescript": [
        r"(?:const|let|var)\s+(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=\s*(.+?)\s*;?$",
    ],
    "php": [
        r"(\$\w+)\s*=\s*(.+?)\s*;",
    ],
    "ruby": [
        r"(\w+)\s*=\s*(.+?)$",
    ],
    "go": [
        r"(\w+)\s*:?=\s*(.+?)$",
    ],
    "csharp": [
        r"(?:(?:string|int|var|object)\s+)?(\w+)\s*=\s*(.+?)\s*;",
    ],
    "kotlin": [
        r"(?:val|var)\s+(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=\s*(.+?)$",
    ],
    "swift": [
        r"(?:let|var)\s+(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=\s*(.+?)$",
    ],
    "rust": [
        r"let\s+(?:mut\s+)?(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=\s*(.+?)\s*;",
    ],
}

# Compiled assignment patterns (lazy)
_ASSIGN_COMPILED: Dict[str, List[re.Pattern]] = {}


# ═══════════════════════════════════════════════════════════════════════
# PATTERN COMPILATION
# ═══════════════════════════════════════════════════════════════════════

def _get_source_patterns(lang: str) -> List[Tuple[re.Pattern, str, int]]:
    """Get compiled source patterns for a language."""
    lang = lang.lower()
    if lang not in _SOURCE_COMPILED:
        raw = _SOURCE_PATTERNS_RAW.get(lang, [])
        compiled = []
        for pat_str, src_type, grp in raw:
            try:
                compiled.append((re.compile(pat_str, re.IGNORECASE), src_type, grp))
            except re.error:
                logger.warning("Failed to compile source pattern: %s", pat_str)
        _SOURCE_COMPILED[lang] = compiled
    return _SOURCE_COMPILED[lang]


def _get_sink_patterns(lang: str) -> List[Tuple[re.Pattern, str]]:
    """Get compiled sink patterns for a language."""
    lang = lang.lower()
    if lang not in _SINK_COMPILED:
        raw = _SINK_PATTERNS_RAW.get(lang, [])
        compiled = []
        for pat_str, sink_type in raw:
            try:
                compiled.append((re.compile(pat_str, re.IGNORECASE), sink_type))
            except re.error:
                logger.warning("Failed to compile sink pattern: %s", pat_str)
        _SINK_COMPILED[lang] = compiled
    return _SINK_COMPILED[lang]


def _get_assignment_patterns(lang: str) -> List[re.Pattern]:
    """Get compiled assignment patterns for a language."""
    lang = lang.lower()
    if lang not in _ASSIGN_COMPILED:
        raw = _ASSIGNMENT_PATTERNS.get(lang, [])
        compiled = []
        for pat_str in raw:
            try:
                compiled.append(re.compile(pat_str, re.MULTILINE))
            except re.error:
                logger.warning("Failed to compile assignment pattern: %s", pat_str)
        _ASSIGN_COMPILED[lang] = compiled
    return _ASSIGN_COMPILED[lang]


# ═══════════════════════════════════════════════════════════════════════
# LANGUAGE DETECTION
# ═══════════════════════════════════════════════════════════════════════

_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".swift": "swift",
    ".rs": "rust",
    ".scala": "scala",
}


def _detect_language(file_name: str) -> str:
    """Infer language from file extension."""
    _, ext = os.path.splitext(file_name.lower())
    return _EXT_TO_LANG.get(ext, "")


# ═══════════════════════════════════════════════════════════════════════
# CORE ANALYSIS FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _analyze_sources(lines: List[str], lang: str) -> List[TaintSource]:
    """Scan file lines for user-controlled input sources."""
    sources: List[TaintSource] = []
    patterns = _get_source_patterns(lang)
    if not patterns:
        return sources

    for line_num, line_text in enumerate(lines, 1):
        stripped = line_text.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue

        for pat, src_type, var_group in patterns:
            m = pat.search(line_text)
            if m:
                var_name = ""
                if var_group > 0:
                    try:
                        var_name = m.group(var_group).strip()
                        # Handle destructured assignments: {a, b, c}
                        if "," in var_name:
                            for v in var_name.split(","):
                                v = v.strip().lstrip("{").rstrip("}")
                                if v:
                                    sources.append(TaintSource(
                                        line=line_num,
                                        variable=v,
                                        source_type=src_type,
                                        raw_match=m.group(0)[:100],
                                    ))
                            continue
                    except IndexError:
                        var_name = ""

                sources.append(TaintSource(
                    line=line_num,
                    variable=var_name,
                    source_type=src_type,
                    raw_match=m.group(0)[:100],
                ))
                break  # one source per line is enough

    return sources


def _analyze_sinks(lines: List[str], lang: str) -> List[TaintSink]:
    """Scan file lines for dangerous sinks."""
    sinks: List[TaintSink] = []
    patterns = _get_sink_patterns(lang)
    if not patterns:
        return sinks

    for line_num, line_text in enumerate(lines, 1):
        stripped = line_text.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue

        for pat, sink_type in patterns:
            m = pat.search(line_text)
            if m:
                # Extract approximate argument context
                arg_start = m.end()
                arg_text = line_text[arg_start:arg_start + 100].strip()

                sinks.append(TaintSink(
                    line=line_num,
                    sink_type=sink_type,
                    raw_match=m.group(0)[:100],
                    arguments=arg_text,
                ))
                break  # one sink per line

    return sinks


def _propagate_taint(
    lines: List[str],
    lang: str,
    tainted_vars: Set[str],
) -> Tuple[Set[str], List[TaintPropagation]]:
    """Track taint propagation through variable assignments.

    Starting from initially tainted variables (from sources), scans
    assignments to find new variables that receive tainted values.

    Performs up to MAX_PROPAGATION_PASSES to follow multi-hop chains.

    Returns (expanded_tainted_vars, propagation_records).
    """
    MAX_PROPAGATION_PASSES = 3  # prevent O(n²) on pathological inputs
    assign_patterns = _get_assignment_patterns(lang)
    if not assign_patterns:
        return tainted_vars, []

    propagations: List[TaintPropagation] = []
    all_tainted = set(tainted_vars)

    for _pass in range(MAX_PROPAGATION_PASSES):
        new_tainted = set()
        for line_num, line_text in enumerate(lines, 1):
            stripped = line_text.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue

            for pat in assign_patterns:
                m = pat.search(line_text)
                if m:
                    target_var = m.group(1).strip()
                    source_expr = m.group(2).strip() if m.lastindex >= 2 else ""

                    # Check if source expression references any tainted variable
                    for tv in all_tainted:
                        if tv and tv in source_expr:
                            if target_var not in all_tainted:
                                new_tainted.add(target_var)
                                propagations.append(TaintPropagation(
                                    line=line_num,
                                    target_var=target_var,
                                    source_var=tv,
                                ))
                            break

        if not new_tainted:
            break  # Fixed point reached
        all_tainted |= new_tainted

    return all_tainted, propagations


def _build_taint_chains(
    sources: List[TaintSource],
    sinks: List[TaintSink],
    propagations: List[TaintPropagation],
    tainted_vars: Set[str],
) -> List[TaintChain]:
    """Build source → sink chains using tainted variable information.

    A chain exists when:
    1. A source introduces a tainted variable
    2. That variable (or a variable tainted through propagation) appears
       in a sink's arguments or on a sink's line
    3. The sink appears AFTER the source in the file (line order)
    """
    chains: List[TaintChain] = []

    for sink in sinks:
        # Check if any tainted variable appears in the sink's arguments or raw_match
        sink_text = (sink.arguments + " " + sink.raw_match).lower()
        matching_vars = [v for v in tainted_vars if v.lower() in sink_text]

        if not matching_vars:
            continue

        # Find the originating source for each matching variable
        for var in matching_vars:
            # Find the source that introduced this variable (or its ancestor)
            best_source = None
            chain_props = []

            # Direct source match
            for src in sources:
                if src.variable == var and src.line < sink.line:
                    best_source = src
                    break

            # If not direct, trace through propagations
            if not best_source:
                # Find the propagation that created this variable
                for prop in propagations:
                    if prop.target_var == var and prop.line < sink.line:
                        chain_props.append(prop)
                        # Now find the source of prop.source_var
                        for src in sources:
                            if src.variable == prop.source_var and src.line < prop.line:
                                best_source = src
                                break
                        if best_source:
                            break

            if best_source:
                chain_length = 1 + len(chain_props)
                # Confidence boost decreases with longer chains (less certain)
                conf_boost = max(5.0, 20.0 - (chain_length - 1) * 5.0)

                chains.append(TaintChain(
                    source=best_source,
                    propagations=chain_props,
                    sink=sink,
                    chain_length=chain_length,
                    confidence_boost=conf_boost,
                ))

    return chains


def analyze_file_taint(
    file_name: str,
    content: str,
) -> FileTaintMap:
    """Perform complete taint analysis on a single file.

    Returns a FileTaintMap with all detected sources, sinks,
    propagations, chains, and tainted variables.
    """
    lang = _detect_language(file_name)
    if not lang:
        return FileTaintMap(file_name=file_name)

    lines = content.splitlines()

    # Step 1: Detect sources
    sources = _analyze_sources(lines, lang)

    # Step 2: Detect sinks
    sinks = _analyze_sinks(lines, lang)

    # If no sources or no sinks, no chains possible
    if not sources and not sinks:
        return FileTaintMap(file_name=file_name)

    # Step 3: Propagate taint from source variables
    initial_tainted = {s.variable for s in sources if s.variable}
    tainted_vars, propagations = _propagate_taint(lines, lang, initial_tainted)

    # Step 4: Build chains
    chains = _build_taint_chains(sources, sinks, propagations, tainted_vars)

    return FileTaintMap(
        file_name=file_name,
        sources=sources,
        sinks=sinks,
        propagations=propagations,
        chains=chains,
        tainted_vars=tainted_vars,
    )


# ═══════════════════════════════════════════════════════════════════════
# CONFIDENCE ADJUSTMENT
# ═══════════════════════════════════════════════════════════════════════

# Confidence adjustments based on taint analysis results
CHAIN_CONFIRMED_BOOST = 20.0     # Source → Sink chain confirmed
SOURCE_ONLY_BOOST = 5.0          # Source detected near finding, no full chain
SINK_NO_SOURCE_PENALTY = -10.0   # Sink detected but no untrusted source


def _adjust_finding_confidence(
    finding: EngineFinding,
    taint_map: FileTaintMap,
) -> bool:
    """Adjust a finding's confidence based on taint analysis.

    Returns True if adjustment was made.
    """
    finding_line = finding.line
    adjusted = False

    # Check if finding line is near a confirmed taint chain
    for chain in taint_map.chains:
        # Chain covers from source line to sink line
        if chain.source.line <= finding_line <= chain.sink.line + 5:
            base = finding.adjusted_confidence or finding.confidence
            boost = min(chain.confidence_boost, 100.0 - base)
            finding.adjusted_confidence = min(100.0, base + boost)
            if "dataflow_chain_confirmed" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("dataflow_chain_confirmed")
            adjusted = True
            break

    if adjusted:
        return True

    # Check if finding is near a source (but no full chain)
    for src in taint_map.sources:
        if abs(src.line - finding_line) <= 20:
            base = finding.adjusted_confidence or finding.confidence
            boost = min(SOURCE_ONLY_BOOST, 100.0 - base)
            finding.adjusted_confidence = min(100.0, base + boost)
            if "dataflow_source_nearby" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("dataflow_source_nearby")
            adjusted = True
            break

    if adjusted:
        return True

    # Check if finding is at a sink but no source detected in file
    for sink in taint_map.sinks:
        if abs(sink.line - finding_line) <= 3:
            if not taint_map.sources:
                # Sink exists but no untrusted source — likely safe
                base = finding.adjusted_confidence or finding.confidence
                penalty = abs(SINK_NO_SOURCE_PENALTY)
                finding.adjusted_confidence = max(5.0, base - penalty)
                if "dataflow_sink_no_source" not in finding.intelligence_modifiers:
                    finding.intelligence_modifiers.append("dataflow_sink_no_source")
                adjusted = True
                break

    return adjusted


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════


def apply_dataflow_analysis(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> List[EngineFinding]:
    """Apply lightweight dataflow analysis to all findings.

    Called from the main pipeline after logic detectors and before
    false positive control.  Mutates findings in-place.

    Args:
        findings: List of EngineFinding objects from prior pipeline stages.
        file_contents: Dict mapping file_name → full file content string.

    Returns:
        The same list with modified findings (for fluent chaining).
    """
    if not findings or not file_contents:
        return findings

    # Group findings by file
    findings_by_file: Dict[str, List[EngineFinding]] = defaultdict(list)
    for f in findings:
        findings_by_file[f.file_name].append(f)

    # Analyze each file that has findings
    total_chains = 0
    total_sources = 0
    total_sinks = 0
    adjusted_count = 0

    for fname, file_findings in findings_by_file.items():
        content = file_contents.get(fname, "")
        if not content:
            continue

        # Perform taint analysis for this file
        taint_map = analyze_file_taint(fname, content)

        total_chains += len(taint_map.chains)
        total_sources += len(taint_map.sources)
        total_sinks += len(taint_map.sinks)

        # Adjust confidence for each finding in this file
        for finding in file_findings:
            if _adjust_finding_confidence(finding, taint_map):
                adjusted_count += 1

    logger.info(
        "Dataflow analysis: %d files analyzed — "
        "%d sources, %d sinks, %d chains detected; "
        "%d findings adjusted.",
        len(findings_by_file),
        total_sources,
        total_sinks,
        total_chains,
        adjusted_count,
    )

    return findings


def get_dataflow_stats(
    file_contents: Dict[str, str],
) -> Dict[str, object]:
    """Return comprehensive dataflow analysis statistics.

    Useful for dashboard / reporting.
    """
    stats = {
        "files_analyzed": 0,
        "total_sources": 0,
        "total_sinks": 0,
        "total_chains": 0,
        "total_tainted_vars": 0,
        "chains_by_type": defaultdict(int),
        "sources_by_type": defaultdict(int),
        "sinks_by_type": defaultdict(int),
    }

    for fname, content in file_contents.items():
        if not content:
            continue

        taint_map = analyze_file_taint(fname, content)

        if taint_map.sources or taint_map.sinks:
            stats["files_analyzed"] += 1
            stats["total_sources"] += len(taint_map.sources)
            stats["total_sinks"] += len(taint_map.sinks)
            stats["total_chains"] += len(taint_map.chains)
            stats["total_tainted_vars"] += len(taint_map.tainted_vars)

            for src in taint_map.sources:
                stats["sources_by_type"][src.source_type] += 1
            for sink in taint_map.sinks:
                stats["sinks_by_type"][sink.sink_type] += 1
            for chain in taint_map.chains:
                chain_key = f"{chain.source.source_type}→{chain.sink.sink_type}"
                stats["chains_by_type"][chain_key] += 1

    # Convert defaultdicts to regular dicts for serialization
    stats["chains_by_type"] = dict(stats["chains_by_type"])
    stats["sources_by_type"] = dict(stats["sources_by_type"])
    stats["sinks_by_type"] = dict(stats["sinks_by_type"])

    return stats
