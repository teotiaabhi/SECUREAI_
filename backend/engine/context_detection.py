"""
Context-aware detection engine — route, query, and multi-signal analysis.

This module transforms SecureAI from keyword-based scanning to context-aware
vulnerability detection. Rules can declare required signals (route decorator,
database query, missing tenant filter) and the engine validates them BEFORE
reporting a finding.

Pipeline position: AFTER pattern match, BEFORE finding creation

Supported signals:
    - route_decorator: Flask/FastAPI/Django/Express/Next.js route decorators
    - database_query:  ORM queries, raw SQL, session.query, db.execute
    - missing_tenant_filter: absence of tenant_id/account_id/organization_id
    - bulk_data_return: CSV/Excel/streaming response patterns

Confidence adjustment:
    - keyword match only       → LOW  (capped at 30)
    - keyword + route          → MEDIUM (capped at 55)
    - route + query + no tenant → HIGH (original confidence preserved)
"""

import logging
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("engine.context_detection")


# ─── Route Decorator Patterns ────────────────────────────────────────
# Detects web framework route decorators across Flask, FastAPI, Django,
# Express, Next.js, Spring, Gin, Laravel, etc.

ROUTE_DECORATOR_PATTERNS: Tuple[re.Pattern, ...] = (
    # Python: Flask / FastAPI / Blueprint
    re.compile(
        r"@(?:app|blueprint|bp|router|api)\."
        r"(?:route|get|post|put|patch|delete|head|options)\s*\(",
        re.IGNORECASE,
    ),
    # Python: Django URL patterns (in views referenced by urls.py)
    re.compile(
        r"@(?:api_view|action|require_(?:GET|POST|http_methods))\s*\(",
        re.IGNORECASE,
    ),
    # JavaScript/TypeScript: Express
    re.compile(
        r"(?:app|router)\."
        r"(?:get|post|put|patch|delete|all|use)\s*\(\s*['\"/]",
        re.IGNORECASE,
    ),
    # Next.js API routes (export default / export async function)
    re.compile(
        r"export\s+(?:default\s+)?(?:async\s+)?function\s+"
        r"(?:GET|POST|PUT|PATCH|DELETE|handler)\b",
        re.IGNORECASE,
    ),
    # Java: Spring @RequestMapping / @GetMapping / @PostMapping
    re.compile(
        r"@(?:Request|Get|Post|Put|Patch|Delete)Mapping\s*\(",
        re.IGNORECASE,
    ),
    # Go: Gin / Echo
    re.compile(
        r"(?:router|r|e|g)\."
        r"(?:GET|POST|PUT|PATCH|DELETE|Handle|Any)\s*\(",
        re.IGNORECASE,
    ),
    # PHP: Laravel Route
    re.compile(
        r"Route::(?:get|post|put|patch|delete|any|match)\s*\(",
        re.IGNORECASE,
    ),
    # Ruby: Rails
    re.compile(
        r"(?:get|post|put|patch|delete|match)\s+['\"/]",
        re.IGNORECASE,
    ),
)


# ─── Database Query Patterns ─────────────────────────────────────────
# Detects ORM queries, raw SQL execution, and data retrieval patterns.

DATABASE_QUERY_PATTERNS: Tuple[re.Pattern, ...] = (
    # SQLAlchemy ORM: Model.query.all(), Model.query.filter()
    re.compile(r"\w+\.query\.(?:all|filter|filter_by|get|first|one|count)\s*\(", re.IGNORECASE),
    # SQLAlchemy session: session.query(), session.execute()
    re.compile(r"(?:session|db\.session|db)\.(?:query|execute|scalar|scalars)\s*\(", re.IGNORECASE),
    # Raw SQL keywords in execute calls
    re.compile(r"\.execute\s*\(\s*(?:text\s*\(\s*)?['\"]?\s*(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE),
    # Django ORM: Model.objects.all(), Model.objects.filter()
    re.compile(r"\w+\.objects\.(?:all|filter|exclude|get|values|values_list|annotate|aggregate)\s*\(", re.IGNORECASE),
    # Cursor-based queries
    re.compile(r"cursor\.(?:execute|fetchall|fetchone|fetchmany)\s*\(", re.IGNORECASE),
    # Pandas SQL queries
    re.compile(r"pd\.read_sql(?:_query|_table)?\s*\(", re.IGNORECASE),
    # Async SQLAlchemy
    re.compile(r"await\s+(?:db|session)\.(?:execute|scalar|scalars)\s*\(", re.IGNORECASE),
    # Raw SQL string patterns (SELECT ... FROM)
    re.compile(r"['\"]SELECT\s+.+?\s+FROM\s+", re.IGNORECASE),
)


# ─── Tenant Filter Patterns ──────────────────────────────────────────
# Patterns indicating proper tenant scoping is present.

TENANT_FILTER_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"tenant_id\s*[=!]", re.IGNORECASE),
    re.compile(r"account_id\s*[=!]", re.IGNORECASE),
    re.compile(r"organization_id\s*[=!]", re.IGNORECASE),
    re.compile(r"org_id\s*[=!]", re.IGNORECASE),
    re.compile(r"workspace_id\s*[=!]", re.IGNORECASE),
    re.compile(r"\.filter(?:_by)?\s*\(\s*(?:.*\s)?tenant_id", re.IGNORECASE),
    re.compile(r"\.filter(?:_by)?\s*\(\s*(?:.*\s)?account_id", re.IGNORECASE),
    re.compile(r"\.filter(?:_by)?\s*\(\s*(?:.*\s)?organization_id", re.IGNORECASE),
    re.compile(r"WHERE\s+.*?tenant_id", re.IGNORECASE),
    re.compile(r"WHERE\s+.*?account_id", re.IGNORECASE),
    re.compile(r"\.tenant_scoped\s*\(", re.IGNORECASE),
    re.compile(r"current_tenant", re.IGNORECASE),
    re.compile(r"g\.tenant_id", re.IGNORECASE),
)


# ─── Bulk Data Return Patterns ───────────────────────────────────────
# CSV/Excel/streaming response patterns that indicate bulk export.

BULK_DATA_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"csv\.(?:writer|DictWriter)\s*\(", re.IGNORECASE),
    re.compile(r"(?:openpyxl|xlsxwriter|xlwt)\b", re.IGNORECASE),
    re.compile(r"pandas\.DataFrame|pd\.DataFrame", re.IGNORECASE),
    re.compile(r"(?:StringIO|BytesIO)\s*\(", re.IGNORECASE),
    re.compile(r"(?:send_file|send_from_directory|StreamingResponse|FileResponse)\s*\(", re.IGNORECASE),
    re.compile(r"\.(?:to_csv|to_excel|to_json)\s*\(", re.IGNORECASE),
    re.compile(r"Content-Disposition.*attachment", re.IGNORECASE),
)


# ─── Signal Detection Functions ──────────────────────────────────────

def detect_route_decorators(content: str) -> List[int]:
    """Find all lines with route decorators in the file content.

    Returns list of 1-based line numbers where routes are detected.
    """
    route_lines: List[int] = []
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        for pattern in ROUTE_DECORATOR_PATTERNS:
            if pattern.search(line):
                route_lines.append(i)
                break
    return route_lines


def detect_database_queries(content: str) -> List[int]:
    """Find all lines with database query patterns.

    Returns list of 1-based line numbers where queries are detected.
    """
    query_lines: List[int] = []
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        for pattern in DATABASE_QUERY_PATTERNS:
            if pattern.search(line):
                query_lines.append(i)
                break
    return query_lines


def has_tenant_filter(content: str, start_line: int, end_line: int) -> bool:
    """Check if tenant filtering exists within a line range.

    Scans the given line range in the content for tenant/account/org ID
    filter patterns. Used to check if a function body has tenant scoping.

    Args:
        content: Full file content.
        start_line: Start of range (1-based, inclusive).
        end_line: End of range (1-based, inclusive).

    Returns:
        True if any tenant filter pattern is found in the range.
    """
    lines = content.split("\n")
    # Clamp to valid range
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    region = "\n".join(lines[start_idx:end_idx])

    for pattern in TENANT_FILTER_PATTERNS:
        if pattern.search(region):
            return True
    return False


def has_bulk_data_return(content: str, start_line: int, end_line: int) -> bool:
    """Check if bulk data export patterns exist within a line range."""
    lines = content.split("\n")
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    region = "\n".join(lines[start_idx:end_idx])

    for pattern in BULK_DATA_PATTERNS:
        if pattern.search(region):
            return True
    return False


def _find_function_end(lines: List[str], func_start_line: int) -> int:
    """Find the approximate end line of a Python function.

    Uses indentation heuristics: the function body has greater indentation
    than the def/decorator line. Returns 1-based line number.
    """
    if func_start_line < 1 or func_start_line > len(lines):
        return min(func_start_line + 50, len(lines))

    # Find the def line (may be after decorator)
    def_line_idx = func_start_line - 1
    for i in range(func_start_line - 1, min(func_start_line + 5, len(lines))):
        stripped = lines[i].lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            def_line_idx = i
            break

    # Get the indentation level of the def line
    def_line = lines[def_line_idx]
    def_indent = len(def_line) - len(def_line.lstrip())

    # Walk forward to find where indentation returns to def level or less
    for i in range(def_line_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if not stripped:  # skip blank lines
            continue
        line_indent = len(line) - len(line.lstrip())
        if line_indent <= def_indent:
            return i  # 0-based, so this is the first line OUTSIDE the function
    return len(lines)


def _find_nearest_route(route_lines: List[int], match_line: int) -> Optional[int]:
    """Find the nearest route decorator line BEFORE a given match line.

    Returns the route line number or None if no route precedes the match.
    A route decorator must be within 5 lines before the function def.
    """
    nearest = None
    for rl in route_lines:
        if rl <= match_line:
            nearest = rl
        else:
            break
    # Route decorator should be within reasonable distance
    if nearest and (match_line - nearest) <= 10:
        return nearest
    return None


# ─── Multi-Signal Evaluation ─────────────────────────────────────────

class ContextSignals:
    """Collected context signals for a finding within a file."""

    __slots__ = (
        "has_route_decorator",
        "has_database_query",
        "has_tenant_filter",
        "has_bulk_data",
        "route_line",
        "nearest_query_line",
        "signal_count",
    )

    def __init__(self):
        self.has_route_decorator: bool = False
        self.has_database_query: bool = False
        self.has_tenant_filter: bool = False
        self.has_bulk_data: bool = False
        self.route_line: Optional[int] = None
        self.nearest_query_line: Optional[int] = None
        self.signal_count: int = 0

    def compute_signal_count(self) -> int:
        """Count how many positive signals are active."""
        count = 0
        if self.has_route_decorator:
            count += 1
        if self.has_database_query:
            count += 1
        if not self.has_tenant_filter:  # MISSING tenant = a signal
            count += 1
        if self.has_bulk_data:
            count += 1
        self.signal_count = count
        return count


def evaluate_context_signals(
    content: str,
    match_line: int,
    route_lines: List[int],
    query_lines: List[int],
) -> ContextSignals:
    """Evaluate all context signals for a specific finding location.

    Analyzes the function containing the match to determine:
    - Whether it's a web route handler
    - Whether it performs database queries
    - Whether tenant filtering exists
    - Whether it returns bulk data

    Args:
        content: Full file content.
        match_line: 1-based line number of the pattern match.
        route_lines: Pre-computed route decorator line numbers.
        query_lines: Pre-computed database query line numbers.

    Returns:
        ContextSignals with all fields populated.
    """
    signals = ContextSignals()
    lines = content.split("\n")

    # Check route decorator
    nearest_route = _find_nearest_route(route_lines, match_line)
    if nearest_route is not None:
        signals.has_route_decorator = True
        signals.route_line = nearest_route

    # Determine function boundaries for deeper analysis
    func_start = nearest_route or match_line
    func_end = _find_function_end(lines, func_start)

    # Check database queries within the function
    for ql in query_lines:
        if func_start <= ql <= func_end:
            signals.has_database_query = True
            signals.nearest_query_line = ql
            break

    # Check tenant filtering within the function
    signals.has_tenant_filter = has_tenant_filter(content, func_start, func_end)

    # Check bulk data patterns within the function
    signals.has_bulk_data = has_bulk_data_return(content, func_start, func_end)

    signals.compute_signal_count()
    return signals


# ─── Confidence Adjustment ───────────────────────────────────────────

# Signal-based confidence caps
CONFIDENCE_CAP_KEYWORD_ONLY = 30.0      # keyword match only → LOW
CONFIDENCE_CAP_KEYWORD_ROUTE = 55.0     # keyword + route → MEDIUM
CONFIDENCE_CAP_ROUTE_QUERY = 70.0       # route + query (but tenant present) → MEDIUM-HIGH
# route + query + missing tenant → HIGH (no cap, use original confidence)


def adjust_confidence_by_signals(
    original_confidence: float,
    signals: ContextSignals,
    requires_route: bool = False,
    requires_query: bool = False,
) -> float:
    """Adjust finding confidence based on context signals.

    Applies confidence caps based on which signals are present:
    - keyword match only                    → capped at 30 (LOW)
    - keyword + route detection             → capped at 55 (MEDIUM)
    - route + database query + tenant filter → capped at 70 (filtered = less severe)
    - route + database query + NO tenant    → original confidence (HIGH)

    Args:
        original_confidence: The rule's base confidence (0-100 scale).
        signals: Evaluated context signals.
        requires_route: Whether this rule requires a route decorator.
        requires_query: Whether this rule requires a database query.

    Returns:
        Adjusted confidence score.
    """
    if requires_route and not signals.has_route_decorator:
        # Rule requires a route but none found → suppress heavily
        return min(original_confidence, CONFIDENCE_CAP_KEYWORD_ONLY)

    if requires_query and not signals.has_database_query:
        # Rule requires a query but none found → still keyword-only
        if signals.has_route_decorator:
            return min(original_confidence, CONFIDENCE_CAP_KEYWORD_ROUTE)
        return min(original_confidence, CONFIDENCE_CAP_KEYWORD_ONLY)

    # Both route and query present
    if signals.has_route_decorator and signals.has_database_query:
        if signals.has_tenant_filter:
            # Tenant filter present → lower confidence (not unscoped)
            return min(original_confidence, CONFIDENCE_CAP_ROUTE_QUERY)
        else:
            # Route + query + NO tenant filter → full confidence (real bug)
            return original_confidence

    # Route present but no query requirement
    if signals.has_route_decorator:
        return min(original_confidence, CONFIDENCE_CAP_KEYWORD_ROUTE)

    # Pure keyword match
    return min(original_confidence, CONFIDENCE_CAP_KEYWORD_ONLY)


# ─── Rule Context Requirements ───────────────────────────────────────
# Maps rule_id prefixes to their required signals. Rules listed here
# will have context-aware validation applied.

CONTEXT_AWARE_RULES: Dict[str, Dict[str, bool]] = {
    # Multi-tenant isolation rules require route + query context
    "LOGIC-MT-": {
        "requires_route": True,
        "requires_query": True,
    },
    # IDOR rules require route context
    "LOGIC-IDOR-": {
        "requires_route": True,
        "requires_query": True,
    },
    # Privilege escalation rules require route context
    "LOGIC-PRIV-": {
        "requires_route": True,
        "requires_query": False,
    },
}


def get_rule_context_requirements(rule_id: str) -> Optional[Dict[str, bool]]:
    """Get context requirements for a rule based on its ID prefix.

    Returns None if the rule has no context requirements (standard matching).
    """
    for prefix, requirements in CONTEXT_AWARE_RULES.items():
        if rule_id.startswith(prefix):
            return requirements
    return None


def should_suppress_finding(
    rule_id: str,
    signals: ContextSignals,
) -> bool:
    """Determine if a finding should be completely suppressed.

    A finding is suppressed when:
    - Rule requires route decorator AND no route is found
    - This prevents internal utility functions from triggering endpoint rules

    Returns True if the finding should be suppressed (not reported).
    """
    requirements = get_rule_context_requirements(rule_id)
    if requirements is None:
        return False

    # If rule requires route decorator and none found → suppress
    if requirements.get("requires_route") and not signals.has_route_decorator:
        return True

    return False
