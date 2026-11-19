"""
Detection engine — core matching logic.

Takes file content + compiled rules, runs streaming scanner, applies
anti-pattern suppression, context-aware signal validation, extracts
code snippets, computes detection IDs.
"""

import hashlib
import logging
import time
from typing import List, Optional, Set, Tuple

from engine.models import (
    CompiledRule,
    EngineFinding,
    PatternMatch,
    MAX_FINDINGS_PER_FILE,
    MAX_SNIPPET_CHARS,
)
from engine.streaming_scanner import scan_file_content, extract_code_snippet
from engine.rule_profiler import get_profiler, SLOW_RULE_THRESHOLD_MS
from engine.context_detection import (
    detect_route_decorators,
    detect_database_queries,
    evaluate_context_signals,
    adjust_confidence_by_signals,
    get_rule_context_requirements,
    should_suppress_finding,
)

logger = logging.getLogger("engine.detection_engine")


def generate_detection_id(
    rule_id: str,
    file_name: str,
    line: int,
    matched_pattern: str,
) -> str:
    """Deterministic hash for idempotent re-scans.

    sha256(rule_id|file_name|line|pattern) truncated to 16 hex chars.
    """
    raw = f"{rule_id}|{file_name}|{line}|{matched_pattern}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def check_anti_patterns(content_lower: str, anti_patterns: tuple) -> bool:
    """Return True if ANY anti-pattern literal is found in content.

    Anti-patterns suppress all matches for the rule in this file.
    Uses case-insensitive literal substring search — same behavior as
    rule-tests/runner/engine.py line 170.
    """
    for ap in anti_patterns:
        if ap.lower() in content_lower:
            return True
    return False


def check_anti_patterns_scoped(
    content: str,
    match_line: int,
    anti_patterns: tuple,
    scope_lines: int = 30,
) -> bool:
    """Scoped anti-pattern check — only looks within ±scope_lines of the match.

    More precise than whole-file check: prevents an anti-pattern in a
    distant function from suppressing a valid finding.
    """
    lines = content.split("\n")
    start = max(0, match_line - 1 - scope_lines)
    end = min(len(lines), match_line + scope_lines)
    region = "\n".join(lines[start:end]).lower()

    for ap in anti_patterns:
        if ap.lower() in region:
            return True
    return False


def _is_string_literal_line(lines: List[str], line_idx: int) -> bool:
    """Check if a line is primarily a string literal (high FP risk).

    Catches the #1 root cause of false positives: patterns matching
    inside documentation strings, code examples in docstrings, error
    messages, and remediation text.

    Heuristics:
    1. Line content is a string continuation (starts/ends with quotes)
    2. Line is inside a triple-quoted block (docstring/multiline string)
    3. Line is a dict/variable assignment to a string value
    """
    if line_idx < 0 or line_idx >= len(lines):
        return False

    line = lines[line_idx]
    stripped = line.strip()

    if not stripped:
        return False

    # Direct string line: starts with a quote (pure string literal)
    if stripped.startswith(('"""', "'''", '"', "'")):
        # But not a single-char string used as argument
        # Allow: f-string with actual code like f"SELECT {x}"
        if stripped.startswith(('f"', "f'", 'f"""', "f'''")):
            return False
        # Allow: short strings that are likely function args
        if len(stripped) < 15:
            return False
        return True

    # String continuation line (inside multiline string)
    # Check if we're between triple-quotes
    in_triple = False
    for i in range(line_idx):
        l = lines[i]
        # Count non-escaped triple quotes
        in_triple_dbl = l.count('"""')
        in_triple_sgl = l.count("'''")
        for _ in range(in_triple_dbl + in_triple_sgl):
            in_triple = not in_triple

    if in_triple:
        return True

    # Assignment to string: varname = "..." or key: "..."
    # This catches dict values containing code examples
    for sep in ('= "', "= '", ': "', ": '", '="', "='"):
        if sep in stripped:
            # Check if the string part takes up most of the line
            idx = stripped.index(sep)
            string_part = stripped[idx + len(sep):]
            if len(string_part) > 30:
                return True

    return False


def _build_string_line_map(lines: List[str]) -> set:
    """Pre-compute set of line indices that are inside string literals.

    Builds a set of 0-based line indices for O(1) lookup per match.
    """
    string_lines = set()

    # Track triple-quote blocks
    in_triple = False
    triple_start = -1

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Count triple-quote transitions
        dbl_count = stripped.count('"""')
        sgl_count = stripped.count("'''")
        total_toggles = dbl_count + sgl_count

        if in_triple:
            string_lines.add(i)
            if total_toggles % 2 == 1:  # Closing triple quote
                in_triple = False
        else:
            if total_toggles % 2 == 1:  # Opening triple quote
                in_triple = True
                string_lines.add(i)
            elif total_toggles >= 2:  # Same-line open+close
                string_lines.add(i)

        # Also check for single-line string assignments
        if not in_triple and i not in string_lines:
            if _is_string_literal_line(lines, i):
                string_lines.add(i)

    return string_lines


def detect_in_file(
    content: str,
    file_name: str,
    rules: List[CompiledRule],
) -> List[EngineFinding]:
    """Run all provided rules against a single file's content.

    For each rule:
    1. Run scan_file_content with the rule's compiled patterns
    2. If matches found, check anti-patterns on full content
       - If anti-pattern found: suppress all matches, continue
    3. For each match: extract snippet, generate detection_id, create finding
    4. Respect MAX_FINDINGS_PER_FILE noise threshold

    Returns list of EngineFinding objects.
    """
    if not content or not rules:
        return []

    findings: List[EngineFinding] = []
    seen_keys: Set[Tuple[str, str, int]] = set()
    content_lower = content.lower()
    slow_rules = []
    content_size = len(content)
    profiler = get_profiler()

    # Pre-compute string-literal line map for FP suppression
    # Lines inside docstrings/multiline strings are high FP risk
    _lines = content.split("\n")
    _string_lines = _build_string_line_map(_lines)

    # Pre-compute context signals once per file (shared across all rules)
    # This is lightweight: just line-by-line regex matching
    _route_lines: Optional[List[int]] = None
    _query_lines: Optional[List[int]] = None

    def _get_route_lines() -> List[int]:
        nonlocal _route_lines
        if _route_lines is None:
            _route_lines = detect_route_decorators(content)
        return _route_lines

    def _get_query_lines() -> List[int]:
        nonlocal _query_lines
        if _query_lines is None:
            _query_lines = detect_database_queries(content)
        return _query_lines

    for rule_idx, compiled_rule in enumerate(rules):
        rule = compiled_rule.rule

        # Part 1: Precise rule execution timing
        rule_start = time.perf_counter()
        matches: List[PatternMatch] = scan_file_content(
            content, compiled_rule.compiled_patterns
        )
        rule_elapsed_ms = (time.perf_counter() - rule_start) * 1000

        # Part 1/3: record every execution in heatmap
        pattern_strs = [
            p.pattern for p in compiled_rule.compiled_patterns
        ] if rule_elapsed_ms > SLOW_RULE_THRESHOLD_MS else None
        profiler.record_execution(
            rule_id=rule.rule_id,
            file_name=file_name,
            elapsed_ms=rule_elapsed_ms,
            match_count=len(matches),
            pattern_strs=pattern_strs,
        )

        # Phase 5 / Part 2: Log patterns exceeding threshold
        if rule_elapsed_ms > SLOW_RULE_THRESHOLD_MS:
            slow_rules.append((rule.rule_id, rule_elapsed_ms, len(matches)))
            logger.warning(
                "[diag] pattern execution >%.0fms: rule_id=%s file=%s "
                "elapsed=%.0fms matches=%d patterns=%d file_size=%d rule_idx=%d/%d",
                SLOW_RULE_THRESHOLD_MS,
                rule.rule_id, file_name, rule_elapsed_ms,
                len(matches), len(compiled_rule.compiled_patterns),
                content_size, rule_idx + 1, len(rules),
            )

        if not matches:
            continue

        # Anti-pattern suppression: if any anti-pattern literal is found
        # in the file, suppress ALL matches for this rule
        if rule.anti_patterns and check_anti_patterns(
            content_lower, rule.anti_patterns
        ):
            logger.debug(
                "Anti-pattern suppressed rule %s in %s (%d matches suppressed)",
                rule.rule_id,
                file_name,
                len(matches),
            )
            continue

        # Convert matches to findings
        for match in matches:
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                logger.info(
                    "Hit MAX_FINDINGS_PER_FILE (%d) for %s; stopping.",
                    MAX_FINDINGS_PER_FILE,
                    file_name,
                )
                return findings

            # Per-match scoped anti-pattern check (±30 lines around match)
            # Catches localized sanitizers that file-level check missed
            if rule.anti_patterns and check_anti_patterns_scoped(
                content, match.line_number, rule.anti_patterns, scope_lines=30,
            ):
                continue

            # String-literal suppression (ROOT CAUSE FIX #1)
            # Skip matches on lines that are inside string literals,
            # docstrings, or string assignments. This is the single
            # biggest accuracy improvement — eliminates ~48% of FPs.
            match_line_idx = match.line_number - 1  # 0-based
            if match_line_idx in _string_lines:
                continue

            snippet = extract_code_snippet(
                content,
                match.line_number,
                context_lines=3,
                max_chars=MAX_SNIPPET_CHARS,
            )

            # Dedup: only one finding per (rule, file, line) — prevents
            # multiple patterns from the same rule creating duplicates
            # on the same line (ROOT CAUSE FIX #2)
            dedup_key = (
                rule.rule_id,
                file_name,
                match.line_number,
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            detection_id = generate_detection_id(
                rule.rule_id,
                file_name,
                match.line_number,
                match.matched_text,
            )

            # Confidence: convert from 0.0-1.0 to 0-100 scale
            confidence_100 = round(rule.confidence * 100, 1)

            # Context-aware signal validation (multi-signal detection)
            # For rules with context requirements, evaluate signals at the
            # match location and adjust confidence / suppress if needed.
            ctx_requirements = get_rule_context_requirements(rule.rule_id)
            if ctx_requirements:
                signals = evaluate_context_signals(
                    content,
                    match.line_number,
                    _get_route_lines(),
                    _get_query_lines(),
                )

                # Suppress findings that lack required context
                if should_suppress_finding(rule.rule_id, signals):
                    logger.debug(
                        "Context suppressed %s in %s line %d: "
                        "route=%s query=%s",
                        rule.rule_id, file_name, match.line_number,
                        signals.has_route_decorator,
                        signals.has_database_query,
                    )
                    continue

                # Adjust confidence based on signal quality
                confidence_100 = adjust_confidence_by_signals(
                    confidence_100,
                    signals,
                    requires_route=ctx_requirements.get("requires_route", False),
                    requires_query=ctx_requirements.get("requires_query", False),
                )

            finding = EngineFinding(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                vulnerability_type=rule.title,
                severity=rule.severity,
                confidence=confidence_100,
                file_name=file_name,
                line=match.line_number,
                description=rule.description,
                category=rule.db_category,
                owasp=rule.owasp,
                cwe=rule.cwe,
                matched_pattern=match.matched_text,
                code_snippet=snippet,
                impact=rule.impact,
                remediation=rule.remediation,
                requires_ai_validation=rule.requires_ai_validation,
                severity_weight=rule.severity_weight,
                exploitability_score=rule.exploitability_score,
                detection_id=detection_id,
            )
            findings.append(finding)

    # Log slow rules for debugging backtracking / performance issues
    if slow_rules:
        for rule_id, elapsed, match_count in slow_rules:
            logger.warning(
                "Slow rule in %s: %s took %.0f ms (%d matches)",
                file_name, rule_id, elapsed, match_count,
            )

    return findings
