"""
Safe YAML scanning subsystem — isolated from the general code-rule engine.

Prevents freezes caused by running complex regex patterns on YAML content.
YAML files are scanned with a dedicated, smaller rule set using bounded
regex patterns and additional safety limits.

Parts addressed:
  1 — YAML file classification (via YAML_LANGUAGES)
  2 — Code-rule isolation (YAML never runs code rules)
  3 — YAML-specific rule set (only devops/yaml/k8s/helm/gha rules)
  4 — Size limit (MAX_YAML_SIZE = 200 KB)
  5 — Safe parsing with yaml.safe_load + recursion guard
  6 — Regex restrictions (bounded patterns, per-pattern timeout)
  7 — Dedicated [YAML_SCAN] logging
"""

import logging
import os
import re
import time
from typing import Dict, List, Optional

try:
    import regex as _regex_mod          # has .finditer(timeout=…)
    _HAS_REGEX = True
except ImportError:
    _HAS_REGEX = False

from engine.models import CompiledRule, EngineFinding, PatternMatch, MAX_SNIPPET_CHARS
from engine.streaming_scanner import (
    build_line_offset_table,
    offset_to_line,
    extract_code_snippet,
)
from engine.rule_profiler import get_profiler, SLOW_RULE_THRESHOLD_MS

logger = logging.getLogger("engine.yaml_scanner")

# ─── Constants ───────────────────────────────────────────────────────

MAX_YAML_SIZE = 204_800          # 200 KB — skip YAML files larger than this
YAML_PATTERN_TIMEOUT_MS = 100    # 100 ms per pattern (stricter than code scanner's 200 ms)
YAML_FILE_TIMEOUT_MS = 3_000     # 3 s hard limit per YAML file
MAX_YAML_FINDINGS = 50           # Cap findings per YAML file
MAX_YAML_RECURSION_DEPTH = 50    # yaml.safe_load recursion guard

# Languages that are YAML-based config files
YAML_LANGUAGES = frozenset({
    "yaml",
    "kubernetes",
    "helm",
    "github_actions",
    "gitlab_ci",
    "bitbucket_pipelines",
})


def is_yaml_language(language: str) -> bool:
    """Return True if the language is a YAML-based config language."""
    return language.lower() in YAML_LANGUAGES


# ─── Safe YAML Parse (Part 5) ───────────────────────────────────────

class _SafeLoaderWithAliasLimit(object):
    """Factory for a yaml.SafeLoader subclass that limits alias expansions.

    Prevents Billion Laughs / anchor-bomb attacks:
        a: &a ["lol","lol","lol"]
        b: &b [*a,*a,*a]
        c: &c [*b,*b,*b]
    """
    MAX_ALIASES = 100  # abort if more than 100 alias dereferences

    @classmethod
    def get_loader(cls):
        try:
            import yaml
        except ImportError:
            return None

        class SafeLoaderLimited(yaml.SafeLoader):
            _alias_count = 0
            _max_aliases = cls.MAX_ALIASES

            def compose_node(self, parent, index):
                if self.check_event(yaml.events.AliasEvent):
                    self._alias_count += 1
                    if self._alias_count > self._max_aliases:
                        raise yaml.constructor.ConstructorError(
                            None, None,
                            f"anchor bomb: too many aliases ({self._alias_count} > {self._max_aliases})",
                            self.peek_event().start_mark,
                        )
                return super().compose_node(parent, index)

        return SafeLoaderLimited


def validate_yaml_structure(content: str, file_name: str) -> bool:
    """Validate YAML is parseable and not maliciously nested.

    Uses yaml.safe_load with:
      - SafeLoader (no arbitrary Python objects)
      - max_aliases limit (Billion Laughs / anchor bomb protection)
      - Recursion depth guard

    Returns False (and logs) for dangerous files. Does NOT block
    regex scanning — just logs a warning.
    """
    try:
        import yaml
    except ImportError:
        return True  # If PyYAML not installed, skip validation

    if len(content) > MAX_YAML_SIZE:
        return False

    LoaderClass = _SafeLoaderWithAliasLimit.get_loader()
    if LoaderClass is None:
        return True

    import sys
    old_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(MAX_YAML_RECURSION_DEPTH + 100)
        yaml.load(content, Loader=LoaderClass)
        return True
    except RecursionError:
        logger.warning(
            "[YAML_SCAN] %s — SKIPPED: recursive anchors / excessive nesting",
            file_name,
        )
        return False
    except yaml.YAMLError as exc:
        exc_str = str(exc)
        if "anchor bomb" in exc_str or "too many aliases" in exc_str:
            logger.warning(
                "[YAML_SCAN] %s — SKIPPED: anchor bomb detected (%s)",
                file_name, exc_str,
            )
            return False
        # Unparseable YAML is fine — we still regex-scan it
        return True
    except Exception:
        return True
    finally:
        sys.setrecursionlimit(old_limit)


# ─── Safe Regex Execution (Part 6) ──────────────────────────────────

def _scan_yaml_patterns(
    content: str,
    patterns: List[re.Pattern],
    line_table: List[int],
    file_start: float,
    file_name: str,
) -> List[PatternMatch]:
    """Run patterns against YAML content with strict timeouts.

    Uses the ``regex`` module's built-in ``timeout`` parameter so that a
    single catastrophic-backtracking attempt is killed at the C level
    (not only checked between matches).  Falls back to ``re`` with
    between-match checks when ``regex`` is not installed.
    """
    matches: List[PatternMatch] = []
    timeout_sec = YAML_PATTERN_TIMEOUT_MS / 1000.0

    for pat_idx, pattern in enumerate(patterns):
        # Hard file timeout
        file_elapsed = (time.monotonic() - file_start) * 1000
        if file_elapsed > YAML_FILE_TIMEOUT_MS:
            logger.warning(
                "[YAML_SCAN] %s — file timeout %.0fms at pattern %d/%d; stopping",
                file_name, file_elapsed, pat_idx, len(patterns),
            )
            break

        pat_start = time.monotonic()
        try:
            if _HAS_REGEX:
                # regex module: recompile so we can pass timeout
                rpat = _regex_mod.compile(pattern.pattern, pattern.flags)
                iterator = rpat.finditer(content, timeout=timeout_sec)
            else:
                iterator = pattern.finditer(content)

            for m in iterator:
                # Fallback timeout for stdlib re (no C-level timeout)
                if not _HAS_REGEX:
                    pat_elapsed = (time.monotonic() - pat_start) * 1000
                    if pat_elapsed > YAML_PATTERN_TIMEOUT_MS:
                        logger.warning(
                            "[YAML_SCAN] %s — pattern %d timed out after %.0fms; skipping",
                            file_name, pat_idx, pat_elapsed,
                        )
                        break

                matched_text = m.group()[:200]
                line_num = offset_to_line(m.start(), line_table)
                matches.append(
                    PatternMatch(
                        pattern_index=pat_idx,
                        start_offset=m.start(),
                        end_offset=m.end(),
                        line_number=line_num,
                        matched_text=matched_text,
                    )
                )
        except TimeoutError:
            pat_elapsed = (time.monotonic() - pat_start) * 1000
            logger.warning(
                "[YAML_SCAN] %s — pattern %d KILLED by regex timeout after %.0fms",
                file_name, pat_idx, pat_elapsed,
            )
        except re.error as exc:
            logger.error(
                "[YAML_SCAN] %s — regex error pattern %d: %s",
                file_name, pat_idx, exc,
            )

    matches.sort(key=lambda m: (m.line_number, m.pattern_index))
    return matches


# ─── Anti-Pattern Check ─────────────────────────────────────────────

def _check_anti_patterns(content_lower: str, anti_patterns: tuple) -> bool:
    for ap in anti_patterns:
        if ap.lower() in content_lower:
            return True
    return False


# ─── Detection ID ───────────────────────────────────────────────────

def _detection_id(rule_id: str, file_name: str, line: int) -> str:
    import hashlib
    raw = f"{rule_id}|{file_name}|{line}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ─── Main Entry Point ───────────────────────────────────────────────

def scan_yaml_file(
    content: str,
    file_name: str,
    yaml_rules: List[CompiledRule],
    language: str,
) -> List[EngineFinding]:
    """Scan a YAML file using the dedicated YAML rule set.

    Parts 1-7 all enforced here:
    - Part 4: size limit (MAX_YAML_SIZE)
    - Part 5: safe parse validation
    - Part 6: bounded regex with strict timeouts
    - Part 7: [YAML_SCAN] logging throughout
    """
    pid = os.getpid()
    file_start = time.monotonic()

    # Part 4: Size limit
    if len(content) > MAX_YAML_SIZE:
        logger.info(
            "[YAML_SCAN] %s — SKIPPED: size %d > %d bytes (pid=%d)",
            file_name, len(content), MAX_YAML_SIZE, pid,
        )
        return []

    # Part 5: Safe parse validation — block anchor bombs
    if not validate_yaml_structure(content, file_name):
        logger.warning(
            "[YAML_SCAN] %s — BLOCKED by structure validation (pid=%d)",
            file_name, pid,
        )
        return []

    if not yaml_rules:
        logger.info(
            "[YAML_SCAN] %s — no applicable YAML rules (lang=%s, pid=%d)",
            file_name, language, pid,
        )
        return []

    # Part 7: Log start
    logger.info(
        "[YAML_SCAN] scanning %s (lang=%s, rules=%d, size=%d, pid=%d)",
        file_name, language, len(yaml_rules), len(content), pid,
    )

    content_lower = content.lower()
    line_table = build_line_offset_table(content)
    findings: List[EngineFinding] = []
    profiler = get_profiler()

    for compiled_rule in yaml_rules:
        rule = compiled_rule.rule

        # Per-rule timing
        rule_start = time.perf_counter()
        matches = _scan_yaml_patterns(
            content,
            compiled_rule.compiled_patterns,
            line_table,
            file_start,
            file_name,
        )
        rule_elapsed_ms = (time.perf_counter() - rule_start) * 1000

        # Record in profiler heatmap
        pattern_strs = (
            [p.pattern for p in compiled_rule.compiled_patterns]
            if rule_elapsed_ms > SLOW_RULE_THRESHOLD_MS
            else None
        )
        profiler.record_execution(
            rule_id=rule.rule_id,
            file_name=file_name,
            elapsed_ms=rule_elapsed_ms,
            match_count=len(matches),
            pattern_strs=pattern_strs,
        )

        if rule_elapsed_ms > SLOW_RULE_THRESHOLD_MS:
            logger.warning(
                "[YAML_SCAN] slow rule %s on %s: %.0fms (%d matches)",
                rule.rule_id, file_name, rule_elapsed_ms, len(matches),
            )

        if not matches:
            continue

        # Anti-pattern suppression
        if rule.anti_patterns and _check_anti_patterns(
            content_lower, rule.anti_patterns
        ):
            continue

        for match in matches:
            if len(findings) >= MAX_YAML_FINDINGS:
                logger.info(
                    "[YAML_SCAN] %s — hit MAX_YAML_FINDINGS (%d); stopping",
                    file_name, MAX_YAML_FINDINGS,
                )
                elapsed_ms = (time.monotonic() - file_start) * 1000
                logger.info(
                    "[YAML_SCAN] finished %s — %d findings in %.0fms (rules=%d, pid=%d)",
                    file_name, len(findings), elapsed_ms, len(yaml_rules), pid,
                )
                return findings

            snippet = extract_code_snippet(
                content, match.line_number,
                context_lines=3, max_chars=MAX_SNIPPET_CHARS,
            )
            detection_id = _detection_id(rule.rule_id, file_name, match.line_number)
            confidence_100 = round(rule.confidence * 100, 1)

            findings.append(EngineFinding(
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
            ))

        # Check file hard timeout after each rule
        if (time.monotonic() - file_start) * 1000 > YAML_FILE_TIMEOUT_MS:
            logger.warning(
                "[YAML_SCAN] %s — file timeout reached after %d rules; stopping",
                file_name, yaml_rules.index(compiled_rule) + 1,
            )
            break

    elapsed_ms = (time.monotonic() - file_start) * 1000
    logger.info(
        "[YAML_SCAN] finished %s — %d findings in %.0fms (rules=%d, pid=%d)",
        file_name, len(findings), elapsed_ms, len(yaml_rules), pid,
    )

    return findings
