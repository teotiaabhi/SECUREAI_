"""
Multiprocess worker — compiled regex cache lives in each worker process.

Workers load rules directly from disk during process startup via
worker_init().  NO rule data is passed through initargs or submit(),
avoiding heavy pickling that deadlocks multiprocessing on Windows.

Each worker compiles regex patterns once at startup, then processes
files via worker_scan_file().
"""

import logging
import os
import re
import time
import traceback
from typing import Dict, List, Optional

from engine.models import EngineRule, CompiledRule, EngineFinding
from engine.detection_engine import detect_in_file
from engine.rule_profiler import get_profiler_snapshot
from engine.yaml_scanner import is_yaml_language, YAML_LANGUAGES, scan_yaml_file
from engine.rule_preconditions import RulePreconditions, evaluate_preconditions
from engine.context_gating import should_rule_execute, is_valid_file_for_language

logger = logging.getLogger("engine.worker")

# ─── Per-process file counter (for "Scanning file X of N" logs) ──────
_files_scanned_count: int = 0
_files_total_hint: int = 0  # Set by caller via worker_set_total()


def _get_memory_mb() -> float:
    """Get current process RSS in MB.  Returns 0 if psutil unavailable."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def worker_set_total(total: int) -> None:
    """Set total file count hint for progress logging."""
    global _files_total_hint, _files_scanned_count
    _files_total_hint = total
    _files_scanned_count = 0


def worker_set_project_context(ctx_dict: Optional[dict]) -> None:
    """Set project context from the main process (deserialized from dict)."""
    global _project_context
    if ctx_dict:
        from engine.framework_detector import ProjectContext
        _project_context = ProjectContext.from_dict(ctx_dict)
    else:
        _project_context = None

# ─── Module-Level Worker State (per-process) ─────────────────────────

_compiled_by_language: Dict[str, List[CompiledRule]] = {}
_universal_rules: List[CompiledRule] = []  # "all"/"universal" only — NOT yaml
_yaml_rules: List[CompiledRule] = []          # yaml-language rules (applied to all YAML files)
_yaml_by_language: Dict[str, List[CompiledRule]] = {}  # kubernetes, helm, gha, etc.
_initialized: bool = False
_project_context = None  # engine.framework_detector.ProjectContext


def _compile_rule(rule: EngineRule) -> Optional[CompiledRule]:
    """Compile an EngineRule's pattern strings into re.Pattern objects.

    Returns CompiledRule or None if all patterns fail.
    """
    compiled_patterns: List[re.Pattern] = []
    for pattern_str, flags in rule.pattern_strings:
        try:
            compiled_patterns.append(re.compile(pattern_str, flags))
        except re.error as exc:
            logger.error(
                "Worker: failed to compile pattern for %s: %s",
                rule.rule_id,
                exc,
            )

    if not compiled_patterns:
        return None

    return CompiledRule(rule=rule, compiled_patterns=compiled_patterns)


def worker_init() -> None:
    """ProcessPoolExecutor initializer — called once per worker process.

    Loads ALL rules from disk via get_rule_index() (no pickling),
    compiles regex patterns, and groups into per-language and universal
    dictionaries.  This eliminates heavy serialization through initargs
    that can deadlock multiprocessing on Windows.
    """
    global _compiled_by_language, _universal_rules, _yaml_rules, _yaml_by_language, _initialized

    if _initialized:
        return

    pid = os.getpid()
    init_start = time.monotonic()
    logger.info("[pid %d] Worker starting — loading rules from disk", pid)

    from engine.rule_loader import get_rule_index

    _compiled_by_language = {}
    _universal_rules = []
    _yaml_rules = []
    _yaml_by_language = {}

    rule_index = get_rule_index()
    compile_errors = 0

    for rule in rule_index.all_rules:
        compiled = _compile_rule(rule)
        if compiled is None:
            compile_errors += 1
            continue

        lang = rule.language.lower()
        if lang in ("all", "universal"):
            _universal_rules.append(compiled)
        elif lang == "yaml":
            # Part 2/3: YAML rules are NOT universal — only applied to YAML files
            _yaml_rules.append(compiled)
        elif lang in YAML_LANGUAGES:
            # Specialised YAML sub-languages (kubernetes, helm, github_actions, etc.)
            _yaml_by_language.setdefault(lang, []).append(compiled)
        else:
            _compiled_by_language.setdefault(lang, []).append(compiled)

    yaml_total = len(_yaml_rules) + sum(len(v) for v in _yaml_by_language.values())
    total = sum(len(v) for v in _compiled_by_language.values()) + len(
        _universal_rules
    ) + yaml_total
    logger.info(
        "[pid %d] YAML subsystem: %d generic yaml rules, %d specialised (%s)",
        pid, len(_yaml_rules), yaml_total - len(_yaml_rules),
        ", ".join(f"{k}:{len(v)}" for k, v in _yaml_by_language.items()),
    )
    _initialized = True

    elapsed_ms = (time.monotonic() - init_start) * 1000
    logger.info(
        "[pid %d] Worker ready: %d compiled rules across %d languages "
        "(%d universal, %d errors) in %.0fms",
        pid, total, len(_compiled_by_language),
        len(_universal_rules), compile_errors, elapsed_ms,
    )

    # Phase 7: Start heartbeat daemon thread
    try:
        from app.orchestration.scan_diagnostics import start_worker_heartbeat
        start_worker_heartbeat(interval=5.0)
        logger.info("[pid %d] Heartbeat thread started", pid)
    except Exception as hb_exc:
        logger.warning("[pid %d] Failed to start heartbeat: %s", pid, hb_exc)


def worker_scan_file(
    file_content: str,
    file_name: str,
    language: str,
) -> List[dict]:
    """Scan a single file using pre-compiled rules.

    Called via ProcessPoolExecutor.submit(). Returns list of
    EngineFinding dicts (picklable for cross-process transfer).

    Args:
        file_content: Full file content string
        file_name: Relative file path
        language: Classified language string (e.g. "python", "javascript")

    Returns:
        List of EngineFinding.__dict__ (dicts, not objects)
    """
    global _files_scanned_count

    if not _initialized:
        logger.error("Worker not initialized; call worker_init first.")
        return []

    _files_scanned_count += 1
    file_num = _files_scanned_count
    total_hint = _files_total_hint or "?"
    mem_mb = _get_memory_mb()
    pid = os.getpid()

    # Phase 7: skip oversized content (safety net)
    if len(file_content) > 2_097_152:  # 2 MB hard limit
        logger.warning(
            "[pid %d] File %s of %s: %s — SKIPPED (size %d > 2MB)",
            pid, file_num, total_hint, file_name, len(file_content),
        )
        return []

    # Phase 12: skip binary content
    if '\x00' in file_content[:8192]:
        logger.info(
            "[pid %d] File %s of %s: %s — SKIPPED (binary)",
            pid, file_num, total_hint, file_name,
        )
        return []

    lang_lower = language.lower()

    # Part 1/2: YAML files go through the dedicated safe YAML scanner
    if is_yaml_language(lang_lower):
        yaml_applicable = list(_yaml_rules)  # generic YAML rules
        yaml_applicable.extend(_yaml_by_language.get(lang_lower, []))  # sub-lang rules
        rules_count = len(yaml_applicable)
        logger.info(
            "[pid %d] [YAML_SCAN] File %s of %s: %s (lang=%s, yaml_rules=%d, size=%d, mem=%.1fMB)",
            pid, file_num, total_hint, file_name, language, rules_count,
            len(file_content), mem_mb,
        )
        start_time = time.monotonic()
        try:
            findings = scan_yaml_file(file_content, file_name, yaml_applicable, language)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.info(
                "[pid %d] [YAML_SCAN] File %s of %s: %s — %d findings in %.0fms (rules=%d, mem=%.1fMB)",
                pid, file_num, total_hint, file_name, len(findings),
                elapsed_ms, rules_count, _get_memory_mb(),
            )
            return [f.to_dict() for f in findings]
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.error(
                "[pid %d] [YAML_SCAN] File %s of %s: %s — FAILED after %.0fms: %s",
                pid, file_num, total_hint, file_name, elapsed_ms, exc,
                exc_info=True,
            )
            return []

    # Non-YAML: language-specific + universal (but NOT yaml rules)
    is_json_file = file_name.replace("\\", "/").lower().endswith(".json")
    if lang_lower == "json":
        applicable = list(_universal_rules)
        for rules_for_language in _compiled_by_language.values():
            applicable.extend(rules_for_language)
    else:
        applicable = list(_compiled_by_language.get(lang_lower, []))
        applicable.extend(_universal_rules)

    # ── Precondition filtering — skip rules that don't apply ─────────
    content_lower = file_content[:50_000].lower() if file_content else ""
    detected_frameworks = frozenset(
        _project_context.frameworks if _project_context else ()
    )
    filtered_applicable: List[CompiledRule] = []
    precond_skipped = 0
    for cr in applicable:
        if is_json_file and not cr.rule.supports_json_files:
            precond_skipped += 1
            continue

        # PART 2 + PART 6: Rule context gating + file type filtering
        should_run, gate_reason = should_rule_execute(
            cr.rule.rule_id,
            cr.rule.language,
            file_name,
            detected_frameworks,
        )
        if not should_run:
            precond_skipped += 1
            continue

        if cr.rule.preconditions:
            precond = RulePreconditions.from_tuple(cr.rule.preconditions)
            should_run, reason = evaluate_preconditions(
                precond, file_name, language,
                project_context=_project_context,
                content_lower=content_lower,
            )
            if not should_run:
                precond_skipped += 1
                continue
        filtered_applicable.append(cr)

    rules_count = len(filtered_applicable)
    logger.info(
        "[pid %d] Scanning file %s of %s: %s (lang=%s, rules=%d, skipped=%d, size=%d, mem=%.1fMB)",
        pid, file_num, total_hint, file_name, language, rules_count,
        precond_skipped, len(file_content), mem_mb,
    )

    if not filtered_applicable:
        logger.info("[pid %d] File %s of %s: %s — no applicable rules, skipped",
                     pid, file_num, total_hint, file_name)
        return []

    start_time = time.monotonic()
    try:
        findings = detect_in_file(file_content, file_name, filtered_applicable)
        elapsed_ms = (time.monotonic() - start_time) * 1000
        logger.info(
            "[pid %d] File %s of %s: %s — %d findings in %.0fms (rules=%d, mem=%.1fMB)",
            pid, file_num, total_hint, file_name, len(findings),
            elapsed_ms, rules_count, _get_memory_mb(),
        )
        return [f.to_dict() for f in findings]
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        logger.error(
            "[pid %d] File %s of %s: %s — FAILED after %.0fms: %s (rules=%d, mem=%.1fMB)",
            pid, file_num, total_hint, file_name, elapsed_ms, exc,
            rules_count, _get_memory_mb(),
            exc_info=True,
        )
        return []


def worker_get_profiler_snapshot() -> dict:
    """Return the per-process profiler snapshot.

    Called via executor at the end of a scan to collect profiling
    data from each worker process.  Returned dict is picklable.
    """
    return get_profiler_snapshot()


def worker_scan_file_safe(
    file_content: str,
    file_name: str,
    language: str,
) -> dict:
    """Crash-safe worker wrapper — NEVER raises exceptions.

    Returns a structured result dict:
        {
            "status": "ok" | "error" | "skipped",
            "file": str,
            "findings": List[dict],
            "error": str | None,
            "pid": int,
            "elapsed_ms": float,
            "rules_executed": int,
        }

    This is the function submitted to ProcessPoolExecutor by the
    ParallelScanController.  Exceptions are caught and encoded
    in the result dict so the controller can track failures without
    needing exception handling on futures.
    """
    pid = os.getpid()
    start = time.monotonic()
    try:
        if not _initialized:
            logger.error(
                "[pid %d] worker_scan_file_safe: not initialized", pid,
            )
            return {
                "status": "error",
                "file": file_name,
                "findings": [],
                "error": "Worker not initialized",
                "pid": pid,
                "elapsed_ms": 0.0,
                "rules_executed": 0,
            }

        # Count applicable rules for the response
        lang_lower = language.lower()
        if is_yaml_language(lang_lower):
            applicable = list(_yaml_rules)
            applicable.extend(_yaml_by_language.get(lang_lower, []))
        else:
            applicable = list(_compiled_by_language.get(lang_lower, []))
            applicable.extend(_universal_rules)
        rules_count = len(applicable)

        # Delegate to existing worker_scan_file for actual scanning
        finding_dicts = worker_scan_file(file_content, file_name, language)
        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "status": "ok",
            "file": file_name,
            "findings": finding_dicts,
            "error": None,
            "pid": pid,
            "elapsed_ms": round(elapsed_ms, 1),
            "rules_executed": rules_count,
        }

    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        tb = traceback.format_exc()
        logger.error(
            "[pid %d] worker_scan_file_safe CRASHED on %s after %.0fms: %s\n%s",
            pid, file_name, elapsed_ms, exc, tb,
        )
        return {
            "status": "error",
            "file": file_name,
            "findings": [],
            "error": f"{type(exc).__name__}: {exc}",
            "pid": pid,
            "elapsed_ms": round(elapsed_ms, 1),
            "rules_executed": 0,
        }
