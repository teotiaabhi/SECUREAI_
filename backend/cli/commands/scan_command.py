"""secureai scan — core scanning command.

Discovers files, initializes the engine worker, scans in parallel,
formats output, and writes a JSON report.
"""

import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from cli.scanner.directory_walker import discover_files
from cli.scanner.result_formatter import (
    print_banner,
    print_findings,
    print_progress,
    print_scan_start,
    print_summary,
)
from cli.scanner.report_writer import write_report
from cli.utils.language_detector import summarize_languages
from engine.framework_detector import detect_project_context
from engine.finding_aggregation import aggregate_finding_dicts
from engine.scan_scope import is_report_file, should_exclude_path


def _deduplicate_finding_dicts(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate raw findings before output and report writing."""
    deduped: List[Dict] = []
    seen: Set[Tuple[str, str, int, str]] = set()

    for finding in findings:
        key = (
            str(finding.get("rule_id", "")),
            str(finding.get("file_name", "")),
            int(finding.get("line", 0) or 0),
            str(finding.get("matched_pattern", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def _read_file_safe(path: str) -> Optional[str]:
    """Read file content, returning None on failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, IOError):
        return None


def _scan_worker(args):
    """Worker function for parallel scanning.

    Runs in a child process. Expects (file_content, file_name, language).
    Returns list of finding dicts.
    """
    file_content, file_name, language = args
    from engine.worker import worker_scan_file
    return worker_scan_file(file_content, file_name, language)


def _init_worker_with_context(ctx_dict: Optional[Dict]):
    """Process pool initializer — loads rules, compiles patterns, sets project context."""
    from engine.worker import worker_init, worker_set_project_context
    worker_init()
    if ctx_dict:
        worker_set_project_context(ctx_dict)


def _init_worker():
    """Process pool initializer — loads rules and compiles patterns."""
    _init_worker_with_context(None)


def run_scan(
    path: str,
    output: str = "secureai-report.json",
    severity: Optional[str] = None,
    lang: Optional[str] = None,
    json_output: bool = False,
    show_progress: bool = True,
    workers: Optional[int] = None,
    confidence_threshold: str = "medium",
    show_low_confidence: bool = False,
    debug_rule: Optional[str] = None,
    debug_file: Optional[str] = None,
) -> int:
    """Execute a full scan pipeline.

    1. Discover files
    2. Initialize engine
    3. Scan (parallel or in-process)
    4. Format and display results
    5. Write JSON report

    Returns exit code: 0 = clean, 1 = findings found, 2 = error.
    """
    start_time = time.monotonic()

    # Resolve target path
    target = os.path.abspath(path)
    if not os.path.exists(target):
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Parse language filter
    lang_filter: Optional[Set[str]] = None
    if lang:
        lang_filter = {l.strip().lower() for l in lang.split(",")}

    if not json_output:
        print_banner()

    # ── 1. Discover files ────────────────────────────────────────────
    files = discover_files(target, lang_filter)
    if not files:
        if not json_output:
            print("  No scannable files found.\n")
        return 0

    lang_summary = summarize_languages(files)

    if not json_output:
        print_scan_start(target, len(files), len(lang_summary))

    # ── 2. Read file contents ────────────────────────────────────────
    scan_jobs: List[tuple] = []
    for file_path, language in files:
        content = _read_file_safe(file_path)
        if content is None:
            continue
        # Use relative path as the display name in findings
        rel_path = os.path.relpath(file_path, target)
        scan_jobs.append((content, rel_path, language))

    if not scan_jobs:
        if not json_output:
            print("  No readable files to scan.\n")
        return 0

    # ── 3. Detect project context (frameworks, languages, patterns) ──
    project_context = detect_project_context(target, files)
    ctx_dict = project_context.to_dict() if project_context else None

    # ── 4. Scan ──────────────────────────────────────────────────────
    all_finding_dicts: List[Dict] = []
    files_done = 0
    total = len(scan_jobs)

    # Decide parallelism: use multiprocessing for larger projects
    total_content_size = sum(len(j[0]) for j in scan_jobs)
    use_multiprocess = total > 50 or total_content_size > 1_000_000

    if use_multiprocess:
        import functools
        worker_count = workers or min(os.cpu_count() or 4, 8)
        init_func = functools.partial(_init_worker_with_context, ctx_dict)
        executor = ProcessPoolExecutor(
            max_workers=worker_count,
            initializer=init_func,
        )
        futures = {}
        for job in scan_jobs:
            fut = executor.submit(_scan_worker, job)
            futures[fut] = job[1]  # file_name

        for fut in as_completed(futures):
            file_name = futures[fut]
            files_done += 1
            try:
                result_dicts = fut.result(timeout=120)
                all_finding_dicts.extend(result_dicts)
            except Exception:
                pass  # Worker errors logged internally

            if show_progress and not json_output:
                print_progress(files_done, total, file_name)

        executor.shutdown(wait=False)
    else:
        # In-process scanning (avoids process pool overhead for small projects)
        from engine.worker import worker_init, worker_scan_file, worker_set_total, worker_set_project_context
        worker_init()
        if ctx_dict:
            worker_set_project_context(ctx_dict)
        worker_set_total(total)

        for content, file_name, language in scan_jobs:
            files_done += 1
            try:
                result_dicts = worker_scan_file(content, file_name, language)
                all_finding_dicts.extend(result_dicts)
            except Exception:
                pass

            if show_progress and not json_output:
                print_progress(files_done, total, file_name)

    all_finding_dicts = _deduplicate_finding_dicts(all_finding_dicts)

    # PART 5 + PART 9: Self-scan protection — remove findings from report files
    all_finding_dicts = [
        f for f in all_finding_dicts
        if not is_report_file(str(f.get("file_name", "")))
        and not should_exclude_path(str(f.get("file_name", "")))
    ]

    elapsed = time.monotonic() - start_time

    # ── 4. Apply severity filter ─────────────────────────────────────
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if severity:
        min_sev = severity_order.get(severity.lower(), 0)
        filtered = [
            f for f in all_finding_dicts
            if severity_order.get(f.get("severity", "info"), 0) >= min_sev
        ]
    else:
        filtered = all_finding_dicts

    # ── 4b. Apply confidence filter (PART 7) ─────────────────────────
    confidence_levels = {"high": 70, "medium": 40, "low": 0}
    if show_low_confidence:
        min_confidence = 0
    else:
        min_confidence = confidence_levels.get(confidence_threshold.lower(), 40)
    
    filtered_by_confidence = []
    for f in filtered:
        adj_conf = f.get("adjusted_confidence")
        if adj_conf is None:
            adj_conf = f.get("confidence", 0)
        
        # Include finding if:
        # 1. It meets the threshold, OR
        # 2. show_low_confidence is enabled
        # 3. --debug-rule matches (always show debug targets)
        if adj_conf >= min_confidence:
            filtered_by_confidence.append(f)
        elif debug_rule and f.get("rule_id") == debug_rule:
            filtered_by_confidence.append(f)
    
    filtered = filtered_by_confidence

    # ── 4d. Aggregate findings (PART 4) ────────────────────────────
    aggregated = aggregate_finding_dicts(filtered)

    # ── 4c. Apply debug filtering ──────────────────────────────────
    if debug_rule:
        debug_findings = [f for f in filtered if f.get("rule_id") == debug_rule]
        if debug_file:
            debug_findings = [f for f in debug_findings if f.get("file_name") == debug_file]
        
        if debug_findings and not json_output:
            from engine.rule_debugger import format_debug_summary
            print(f"\n📋 Debug Mode: {debug_rule}\n")
            for finding_dict in debug_findings:
                # Format and print debug info
                try:
                    print(format_debug_summary(finding_dict))
                    print()
                except Exception as exc:
                    print(f"  Error formatting debug info: {exc}")

    # ── 5. Output results (PART 10) ─────────────────────────────────
    if json_output:
        json.dump(aggregated, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print_findings(aggregated, severity)
        print_summary(aggregated, elapsed, len(scan_jobs))

    # ── 6. Write report (with aggregated findings) ───────────────────
    languages = list({j[2] for j in scan_jobs})
    report_path = write_report(
        findings=aggregated,  # Aggregated findings in report
        output_path=output,
        scan_target=target,
        files_scanned=len(scan_jobs),
        elapsed_sec=elapsed,
        languages=languages,
    )

    if not json_output:
        print(f"  Report saved: {report_path}\n")

    # Exit code: 1 if findings found, 0 if clean
    return 1 if aggregated else 0
