"""secureai scan --ai -- AI-powered scan with Codex false-positive removal.

Pipeline:
    1. Run the standard SAST scan (reuses existing engine)
    2. Enhance findings with actual source-code lines
    3. Send enhanced findings to OpenAI Codex CLI
    4. Parse Codex response, remove false positives
    5. Write AI-validated JSON report

Note: Codex CLI uses its own auth (codex auth / ChatGPT sign-in).
      No API key environment variable needed. Free tier works.
"""

import json
import os
import sys
import time
from typing import Dict, List, Optional, Set

from cli.scanner.result_formatter import (
    print_banner,
    print_findings,
    print_summary,
    _c,
)


def _safe(text: str) -> str:
    """Make text safe for Windows cp1252 consoles."""
    replacements = {
        "\u2716": "X",   # heavy multiplication x -> X
        "\u2714": "*",   # heavy check mark -> *
        "\u2713": "*",   # check mark -> *
        "\u2717": "X",   # ballot x -> X
        "\u2718": "X",   # heavy ballot x -> X
        "\u2022": "-",   # bullet -> -
        "\u2192": "->",  # right arrow -> ->
        "\u2014": "--",  # em dash -> --
        "\u2605": "*",   # star -> *
        "\u26a0": "!",   # warning sign -> !
        "\u2716": "X",   # cross mark -> X
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    return text


def _print_ai_banner() -> None:
    """Print the AI scan mode banner."""
    try:
        print(_c("bold", "\n  SecureAI Code Analyzer -- AI Mode"))
        print(_c("magenta", "  Powered by OpenAI Codex"))
        print(_c("dim", "  SAST Scan + AI False-Positive Removal\n"))
    except UnicodeEncodeError:
        print("\n  SecureAI Code Analyzer -- AI Mode")
        print("  Powered by OpenAI Codex")
        print("  SAST Scan + AI False-Positive Removal\n")


def _print_ai_progress(step: int, total: int, message: str) -> None:
    """Print a step indicator for the AI pipeline."""
    color = "cyan"
    try:
        print(f"  {_c(color, f'[{step}/{total}]')} {message}")
    except UnicodeEncodeError:
        print(f"  [{step}/{total}] {message}")


def _print_codex_results(
    original_count: int,
    true_pos: int,
    false_pos: int,
    removed: List[Dict],
) -> None:
    """Print Codex analysis results summary."""
    print()
    try:
        print(_c("bold", "  -- Codex AI Analysis Results --"))
    except UnicodeEncodeError:
        print("  -- Codex AI Analysis Results --")
    print()
    print(f"    Findings reviewed   : {original_count}")
    print(f"    True positives      : {true_pos}")
    print(f"    False positives removed: {false_pos}")

    if removed:
        print()
        print("    Removed false positives:")
        for r in removed[:10]:
            rule = r.get("rule_id", "?")
            fname = r.get("file_name", "?")
            line = r.get("line", "?")
            reason = r.get("reason", "No reason given")
            print(f"      X {rule} @ {fname}:L{line}")
            print(f"        {reason[:120]}")
        if len(removed) > 10:
            print(f"      ... and {len(removed) - 10} more")
    print()


def run_scan_ai(
    path: str,
    output: str = "secureai-ai-report.json",
    severity: Optional[str] = None,
    lang: Optional[str] = None,
    json_output: bool = False,
    show_progress: bool = True,
    workers: Optional[int] = None,
    confidence_threshold: str = "medium",
    show_low_confidence: bool = False,
    timeout: int = 180,
) -> int:
    """Execute the AI-enhanced scan pipeline.

    1. Run standard SAST scan
    2. Enhance findings with source code
    3. Send to Codex for AI validation (free tier, no API key needed)
    4. Output cleaned results

    Returns exit code: 0 = clean, 1 = findings, 2 = error.
    """
    start_time = time.monotonic()
    total_steps = 5

    # ── Step 0: Validate prerequisites ───────────────────────────────
    if not json_output:
        _print_ai_banner()

    from cli.utils.codex_integration import (
        check_codex_installed,
        install_codex,
    )

    if not check_codex_installed():
        if not json_output:
            _print_ai_progress(0, total_steps, "Codex CLI not found. Installing...")
        success, msg = install_codex()
        if not success:
            if not json_output:
                print(f"\n  X {msg}")
                print("  Falling back to standard scan...\n")
            # Fallback to standard scan
            from cli.commands.scan_command import run_scan
            return run_scan(
                path=path,
                output=output.replace("-ai-report", "-report"),
                severity=severity,
                lang=lang,
                json_output=json_output,
                show_progress=show_progress,
                workers=workers,
                confidence_threshold=confidence_threshold,
                show_low_confidence=show_low_confidence,
            )
        if not json_output:
            print(f"    * {msg}")

    # ── Step 1: Run standard SAST scan ───────────────────────────────
    if not json_output:
        _print_ai_progress(1, total_steps, "Running SAST scan engine...")

    target = os.path.abspath(path)
    if not os.path.exists(target):
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Import and run the core scan inline (capture findings, don't write report yet)
    from cli.scanner.directory_walker import discover_files
    from cli.utils.language_detector import summarize_languages
    from engine.framework_detector import detect_project_context
    from engine.finding_aggregation import aggregate_finding_dicts
    from engine.scan_scope import is_report_file, should_exclude_path

    lang_filter: Optional[Set[str]] = None
    if lang:
        lang_filter = {l.strip().lower() for l in lang.split(",")}

    files = discover_files(target, lang_filter)
    if not files:
        if not json_output:
            print("  No scannable files found.\n")
        return 0

    lang_summary = summarize_languages(files)

    if not json_output:
        print(f"    Target: {target}")
        print(f"    Files : {len(files)} ({len(lang_summary)} languages)")

    # Read file contents
    scan_jobs: List[tuple] = []
    for file_path, language in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            rel_path = os.path.relpath(file_path, target)
            scan_jobs.append((content, rel_path, language))
        except (OSError, IOError):
            continue

    if not scan_jobs:
        if not json_output:
            print("  No readable files to scan.\n")
        return 0

    # Detect project context
    project_context = detect_project_context(target, files)
    ctx_dict = project_context.to_dict() if project_context else None

    # Run scan engine
    all_finding_dicts: List[Dict] = []
    total = len(scan_jobs)

    total_content_size = sum(len(j[0]) for j in scan_jobs)
    use_multiprocess = total > 50 or total_content_size > 1_000_000

    if use_multiprocess:
        import functools
        from concurrent.futures import ProcessPoolExecutor, as_completed
        from cli.commands.scan_command import _scan_worker, _init_worker_with_context

        worker_count = workers or min(os.cpu_count() or 4, 8)
        init_func = functools.partial(_init_worker_with_context, ctx_dict)
        executor = ProcessPoolExecutor(
            max_workers=worker_count,
            initializer=init_func,
        )
        futures = {}
        for job in scan_jobs:
            fut = executor.submit(_scan_worker, job)
            futures[fut] = job[1]

        for fut in as_completed(futures):
            try:
                result_dicts = fut.result(timeout=120)
                all_finding_dicts.extend(result_dicts)
            except Exception:
                pass

        executor.shutdown(wait=False)
    else:
        from engine.worker import worker_init, worker_scan_file, worker_set_total, worker_set_project_context
        worker_init()
        if ctx_dict:
            worker_set_project_context(ctx_dict)
        worker_set_total(total)

        for content, file_name, language in scan_jobs:
            try:
                result_dicts = worker_scan_file(content, file_name, language)
                all_finding_dicts.extend(result_dicts)
            except Exception:
                pass

    # Deduplicate
    from cli.commands.scan_command import _deduplicate_finding_dicts
    all_finding_dicts = _deduplicate_finding_dicts(all_finding_dicts)

    # Remove self-scan findings
    all_finding_dicts = [
        f for f in all_finding_dicts
        if not is_report_file(str(f.get("file_name", "")))
        and not should_exclude_path(str(f.get("file_name", "")))
    ]

    # Apply severity filter
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if severity:
        min_sev = severity_order.get(severity.lower(), 0)
        all_finding_dicts = [
            f for f in all_finding_dicts
            if severity_order.get(f.get("severity", "info"), 0) >= min_sev
        ]

    # Apply confidence filter
    confidence_levels = {"high": 70, "medium": 40, "low": 0}
    if show_low_confidence:
        min_confidence = 0
    else:
        min_confidence = confidence_levels.get(confidence_threshold.lower(), 40)

    all_finding_dicts = [
        f for f in all_finding_dicts
        if (f.get("adjusted_confidence") or f.get("confidence", 0)) >= min_confidence
    ]

    # Aggregate
    aggregated = aggregate_finding_dicts(all_finding_dicts)

    scan_elapsed = time.monotonic() - start_time

    if not json_output:
        print(f"    * Scan complete: {len(aggregated)} findings in {scan_elapsed:.1f}s")

    if not aggregated:
        if not json_output:
            print("\n  * No vulnerabilities found. Code is clean!\n")
        return 0

    # ── Step 2: Enhance findings with source code ────────────────────
    if not json_output:
        _print_ai_progress(2, total_steps, "Enhancing findings with source code...")

    from cli.utils.codex_integration import enhance_findings_with_code
    enhanced = enhance_findings_with_code(aggregated, target)

    if not json_output:
        enhanced_count = sum(1 for f in enhanced if f.get("source_line"))
        print(f"    * Enhanced {enhanced_count}/{len(enhanced)} findings with code context")

    # ── Step 3: Send to Codex for analysis ───────────────────────────
    if not json_output:
        _print_ai_progress(3, total_steps, "Sending findings to OpenAI Codex for analysis...")
        print(f"    (timeout: {timeout}s, reviewing {len(enhanced)} findings)")

    from cli.utils.codex_integration import run_codex_analysis
    success, codex_result = run_codex_analysis(enhanced, timeout_sec=timeout)

    # ── Step 4: Process results ──────────────────────────────────────
    if not json_output:
        _print_ai_progress(4, total_steps, "Processing Codex results...")

    if success:
        validated = codex_result.get("validated_findings", aggregated)
        removed = codex_result.get("removed_findings", [])
        codex_summary = codex_result.get("summary", {})

        if not json_output:
            _print_codex_results(
                original_count=len(aggregated),
                true_pos=len(validated),
                false_pos=len(removed),
                removed=removed,
            )
    else:
        # Codex failed -- use original findings
        if not json_output:
            error_msg = codex_result.get("error", "Unknown error")
            print(f"\n    ! Codex analysis failed: {error_msg}")
            print("    Using original scan results (no AI filtering)\n")
        validated = aggregated
        removed = []
        codex_summary = None

    # ── Step 5: Write report & output ────────────────────────────────
    if not json_output:
        _print_ai_progress(5, total_steps, "Generating AI-validated report...")

    total_elapsed = time.monotonic() - start_time
    languages = list({j[2] for j in scan_jobs})

    from cli.scanner.ai_report_writer import write_ai_report
    report_path = write_ai_report(
        validated_findings=validated,
        removed_findings=removed,
        original_count=len(aggregated),
        output_path=output,
        scan_target=target,
        files_scanned=len(scan_jobs),
        elapsed_sec=total_elapsed,
        languages=languages,
        codex_summary=codex_summary,
    )

    if json_output:
        # Output validated findings as JSON to stdout
        result = {
            "ai_validation": {
                "engine": "openai-codex",
                "original_findings": len(aggregated),
                "true_positives": len(validated),
                "false_positives_removed": len(removed),
            },
            "findings": validated,
        }
        json.dump(result, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print_findings(validated, severity)
        print_summary(validated, total_elapsed, len(scan_jobs))
        print(f"  * AI-validated report saved: {report_path}")
        if removed:
            print(f"    ({len(removed)} false positives removed by Codex)")
        print()

    return 1 if validated else 0
