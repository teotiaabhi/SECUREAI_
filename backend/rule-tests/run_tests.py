#!/usr/bin/env python3
"""Main entry point for the rule validation test framework.

Usage:
    python run_tests.py                         # Run all tests with defaults
    python run_tests.py --category injection     # Filter by category
    python run_tests.py --language python         # Filter by language
    python run_tests.py --report json,markdown    # Specify report formats
    python run_tests.py --save-baseline v2.0.0    # Save a new baseline
    python run_tests.py --check-regression        # Compare against baseline
    python run_tests.py --compare-versions /old /new  # Diff two rule sets
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure the runner package is importable when invoked from the rule-tests dir.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from runner.config import load_config, RuleTestConfig
from runner.rule_loader import load_all_rules, RuleRegistry
from runner.test_loader import load_all_tests, TestSuite
from runner.engine import run_tests, TestRunResult, Outcome
from runner.metrics import (
    compute_rule_metrics,
    compute_category_metrics,
    compute_language_metrics,
    compute_engine_metrics,
    RuleMetrics,
)
from runner.reporter import ReportGenerator
from runner.regression import BaselineManager, ThresholdConfig


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Security rule validation and benchmarking framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=None,
        help="Path to the rules directory (overrides config).",
    )
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=None,
        help="Path to the test samples directory (overrides config).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to a YAML configuration file.",
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Only run tests for a specific category (e.g. injection, xss).",
    )
    parser.add_argument(
        "--language",
        type=str,
        default=None,
        help="Only run tests for a specific language (e.g. python, javascript).",
    )
    parser.add_argument(
        "--rule-id",
        type=str,
        default=None,
        help="Only run tests for a specific rule ID.",
    )
    parser.add_argument(
        "--report",
        type=str,
        default="console",
        help="Comma-separated report formats: console, json, markdown (default: console).",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Output directory for report files.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers (default: from config).",
    )
    parser.add_argument(
        "--confidence-threshold",
        type=float,
        default=None,
        help="Minimum confidence threshold for matches.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-rule timeout in milliseconds.",
    )
    parser.add_argument(
        "--save-baseline",
        type=str,
        default=None,
        metavar="TAG",
        help="Save the current run as a baseline with the given tag.",
    )
    parser.add_argument(
        "--check-regression",
        action="store_true",
        help="Compare the current run against the latest baseline.",
    )
    parser.add_argument(
        "--compare-versions",
        nargs=2,
        type=Path,
        default=None,
        metavar=("BASELINE_DIR", "CURRENT_DIR"),
        help="Compare two rule directories and produce a diff report.",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with non-zero code if a regression is detected.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    return parser


def _collect_rule_metrics(
    run_result: TestRunResult,
    registry: RuleRegistry,
) -> List[RuleMetrics]:
    """Aggregate per-rule metrics from the test run result."""

    # Accumulate counters per rule_id.
    rule_data: Dict[str, Dict[str, Any]] = {}

    for cr in run_result.case_results:
        for mr in cr.match_results:
            entry = rule_data.setdefault(mr.rule_id, {
                "true_positives": 0,
                "false_positives": 0,
                "true_negatives": 0,
                "false_negatives": 0,
                "detection_times_ms": [],
                "confidence_scores": [],
                "total_bytes_scanned": 0,
                "total_matches": 0,
            })
            outcome = cr.outcomes.get(mr.rule_id)
            if outcome == Outcome.TRUE_POSITIVE:
                entry["true_positives"] += 1
            elif outcome == Outcome.FALSE_POSITIVE:
                entry["false_positives"] += 1
            elif outcome == Outcome.TRUE_NEGATIVE:
                entry["true_negatives"] += 1
            elif outcome == Outcome.FALSE_NEGATIVE:
                entry["false_negatives"] += 1

            entry["detection_times_ms"].append(mr.execution_time_ms)
            if mr.confidence > 0:
                entry["confidence_scores"].append(mr.confidence)
            entry["total_bytes_scanned"] += cr.test_case.file_size_bytes
            entry["total_matches"] += mr.match_count

    # Also count FNs for expected rules that were never evaluated.
    for cr in run_result.case_results:
        for rule_id, outcome in cr.outcomes.items():
            if rule_id not in rule_data:
                rule_data[rule_id] = {
                    "true_positives": 0,
                    "false_positives": 0,
                    "true_negatives": 0,
                    "false_negatives": 0,
                    "detection_times_ms": [],
                    "confidence_scores": [],
                    "total_bytes_scanned": 0,
                    "total_matches": 0,
                }
            if outcome == Outcome.FALSE_NEGATIVE and rule_id not in {
                mr.rule_id for mr in cr.match_results
            }:
                rule_data[rule_id]["false_negatives"] += 1

    all_metrics: List[RuleMetrics] = []
    for rule_id, data in sorted(rule_data.items()):
        rm = compute_rule_metrics(rule_id, data)
        all_metrics.append(rm)

    return all_metrics


def _build_report_dicts(
    all_rule_metrics: List[RuleMetrics],
    registry: RuleRegistry,
    run_result: TestRunResult,
    total_time: float,
) -> tuple:
    """Prepare metric dictionaries in the format expected by ReportGenerator."""

    # Engine-level metrics.
    engine_m = compute_engine_metrics(
        all_rule_metrics,
        compilation_times={
            r.rule_id: r.regex_compile_time_ms for r in registry.all_rules
        },
        total_time=total_time,
    )
    engine_dict: Dict[str, Any] = {
        "total_rules": engine_m.total_rules,
        "total_tests": engine_m.total_tests,
        "precision": engine_m.global_precision,
        "recall": engine_m.global_recall,
        "f1_score": engine_m.global_f1,
        "total_time_ms": engine_m.total_execution_time_s * 1000.0,
        "regex_compile_time_ms": engine_m.regex_compilation_time_ms,
        "avg_match_time_ms": engine_m.avg_detection_time_ms,
        "memory_estimate_mb": engine_m.estimated_memory_mb,
    }

    # Per-rule metric dicts.
    rule_dicts: List[Dict[str, Any]] = []
    for rm in all_rule_metrics:
        rule_def = registry.get_rule_by_id(rm.rule_id)
        rule_dicts.append({
            "rule_id": rm.rule_id,
            "category": rule_def.category if rule_def else "unknown",
            "language": rule_def.language if rule_def else "unknown",
            "total_tests": rm.true_positives + rm.false_positives + rm.true_negatives + rm.false_negatives,
            "true_positives": rm.true_positives,
            "false_positives": rm.false_positives,
            "true_negatives": rm.true_negatives,
            "false_negatives": rm.false_negatives,
            "precision": rm.precision,
            "recall": rm.recall,
            "f1_score": rm.f1_score,
            "status": rm.status,
            "avg_match_time_ms": rm.avg_detection_time_ms,
            "confidence": rm.confidence_mean,
        })

    # Per-category metrics.
    cat_dicts: List[Dict[str, Any]] = []
    for cat in sorted(registry.categories):
        cat_rule_ids = {r.rule_id for r in registry.get_rules_by_category(cat)}
        cat_rule_metrics = [m for m in all_rule_metrics if m.rule_id in cat_rule_ids]
        if not cat_rule_metrics:
            continue
        cm = compute_category_metrics(cat, cat_rule_metrics)
        cat_dicts.append({
            "category": cm.category,
            "rule_count": cm.rule_count,
            "test_count": cm.total_tests,
            "precision": cm.aggregate_precision,
            "recall": cm.aggregate_recall,
            "f1_score": cm.aggregate_f1,
            "avg_time_ms": cm.avg_detection_time_ms,
        })

    # Per-language metrics.
    lang_dicts: List[Dict[str, Any]] = []
    for lang in sorted(registry.languages):
        lang_rule_ids = {r.rule_id for r in registry.get_rules_by_language(lang)}
        lang_rule_metrics = [m for m in all_rule_metrics if m.rule_id in lang_rule_ids]
        if not lang_rule_metrics:
            continue
        lm = compute_language_metrics(lang, lang_rule_metrics)
        lang_dicts.append({
            "language": lm.language,
            "rule_count": lm.rule_count,
            "test_count": lm.total_tests,
            "precision": lm.aggregate_precision,
            "recall": lm.aggregate_recall,
            "f1_score": lm.aggregate_f1,
        })

    return engine_dict, rule_dicts, cat_dicts, lang_dicts


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()

    # -- Logging -------------------------------------------------------
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # -- Version comparison mode (standalone) --------------------------
    if args.compare_versions:
        from runner.version_compare import compare_versions, format_comparison_report
        result = compare_versions(
            baseline_dir=args.compare_versions[0],
            current_dir=args.compare_versions[1],
            baseline_tag=str(args.compare_versions[0]),
            current_tag=str(args.compare_versions[1]),
        )
        report = format_comparison_report(result)
        print(report)
        return 0

    # -- Configuration -------------------------------------------------
    config = load_config(args.config)
    if args.rules_dir:
        config.rules_dir = args.rules_dir
    if args.tests_dir:
        config.tests_dir = args.tests_dir
    if args.workers:
        config.parallel_workers = args.workers
    if args.confidence_threshold is not None:
        config.confidence_threshold = args.confidence_threshold
    if args.timeout is not None:
        config.timeout_per_rule_ms = args.timeout
    if args.report_dir:
        config.reports_dir = args.report_dir
    if args.verbose:
        config.verbose = True

    # -- Load rules and tests ------------------------------------------
    logging.getLogger().info("Loading rules from %s", config.rules_dir)
    registry = load_all_rules(config.rules_dir)
    if len(registry) == 0:
        logging.getLogger().error("No rules loaded. Check --rules-dir path.")
        return 1

    logging.getLogger().info("Loading tests from %s", config.tests_dir)
    suite = load_all_tests(config.tests_dir)
    if len(suite) == 0:
        logging.getLogger().error("No test cases loaded. Check --tests-dir path.")
        return 1

    # -- Run tests -----------------------------------------------------
    wall_start = time.perf_counter()
    run_result = run_tests(
        registry=registry,
        suite=suite,
        confidence_threshold=config.confidence_threshold,
        timeout_ms=config.timeout_per_rule_ms,
        parallel_workers=config.parallel_workers,
    )
    wall_time = time.perf_counter() - wall_start

    # -- Compute metrics -----------------------------------------------
    all_rule_metrics = _collect_rule_metrics(run_result, registry)
    engine_dict, rule_dicts, cat_dicts, lang_dicts = _build_report_dicts(
        all_rule_metrics, registry, run_result, wall_time,
    )

    # -- Generate reports ----------------------------------------------
    reporter = ReportGenerator(use_color=True)
    report_formats = {f.strip().lower() for f in args.report.split(",")}

    if "console" in report_formats:
        reporter.generate_console_report(engine_dict, rule_dicts, cat_dicts, lang_dicts)

    if "json" in report_formats:
        json_path = reporter.generate_json_report(
            engine_dict, rule_dicts, cat_dicts, lang_dicts,
        )
        logging.getLogger().info("JSON report: %s", json_path)

    if "markdown" in report_formats:
        md_path = reporter.generate_markdown_report(
            engine_dict, rule_dicts, cat_dicts, lang_dicts,
        )
        logging.getLogger().info("Markdown report: %s", md_path)

    # -- Failure report for non-passing rules --------------------------
    failed_rules = [rd for rd in rule_dicts if rd.get("status") not in ("stable",)]
    if failed_rules:
        reporter.generate_failure_report(failed_rules)

    # -- Baseline management -------------------------------------------
    mgr = BaselineManager(config.baselines_dir)
    exit_code = 0

    baseline_metrics = {
        "engine": engine_dict,
        "rules": {rd["rule_id"]: rd for rd in rule_dicts},
    }

    if args.save_baseline:
        mgr.save_baseline(baseline_metrics, tag=args.save_baseline)

    if args.check_regression:
        report = mgr.check_regression(baseline_metrics)
        mgr.save_regression_report(report)

        if not report.overall_passed:
            logging.getLogger().warning("REGRESSION DETECTED")
            for r in report.results:
                if not r.passed:
                    for v in r.violations:
                        logging.getLogger().warning("  [%s] %s", r.rule_id, v)
            if args.fail_on_regression:
                exit_code = 2

    # -- Summary -------------------------------------------------------
    summary = run_result.summary
    logging.getLogger().info(
        "Done: TP=%d FP=%d TN=%d FN=%d | P=%.3f R=%.3f F1=%.3f | %.1fs",
        summary.true_positives,
        summary.false_positives,
        summary.true_negatives,
        summary.false_negatives,
        summary.precision,
        summary.recall,
        summary.f1_score,
        wall_time,
    )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
