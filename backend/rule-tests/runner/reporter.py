"""Reporting module for the rule validation test framework.

Generates console, JSON, and Markdown reports from validation metrics.
Supports formatted tables with box-drawing characters, ANSI color output,
structured JSON, and GitHub-flavored Markdown.

No external dependencies required.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─── ANSI Color Codes ───────────────────────────────────────────────

_COLORS = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

_STATUS_COLORS = {
    "stable": "green",
    "needs_tuning": "yellow",
    "noisy": "red",
    "under_sensitive": "red",
    "unknown": "dim",
}

_STATUS_ICONS_CONSOLE = {
    "stable": "PASS",
    "needs_tuning": "WARN",
    "noisy": "FAIL",
    "under_sensitive": "FAIL",
    "unknown": " -- ",
}

_STATUS_ICONS_MARKDOWN = {
    "stable": ":white_check_mark:",
    "needs_tuning": ":warning:",
    "noisy": ":x:",
    "under_sensitive": ":x:",
    "unknown": ":grey_question:",
}

ENGINE_VERSION = "1.0.0"


# ─── Report Generator ───────────────────────────────────────────────

class ReportGenerator:
    """Generates validation reports in multiple output formats.

    Accepts engine-level, rule-level, category-level, and language-level
    metrics dictionaries and produces console, JSON, and Markdown reports.

    Expected metric dictionary shapes:

        engine_metrics: {
            total_rules: int, total_tests: int,
            precision: float, recall: float, f1_score: float,
            total_time_ms: float,
            regex_compile_time_ms: float,
            avg_match_time_ms: float,
            memory_estimate_mb: float,
        }

        rule_metrics (each element): {
            rule_id: str, category: str, language: str,
            total_tests: int, true_positives: int, false_positives: int,
            true_negatives: int, false_negatives: int,
            precision: float, recall: float, f1_score: float,
            status: str, avg_match_time_ms: float, confidence: float,
        }

        category_metrics (each element): {
            category: str, rule_count: int, test_count: int,
            precision: float, recall: float, f1_score: float,
            avg_time_ms: float,
        }

        language_metrics (each element): {
            language: str, rule_count: int, test_count: int,
            precision: float, recall: float, f1_score: float,
        }
    """

    def __init__(self, use_color: bool = True) -> None:
        """Initialize the report generator.

        Args:
            use_color: Whether to emit ANSI color codes on the console.
                       Automatically disabled when stdout is not a TTY.
        """
        self._use_color = use_color and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    # ── Console Report ───────────────────────────────────────────────

    def generate_console_report(
        self,
        engine_metrics: Dict[str, Any],
        rule_metrics_list: List[Dict[str, Any]],
        category_metrics_list: List[Dict[str, Any]],
        language_metrics_list: List[Dict[str, Any]],
    ) -> str:
        """Build and print a formatted console report.

        Returns the full report string (without ANSI codes stripped) so
        callers can capture it for logging if desired.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: List[str] = []

        # Header
        lines.append("")
        lines.append(self._ansi_color("=" * 72, "cyan"))
        lines.append(self._ansi_color("  Rule Engine Validation Report", "bold"))
        lines.append(self._ansi_color(f"  Generated: {now}", "dim"))
        lines.append(self._ansi_color("=" * 72, "cyan"))
        lines.append("")

        # ── Global Summary ───────────────────────────────────────────
        lines.append(self._ansi_color("  Global Summary", "bold"))
        lines.append(self._ansi_color("  " + "-" * 40, "dim"))
        lines.append(f"  Total Rules:  {engine_metrics.get('total_rules', 0)}")
        lines.append(f"  Total Tests:  {engine_metrics.get('total_tests', 0)}")
        lines.append(f"  Precision:    {self._format_percentage(engine_metrics.get('precision', 0.0))}")
        lines.append(f"  Recall:       {self._format_percentage(engine_metrics.get('recall', 0.0))}")
        lines.append(f"  F1 Score:     {self._format_percentage(engine_metrics.get('f1_score', 0.0))}")
        lines.append(f"  Total Time:   {engine_metrics.get('total_time_ms', 0.0):.1f} ms")
        lines.append("")

        # ── Rule Health Summary ──────────────────────────────────────
        health_buckets: Dict[str, List[str]] = {}
        for rm in rule_metrics_list:
            status = rm.get("status", "unknown")
            health_buckets.setdefault(status, []).append(rm.get("rule_id", "?"))

        lines.append(self._ansi_color("  Rule Health Summary", "bold"))
        health_headers = ["Status", "Count", "Rule IDs"]
        health_rows: List[List[str]] = []
        for status in ("stable", "needs_tuning", "noisy", "under_sensitive"):
            ids = health_buckets.get(status, [])
            if not ids:
                continue
            id_str = self._truncate(", ".join(ids), 42)
            colored_status = self._ansi_color(
                f"[{_STATUS_ICONS_CONSOLE.get(status, '--')}] {status}",
                _STATUS_COLORS.get(status, "dim"),
            )
            health_rows.append([colored_status, str(len(ids)), id_str])

        lines.append(self._format_table(health_headers, health_rows, [30, 7, 44]))
        lines.append("")

        # ── Per-Category Results ─────────────────────────────────────
        lines.append(self._ansi_color("  Per-Category Results", "bold"))
        cat_headers = ["Category", "Rules", "Tests", "Precision", "Recall", "F1", "Avg Time(ms)"]
        cat_rows: List[List[str]] = []
        for cm in category_metrics_list:
            cat_rows.append([
                self._truncate(cm.get("category", ""), 20),
                str(cm.get("rule_count", 0)),
                str(cm.get("test_count", 0)),
                self._format_percentage(cm.get("precision", 0.0)),
                self._format_percentage(cm.get("recall", 0.0)),
                self._format_percentage(cm.get("f1_score", 0.0)),
                f"{cm.get('avg_time_ms', 0.0):.2f}",
            ])
        lines.append(self._format_table(cat_headers, cat_rows, [22, 7, 7, 10, 10, 10, 13]))
        lines.append("")

        # ── Per-Language Results ─────────────────────────────────────
        lines.append(self._ansi_color("  Per-Language Results", "bold"))
        lang_headers = ["Language", "Rules", "Tests", "Precision", "Recall", "F1"]
        lang_rows: List[List[str]] = []
        for lm in language_metrics_list:
            lang_rows.append([
                self._truncate(lm.get("language", ""), 16),
                str(lm.get("rule_count", 0)),
                str(lm.get("test_count", 0)),
                self._format_percentage(lm.get("precision", 0.0)),
                self._format_percentage(lm.get("recall", 0.0)),
                self._format_percentage(lm.get("f1_score", 0.0)),
            ])
        lines.append(self._format_table(lang_headers, lang_rows, [18, 7, 7, 10, 10, 10]))
        lines.append("")

        # ── Rules Needing Attention ──────────────────────────────────
        attention_rules = [
            rm for rm in rule_metrics_list
            if rm.get("status") in ("needs_tuning", "noisy", "under_sensitive")
        ]
        if attention_rules:
            lines.append(self._ansi_color("  Rules Needing Attention", "bold"))
            att_headers = ["Rule ID", "Status", "Precision", "Recall", "F1", "Issue"]
            att_rows: List[List[str]] = []
            for rm in attention_rules:
                issue = self._derive_issue(rm)
                status = rm.get("status", "unknown")
                colored_status = self._ansi_color(status, _STATUS_COLORS.get(status, "dim"))
                att_rows.append([
                    self._truncate(rm.get("rule_id", ""), 22),
                    colored_status,
                    self._format_percentage(rm.get("precision", 0.0)),
                    self._format_percentage(rm.get("recall", 0.0)),
                    self._format_percentage(rm.get("f1_score", 0.0)),
                    self._truncate(issue, 28),
                ])
            lines.append(self._format_table(att_headers, att_rows, [24, 16, 10, 10, 10, 30]))
            lines.append("")

        # ── Performance Summary ──────────────────────────────────────
        lines.append(self._ansi_color("  Performance Summary", "bold"))
        perf_headers = ["Metric", "Value"]
        perf_rows = [
            ["Regex Compile Time", f"{engine_metrics.get('regex_compile_time_ms', 0.0):.2f} ms"],
            ["Avg Match Time", f"{engine_metrics.get('avg_match_time_ms', 0.0):.3f} ms"],
            ["Memory Estimate", f"{engine_metrics.get('memory_estimate_mb', 0.0):.2f} MB"],
            ["Total Execution Time", f"{engine_metrics.get('total_time_ms', 0.0):.1f} ms"],
        ]
        lines.append(self._format_table(perf_headers, perf_rows, [24, 20]))
        lines.append("")
        lines.append(self._ansi_color("=" * 72, "cyan"))
        lines.append("")

        report = "\n".join(lines)
        print(report)
        return report

    # ── JSON Report ──────────────────────────────────────────────────

    def generate_json_report(
        self,
        engine_metrics: Dict[str, Any],
        rule_metrics_list: List[Dict[str, Any]],
        category_metrics_list: List[Dict[str, Any]],
        language_metrics_list: List[Dict[str, Any]],
        output_path: Optional[str] = None,
    ) -> str:
        """Generate a structured JSON report and write it to disk.

        Args:
            output_path: File path for the JSON output.  When *None* a
                timestamped file is created under ``reports/``.

        Returns:
            The absolute path of the written report file.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")

        if output_path is None:
            reports_dir = Path(__file__).resolve().parent.parent / "reports"
            output_path = str(reports_dir / f"report_{timestamp_str}.json")

        # Build health summary counts
        health_summary: Dict[str, int] = {}
        for rm in rule_metrics_list:
            status = rm.get("status", "unknown")
            health_summary[status] = health_summary.get(status, 0) + 1

        report_data: Dict[str, Any] = {
            "metadata": {
                "timestamp": now.isoformat(),
                "engine_version": ENGINE_VERSION,
                "rule_count": engine_metrics.get("total_rules", 0),
                "test_count": engine_metrics.get("total_tests", 0),
            },
            "global_metrics": {
                "precision": engine_metrics.get("precision", 0.0),
                "recall": engine_metrics.get("recall", 0.0),
                "f1_score": engine_metrics.get("f1_score", 0.0),
                "total_time_ms": engine_metrics.get("total_time_ms", 0.0),
            },
            "rules": [
                {
                    "rule_id": rm.get("rule_id"),
                    "category": rm.get("category"),
                    "language": rm.get("language"),
                    "total_tests": rm.get("total_tests", 0),
                    "true_positives": rm.get("true_positives", 0),
                    "false_positives": rm.get("false_positives", 0),
                    "true_negatives": rm.get("true_negatives", 0),
                    "false_negatives": rm.get("false_negatives", 0),
                    "precision": rm.get("precision", 0.0),
                    "recall": rm.get("recall", 0.0),
                    "f1_score": rm.get("f1_score", 0.0),
                    "status": rm.get("status", "unknown"),
                    "avg_match_time_ms": rm.get("avg_match_time_ms", 0.0),
                    "confidence": rm.get("confidence", 0.0),
                }
                for rm in rule_metrics_list
            ],
            "categories": [
                {
                    "category": cm.get("category"),
                    "rule_count": cm.get("rule_count", 0),
                    "test_count": cm.get("test_count", 0),
                    "precision": cm.get("precision", 0.0),
                    "recall": cm.get("recall", 0.0),
                    "f1_score": cm.get("f1_score", 0.0),
                    "avg_time_ms": cm.get("avg_time_ms", 0.0),
                }
                for cm in category_metrics_list
            ],
            "languages": [
                {
                    "language": lm.get("language"),
                    "rule_count": lm.get("rule_count", 0),
                    "test_count": lm.get("test_count", 0),
                    "precision": lm.get("precision", 0.0),
                    "recall": lm.get("recall", 0.0),
                    "f1_score": lm.get("f1_score", 0.0),
                }
                for lm in language_metrics_list
            ],
            "performance": {
                "regex_compile_time_ms": engine_metrics.get("regex_compile_time_ms", 0.0),
                "avg_match_time_ms": engine_metrics.get("avg_match_time_ms", 0.0),
                "memory_estimate_mb": engine_metrics.get("memory_estimate_mb", 0.0),
            },
            "health_summary": health_summary,
        }

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, default=str)

        return str(out.resolve())

    # ── Markdown Report ──────────────────────────────────────────────

    def generate_markdown_report(
        self,
        engine_metrics: Dict[str, Any],
        rule_metrics_list: List[Dict[str, Any]],
        category_metrics_list: List[Dict[str, Any]],
        language_metrics_list: List[Dict[str, Any]],
        output_path: Optional[str] = None,
    ) -> str:
        """Generate a GitHub-flavored Markdown report and write it to disk.

        Returns:
            The absolute path of the written report file.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")

        if output_path is None:
            reports_dir = Path(__file__).resolve().parent.parent / "reports"
            output_path = str(reports_dir / f"report_{timestamp_str}.md")

        md: List[str] = []

        # Title
        md.append("# Rule Engine Validation Report")
        md.append("")
        md.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        md.append(f"**Engine Version:** {ENGINE_VERSION}")
        md.append("")

        # ── Executive Summary ────────────────────────────────────────
        md.append("---")
        md.append("## Executive Summary")
        md.append("")
        total_rules = engine_metrics.get("total_rules", 0)
        total_tests = engine_metrics.get("total_tests", 0)
        stable_count = sum(1 for rm in rule_metrics_list if rm.get("status") == "stable")
        attention_count = sum(
            1 for rm in rule_metrics_list
            if rm.get("status") in ("needs_tuning", "noisy", "under_sensitive")
        )
        md.append(f"- **{total_rules}** rules validated against **{total_tests}** test cases")
        md.append(f"- **{stable_count}** rules are stable, **{attention_count}** need attention")
        md.append(
            f"- Global F1 Score: **{self._format_percentage(engine_metrics.get('f1_score', 0.0))}**"
        )
        md.append("")

        # ── Global Metrics ───────────────────────────────────────────
        md.append("---")
        md.append("## Global Metrics")
        md.append("")
        md.append("| Metric | Value |")
        md.append("| ------ | ----- |")
        md.append(f"| Total Rules | {total_rules} |")
        md.append(f"| Total Tests | {total_tests} |")
        md.append(f"| Precision | {self._format_percentage(engine_metrics.get('precision', 0.0))} |")
        md.append(f"| Recall | {self._format_percentage(engine_metrics.get('recall', 0.0))} |")
        md.append(f"| F1 Score | {self._format_percentage(engine_metrics.get('f1_score', 0.0))} |")
        md.append(f"| Total Time | {engine_metrics.get('total_time_ms', 0.0):.1f} ms |")
        md.append("")

        # ── Category Breakdown ───────────────────────────────────────
        md.append("---")
        md.append("## Category Breakdown")
        md.append("")
        md.append("| Category | Rules | Tests | Precision | Recall | F1 | Avg Time(ms) |")
        md.append("| -------- | ----: | ----: | --------: | -----: | -: | -----------: |")
        for cm in category_metrics_list:
            md.append(
                f"| {cm.get('category', '')} "
                f"| {cm.get('rule_count', 0)} "
                f"| {cm.get('test_count', 0)} "
                f"| {self._format_percentage(cm.get('precision', 0.0))} "
                f"| {self._format_percentage(cm.get('recall', 0.0))} "
                f"| {self._format_percentage(cm.get('f1_score', 0.0))} "
                f"| {cm.get('avg_time_ms', 0.0):.2f} |"
            )
        md.append("")

        # ── Language Breakdown ───────────────────────────────────────
        md.append("---")
        md.append("## Language Breakdown")
        md.append("")
        md.append("| Language | Rules | Tests | Precision | Recall | F1 |")
        md.append("| -------- | ----: | ----: | --------: | -----: | -: |")
        for lm in language_metrics_list:
            md.append(
                f"| {lm.get('language', '')} "
                f"| {lm.get('rule_count', 0)} "
                f"| {lm.get('test_count', 0)} "
                f"| {self._format_percentage(lm.get('precision', 0.0))} "
                f"| {self._format_percentage(lm.get('recall', 0.0))} "
                f"| {self._format_percentage(lm.get('f1_score', 0.0))} |"
            )
        md.append("")

        # ── Rule Health Status ───────────────────────────────────────
        md.append("---")
        md.append("## Rule Health Status")
        md.append("")
        md.append("| Rule ID | Status | Precision | Recall | F1 |")
        md.append("| ------- | ------ | --------: | -----: | -: |")
        for rm in rule_metrics_list:
            status = rm.get("status", "unknown")
            icon = _STATUS_ICONS_MARKDOWN.get(status, ":grey_question:")
            md.append(
                f"| {rm.get('rule_id', '')} "
                f"| {icon} {status} "
                f"| {self._format_percentage(rm.get('precision', 0.0))} "
                f"| {self._format_percentage(rm.get('recall', 0.0))} "
                f"| {self._format_percentage(rm.get('f1_score', 0.0))} |"
            )
        md.append("")

        # ── Rules Needing Attention ──────────────────────────────────
        attention_rules = [
            rm for rm in rule_metrics_list
            if rm.get("status") in ("needs_tuning", "noisy", "under_sensitive")
        ]
        if attention_rules:
            md.append("---")
            md.append("## Rules Needing Attention")
            md.append("")
            md.append("| Rule ID | Status | Precision | Recall | F1 | Issue |")
            md.append("| ------- | ------ | --------: | -----: | -: | ----- |")
            for rm in attention_rules:
                status = rm.get("status", "unknown")
                icon = _STATUS_ICONS_MARKDOWN.get(status, ":grey_question:")
                issue = self._derive_issue(rm)
                md.append(
                    f"| {rm.get('rule_id', '')} "
                    f"| {icon} {status} "
                    f"| {self._format_percentage(rm.get('precision', 0.0))} "
                    f"| {self._format_percentage(rm.get('recall', 0.0))} "
                    f"| {self._format_percentage(rm.get('f1_score', 0.0))} "
                    f"| {issue} |"
                )
            md.append("")

        # ── Performance Metrics ──────────────────────────────────────
        md.append("---")
        md.append("## Performance Metrics")
        md.append("")
        md.append("| Metric | Value |")
        md.append("| ------ | ----- |")
        md.append(
            f"| Regex Compile Time | {engine_metrics.get('regex_compile_time_ms', 0.0):.2f} ms |"
        )
        md.append(
            f"| Avg Match Time | {engine_metrics.get('avg_match_time_ms', 0.0):.3f} ms |"
        )
        md.append(
            f"| Memory Estimate | {engine_metrics.get('memory_estimate_mb', 0.0):.2f} MB |"
        )
        md.append("")

        # ── Confidence Distribution ──────────────────────────────────
        md.append("---")
        md.append("## Confidence Distribution")
        md.append("")
        buckets = {"high (>= 0.8)": 0, "medium (0.5 - 0.8)": 0, "low (< 0.5)": 0}
        for rm in rule_metrics_list:
            conf = rm.get("confidence", 0.0)
            if conf >= 0.8:
                buckets["high (>= 0.8)"] += 1
            elif conf >= 0.5:
                buckets["medium (0.5 - 0.8)"] += 1
            else:
                buckets["low (< 0.5)"] += 1
        md.append("| Confidence Band | Rule Count |")
        md.append("| --------------- | ---------: |")
        for band, count in buckets.items():
            md.append(f"| {band} | {count} |")
        md.append("")

        # ── Recommendations ──────────────────────────────────────────
        md.append("---")
        md.append("## Recommendations")
        md.append("")
        recommendations = self._build_recommendations(engine_metrics, rule_metrics_list)
        if recommendations:
            for rec in recommendations:
                md.append(f"- {rec}")
        else:
            md.append("- All rules are performing within acceptable thresholds.")
        md.append("")

        content = "\n".join(md)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(content)

        return str(out.resolve())

    # ── Failure Report ───────────────────────────────────────────────

    def generate_failure_report(
        self,
        failed_rules: List[Dict[str, Any]],
        output_path: Optional[str] = None,
    ) -> str:
        """Generate a detailed failure analysis for rules that missed thresholds.

        Each entry in *failed_rules* is expected to have:
            rule_id, status, precision, recall, f1_score,
            false_positives, false_negatives, affected_test_files (list[str])

        Both a JSON file and console output are produced.

        Returns:
            The absolute path of the written JSON failure report.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")

        if output_path is None:
            reports_dir = Path(__file__).resolve().parent.parent / "reports"
            output_path = str(reports_dir / f"failures_{timestamp_str}.json")

        failure_entries: List[Dict[str, Any]] = []
        console_lines: List[str] = []

        console_lines.append("")
        console_lines.append(self._ansi_color("=" * 60, "red"))
        console_lines.append(self._ansi_color("  Failure Analysis Report", "bold"))
        console_lines.append(self._ansi_color("=" * 60, "red"))
        console_lines.append("")

        for rule in failed_rules:
            rule_id = rule.get("rule_id", "UNKNOWN")
            status = rule.get("status", "unknown")
            failure_type = self._classify_failure_type(rule)
            suggested = self._suggest_action(rule)
            affected_files = rule.get("affected_test_files", [])

            entry = {
                "rule_id": rule_id,
                "failure_type": failure_type,
                "status": status,
                "precision": rule.get("precision", 0.0),
                "recall": rule.get("recall", 0.0),
                "f1_score": rule.get("f1_score", 0.0),
                "false_positives": rule.get("false_positives", 0),
                "false_negatives": rule.get("false_negatives", 0),
                "affected_test_files": affected_files,
                "suggested_action": suggested,
            }
            failure_entries.append(entry)

            color = _STATUS_COLORS.get(status, "dim")
            console_lines.append(self._ansi_color(f"  Rule: {rule_id}", "bold"))
            console_lines.append(f"    Failure Type:  {self._ansi_color(failure_type, color)}")
            console_lines.append(f"    Status:        {self._ansi_color(status, color)}")
            console_lines.append(f"    Precision:     {self._format_percentage(rule.get('precision', 0.0))}")
            console_lines.append(f"    Recall:        {self._format_percentage(rule.get('recall', 0.0))}")
            console_lines.append(f"    F1 Score:      {self._format_percentage(rule.get('f1_score', 0.0))}")
            if affected_files:
                console_lines.append(f"    Affected Files ({len(affected_files)}):")
                for af in affected_files[:10]:
                    console_lines.append(f"      - {af}")
                if len(affected_files) > 10:
                    console_lines.append(f"      ... and {len(affected_files) - 10} more")
            console_lines.append(f"    Suggested:     {suggested}")
            console_lines.append("")

        console_lines.append(self._ansi_color("=" * 60, "red"))
        console_lines.append("")

        report_text = "\n".join(console_lines)
        print(report_text)

        report_data = {
            "metadata": {
                "timestamp": now.isoformat(),
                "total_failures": len(failure_entries),
            },
            "failures": failure_entries,
        }

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, default=str)

        return str(out.resolve())

    # ── Helper Methods ───────────────────────────────────────────────

    def _format_table(
        self,
        headers: List[str],
        rows: List[List[str]],
        col_widths: List[int],
    ) -> str:
        """Render a table with box-drawing border characters.

        Args:
            headers: Column header labels.
            rows: List of row data (each row is a list of cell strings).
            col_widths: Desired display width for each column.

        Returns:
            A multi-line string containing the formatted table.
        """
        # Ensure col_widths matches header count
        while len(col_widths) < len(headers):
            col_widths.append(12)

        def _visible_len(text: str) -> int:
            """Return visible length excluding ANSI escape sequences."""
            import re as _re
            return len(_re.sub(r"\033\[[0-9;]*m", "", text))

        def _pad(text: str, width: int) -> str:
            visible = _visible_len(text)
            padding = max(0, width - visible)
            return text + " " * padding

        lines: List[str] = []

        # Top border: ┌─────┬─────┐
        top = "  \u250c" + "\u252c".join("\u2500" * (w + 2) for w in col_widths) + "\u2510"
        lines.append(top)

        # Header row
        header_cells = [
            " " + _pad(h, w) + " " for h, w in zip(headers, col_widths)
        ]
        lines.append("  \u2502" + "\u2502".join(header_cells) + "\u2502")

        # Header separator: ├─────┼─────┤
        sep = "  \u251c" + "\u253c".join("\u2500" * (w + 2) for w in col_widths) + "\u2524"
        lines.append(sep)

        # Data rows
        for row in rows:
            # Pad row if it has fewer cells than headers
            while len(row) < len(headers):
                row.append("")
            cells = [
                " " + _pad(cell, w) + " " for cell, w in zip(row, col_widths)
            ]
            lines.append("  \u2502" + "\u2502".join(cells) + "\u2502")

        # Bottom border: └─────┴─────┘
        bottom = "  \u2514" + "\u2534".join("\u2500" * (w + 2) for w in col_widths) + "\u2518"
        lines.append(bottom)

        return "\n".join(lines)

    def _format_percentage(self, value: float) -> str:
        """Format a float (0.0 - 1.0) as a percentage string."""
        if value is None:
            return "  N/A"
        return f"{value * 100:6.2f}%"

    def _ansi_color(self, text: str, color: str) -> str:
        """Wrap *text* in ANSI color codes if color output is enabled."""
        if not self._use_color:
            return text
        code = _COLORS.get(color, "")
        reset = _COLORS["reset"]
        if not code:
            return text
        return f"{code}{text}{reset}"

    def _truncate(self, text: str, max_len: int) -> str:
        """Truncate *text* to *max_len* characters, adding ellipsis if trimmed."""
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."

    def _status_icon(self, status: str) -> str:
        """Return a short console icon for the given health status."""
        return _STATUS_ICONS_CONSOLE.get(status, "--")

    def _derive_issue(self, rule_metrics: Dict[str, Any]) -> str:
        """Derive a human-readable issue description from rule metrics."""
        status = rule_metrics.get("status", "unknown")
        precision = rule_metrics.get("precision", 0.0)
        recall = rule_metrics.get("recall", 0.0)
        fp = rule_metrics.get("false_positives", 0)
        fn = rule_metrics.get("false_negatives", 0)

        if status == "noisy":
            return f"High false-positive rate ({fp} FP, precision {precision * 100:.0f}%)"
        if status == "under_sensitive":
            return f"Missed detections ({fn} FN, recall {recall * 100:.0f}%)"
        if status == "needs_tuning":
            issues: List[str] = []
            if precision < 0.8:
                issues.append(f"precision {precision * 100:.0f}%")
            if recall < 0.8:
                issues.append(f"recall {recall * 100:.0f}%")
            return "Borderline: " + ", ".join(issues) if issues else "Needs review"
        return ""

    def _classify_failure_type(self, rule: Dict[str, Any]) -> str:
        """Classify the failure type for a rule based on its metrics."""
        status = rule.get("status", "unknown")
        precision = rule.get("precision", 0.0)
        recall = rule.get("recall", 0.0)

        if status == "noisy" or (precision < 0.5 and recall >= 0.7):
            return "Over-sensitive"
        if status == "under_sensitive" or (recall < 0.5 and precision >= 0.7):
            return "Under-sensitive"
        if precision < 0.5 and recall < 0.5:
            return "Unstable"
        return "Noisy"

    def _suggest_action(self, rule: Dict[str, Any]) -> str:
        """Suggest a corrective action based on the rule failure profile."""
        failure_type = self._classify_failure_type(rule)
        rule_id = rule.get("rule_id", "UNKNOWN")

        suggestions = {
            "Over-sensitive": (
                f"Tighten regex patterns for {rule_id} to reduce false positives. "
                "Consider adding negative lookaheads or more specific anchors."
            ),
            "Under-sensitive": (
                f"Broaden patterns for {rule_id} to capture missed variants. "
                "Review false-negative test files for uncovered syntax patterns."
            ),
            "Unstable": (
                f"Rule {rule_id} performs poorly on both precision and recall. "
                "Consider rewriting patterns from scratch or splitting into sub-rules."
            ),
            "Noisy": (
                f"Review {rule_id} patterns for overly broad matches. "
                "Add context-aware constraints or increase confidence threshold."
            ),
        }
        return suggestions.get(failure_type, f"Manually review rule {rule_id}.")

    def _build_recommendations(
        self,
        engine_metrics: Dict[str, Any],
        rule_metrics_list: List[Dict[str, Any]],
    ) -> List[str]:
        """Build a list of actionable recommendations based on metrics."""
        recs: List[str] = []

        global_f1 = engine_metrics.get("f1_score", 0.0)
        if global_f1 < 0.7:
            recs.append(
                f"Global F1 score is **{global_f1 * 100:.1f}%** (below 70%). "
                "Prioritize tuning rules with the lowest individual F1 scores."
            )

        noisy_rules = [rm for rm in rule_metrics_list if rm.get("status") == "noisy"]
        if noisy_rules:
            ids = ", ".join(rm.get("rule_id", "?") for rm in noisy_rules[:5])
            recs.append(
                f"**{len(noisy_rules)}** rule(s) classified as noisy: {ids}. "
                "Review patterns for overly broad matches."
            )

        under_rules = [rm for rm in rule_metrics_list if rm.get("status") == "under_sensitive"]
        if under_rules:
            ids = ", ".join(rm.get("rule_id", "?") for rm in under_rules[:5])
            recs.append(
                f"**{len(under_rules)}** rule(s) classified as under-sensitive: {ids}. "
                "Add additional patterns to cover missed attack variants."
            )

        slow_rules = [
            rm for rm in rule_metrics_list if rm.get("avg_match_time_ms", 0.0) > 50.0
        ]
        if slow_rules:
            ids = ", ".join(rm.get("rule_id", "?") for rm in slow_rules[:5])
            recs.append(
                f"**{len(slow_rules)}** rule(s) exceed 50 ms average match time: {ids}. "
                "Consider simplifying regex patterns or pre-filtering input."
            )

        avg_time = engine_metrics.get("avg_match_time_ms", 0.0)
        if avg_time > 10.0:
            recs.append(
                f"Average match time is **{avg_time:.1f} ms** (above 10 ms). "
                "Profile the slowest patterns and consider compiled regex caching."
            )

        return recs
