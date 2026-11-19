"""Regression testing module for the rule validation framework.

Manages performance baselines, detects metric regressions between runs,
and provides threshold-based alerting for CI/CD integration.
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ThresholdConfig:
    """Alerting thresholds for regression detection.

    Attributes:
        min_precision: Absolute minimum precision before a regression is flagged.
        min_recall: Absolute minimum recall before a regression is flagged.
        min_f1: Absolute minimum F1 before a regression is flagged.
        max_precision_drop: Maximum allowed drop in precision vs. baseline.
        max_recall_drop: Maximum allowed drop in recall vs. baseline.
        max_f1_drop: Maximum allowed drop in F1 vs. baseline.
        max_new_false_positives: Maximum number of new FPs compared to baseline.
        max_new_false_negatives: Maximum number of new FNs compared to baseline.
        max_avg_time_increase_pct: Maximum percentage increase in average
            detection time before a performance regression is flagged.
    """

    min_precision: float = 0.80
    min_recall: float = 0.80
    min_f1: float = 0.75
    max_precision_drop: float = 0.05
    max_recall_drop: float = 0.05
    max_f1_drop: float = 0.05
    max_new_false_positives: int = 3
    max_new_false_negatives: int = 2
    max_avg_time_increase_pct: float = 50.0


@dataclass
class RegressionResult:
    """Result of a regression check for a single rule or the global engine.

    Attributes:
        rule_id: Rule identifier, or ``"__global__"`` for engine-level checks.
        passed: Whether the regression check passed all thresholds.
        violations: Human-readable list of threshold violations.
        baseline_metrics: Snapshot of the baseline metrics used for comparison.
        current_metrics: Snapshot of the current run metrics.
    """

    rule_id: str
    passed: bool
    violations: List[str] = field(default_factory=list)
    baseline_metrics: Dict[str, Any] = field(default_factory=dict)
    current_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegressionReport:
    """Aggregated regression report across all rules.

    Attributes:
        timestamp: ISO-8601 timestamp of the regression check.
        overall_passed: Whether **all** rule-level checks passed.
        results: Per-rule (and global) regression results.
        summary: Quick counts of passed/failed checks.
    """

    timestamp: str = ""
    overall_passed: bool = True
    results: List[RegressionResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


class BaselineManager:
    """Manages baseline metric snapshots for regression detection.

    Baselines are stored as JSON files in the baselines directory.  Each
    baseline contains engine-level and per-rule metrics from a known-good
    validation run.

    Typical workflow::

        mgr = BaselineManager(baselines_dir)
        mgr.save_baseline(current_metrics, tag="v2.0.0")
        report = mgr.check_regression(current_metrics, thresholds)
    """

    LATEST_SYMLINK = "latest.json"

    def __init__(self, baselines_dir: Path) -> None:
        self._dir = baselines_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ── Baseline persistence ─────────────────────────────────────────

    def save_baseline(
        self,
        metrics: Dict[str, Any],
        tag: Optional[str] = None,
    ) -> Path:
        """Persist a metrics snapshot as a new baseline.

        Args:
            metrics: Dictionary with ``engine`` and ``rules`` keys containing
                the current validation metrics.
            tag: Optional human-readable version tag embedded in the filename.

        Returns:
            Path to the written baseline JSON file.
        """
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y%m%d_%H%M%S")
        suffix = f"_{tag}" if tag else ""
        filename = f"baseline_{ts}{suffix}.json"
        filepath = self._dir / filename

        baseline_data = {
            "metadata": {
                "timestamp": now.isoformat(),
                "tag": tag or "",
            },
            "engine": metrics.get("engine", {}),
            "rules": metrics.get("rules", {}),
        }

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(baseline_data, fh, indent=2, default=str)

        # Update "latest" pointer.
        latest_path = self._dir / self.LATEST_SYMLINK
        with open(latest_path, "w", encoding="utf-8") as fh:
            json.dump(baseline_data, fh, indent=2, default=str)

        logger.info("Saved baseline to %s", filepath)
        return filepath

    def load_baseline(self, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Load a baseline from disk.

        Args:
            path: Explicit path to a baseline JSON file.  When ``None`` the
                latest baseline is loaded.

        Returns:
            Parsed baseline dictionary, or ``None`` if no baseline exists.
        """
        if path is None:
            path = self._dir / self.LATEST_SYMLINK

        if not path.is_file():
            logger.warning("No baseline found at %s", path)
            return None

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            logger.info("Loaded baseline from %s", path)
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load baseline %s: %s", path, exc)
            return None

    def list_baselines(self) -> List[Path]:
        """Return all baseline files sorted by modification time (newest first)."""
        files = sorted(
            self._dir.glob("baseline_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return files

    # ── Regression detection ─────────────────────────────────────────

    def check_regression(
        self,
        current_metrics: Dict[str, Any],
        thresholds: Optional[ThresholdConfig] = None,
        baseline_path: Optional[Path] = None,
    ) -> RegressionReport:
        """Compare current metrics against a baseline and check for regressions.

        Args:
            current_metrics: Current validation run metrics with ``engine``
                and ``rules`` keys.
            thresholds: Alerting thresholds.  Uses defaults when ``None``.
            baseline_path: Explicit baseline to compare against.

        Returns:
            A ``RegressionReport`` with per-rule results and an overall verdict.
        """
        if thresholds is None:
            thresholds = ThresholdConfig()

        report = RegressionReport(
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        baseline = self.load_baseline(baseline_path)
        if baseline is None:
            logger.info("No baseline available; skipping regression check.")
            report.summary = {"skipped": 1}
            return report

        # ── Engine-level check ───────────────────────────────────────
        engine_result = self._check_engine_regression(
            baseline.get("engine", {}),
            current_metrics.get("engine", {}),
            thresholds,
        )
        report.results.append(engine_result)

        # ── Per-rule checks ──────────────────────────────────────────
        baseline_rules: Dict[str, Dict] = baseline.get("rules", {})
        current_rules: Dict[str, Dict] = current_metrics.get("rules", {})

        for rule_id, current in current_rules.items():
            prev = baseline_rules.get(rule_id)
            if prev is None:
                # New rule — no regression possible.
                continue
            rule_result = self._check_rule_regression(
                rule_id, prev, current, thresholds
            )
            report.results.append(rule_result)

        # ── Summary ──────────────────────────────────────────────────
        passed_count = sum(1 for r in report.results if r.passed)
        failed_count = sum(1 for r in report.results if not r.passed)
        report.overall_passed = failed_count == 0
        report.summary = {
            "total_checks": len(report.results),
            "passed": passed_count,
            "failed": failed_count,
        }

        if not report.overall_passed:
            logger.warning(
                "Regression detected: %d/%d checks failed.",
                failed_count,
                len(report.results),
            )
        else:
            logger.info("All %d regression checks passed.", len(report.results))

        return report

    # ── Internal check helpers ───────────────────────────────────────

    def _check_engine_regression(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
        thresholds: ThresholdConfig,
    ) -> RegressionResult:
        """Compare engine-level metrics against baseline."""
        violations: List[str] = []

        for metric, min_val, max_drop in [
            ("precision", thresholds.min_precision, thresholds.max_precision_drop),
            ("recall", thresholds.min_recall, thresholds.max_recall_drop),
            ("f1_score", thresholds.min_f1, thresholds.max_f1_drop),
        ]:
            cur_val = current.get(metric, 0.0)
            base_val = baseline.get(metric, 0.0)

            if cur_val < min_val:
                violations.append(
                    f"Global {metric} ({cur_val:.4f}) below minimum ({min_val:.4f})"
                )
            if base_val > 0 and (base_val - cur_val) > max_drop:
                violations.append(
                    f"Global {metric} dropped by {base_val - cur_val:.4f} "
                    f"(max allowed: {max_drop:.4f})"
                )

        # Detection time regression
        cur_time = current.get("avg_detection_time_ms", 0.0)
        base_time = baseline.get("avg_detection_time_ms", 0.0)
        if base_time > 0:
            pct_change = ((cur_time - base_time) / base_time) * 100
            if pct_change > thresholds.max_avg_time_increase_pct:
                violations.append(
                    f"Avg detection time increased by {pct_change:.1f}% "
                    f"(max allowed: {thresholds.max_avg_time_increase_pct:.1f}%)"
                )

        return RegressionResult(
            rule_id="__global__",
            passed=len(violations) == 0,
            violations=violations,
            baseline_metrics=baseline,
            current_metrics=current,
        )

    def _check_rule_regression(
        self,
        rule_id: str,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
        thresholds: ThresholdConfig,
    ) -> RegressionResult:
        """Compare per-rule metrics against baseline."""
        violations: List[str] = []

        for metric, max_drop in [
            ("precision", thresholds.max_precision_drop),
            ("recall", thresholds.max_recall_drop),
            ("f1_score", thresholds.max_f1_drop),
        ]:
            cur_val = current.get(metric, 0.0)
            base_val = baseline.get(metric, 0.0)
            if base_val > 0 and (base_val - cur_val) > max_drop:
                violations.append(
                    f"{metric} dropped from {base_val:.4f} to {cur_val:.4f} "
                    f"(delta: {base_val - cur_val:.4f}, max: {max_drop:.4f})"
                )

        # New false positives
        cur_fp = current.get("false_positives", 0)
        base_fp = baseline.get("false_positives", 0)
        new_fp = cur_fp - base_fp
        if new_fp > thresholds.max_new_false_positives:
            violations.append(
                f"{new_fp} new false positives "
                f"(max allowed: {thresholds.max_new_false_positives})"
            )

        # New false negatives
        cur_fn = current.get("false_negatives", 0)
        base_fn = baseline.get("false_negatives", 0)
        new_fn = cur_fn - base_fn
        if new_fn > thresholds.max_new_false_negatives:
            violations.append(
                f"{new_fn} new false negatives "
                f"(max allowed: {thresholds.max_new_false_negatives})"
            )

        return RegressionResult(
            rule_id=rule_id,
            passed=len(violations) == 0,
            violations=violations,
            baseline_metrics=baseline,
            current_metrics=current,
        )

    # ── Report serialisation ─────────────────────────────────────────

    def save_regression_report(
        self,
        report: RegressionReport,
        output_path: Optional[Path] = None,
    ) -> Path:
        """Write a regression report to JSON.

        Args:
            report: The completed regression report.
            output_path: Destination path.  Defaults to
                ``baselines/regression_<timestamp>.json``.

        Returns:
            Path to the written file.
        """
        if output_path is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = self._dir / f"regression_{ts}.json"

        data = {
            "timestamp": report.timestamp,
            "overall_passed": report.overall_passed,
            "summary": report.summary,
            "results": [
                {
                    "rule_id": r.rule_id,
                    "passed": r.passed,
                    "violations": r.violations,
                }
                for r in report.results
            ],
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        logger.info("Saved regression report to %s", output_path)
        return output_path
