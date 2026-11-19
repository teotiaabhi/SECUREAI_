"""
Metrics computation module for the rule validation framework.

Provides comprehensive performance and accuracy metrics for security detection
rules, including per-rule precision/recall/F1, category-level aggregations,
language-level summaries, and full engine-wide statistics. Supports confidence
distribution analysis, detection-time tracking, and memory footprint estimation.
"""

from __future__ import annotations

import logging
import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------
FP_RATE_NOISY_THRESHOLD = 0.15
FN_RATE_UNDER_SENSITIVE_THRESHOLD = 0.10
CONFIDENCE_STDDEV_UNSTABLE_THRESHOLD = 0.15
PRECISION_TUNING_THRESHOLD = 0.90
RECALL_TUNING_THRESHOLD = 0.90
F1_OVER_SENSITIVE_THRESHOLD = 0.60
AVG_PATTERN_SIZE_BYTES = 512  # rough estimate per compiled regex pattern


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Return *numerator / denominator*, falling back to *default* on zero division."""
    if denominator == 0:
        return default
    return numerator / denominator


def _safe_f1(precision: float, recall: float) -> float:
    """Compute F1 from precision and recall with zero-division guard."""
    denom = precision + recall
    if denom == 0:
        return 0.0
    return 2.0 * precision * recall / denom


def _stddev(values: Sequence[float]) -> float:
    """Population standard deviation, returning 0.0 for fewer than 2 values."""
    if len(values) < 2:
        return 0.0
    try:
        return statistics.stdev(values)
    except statistics.StatisticsError:
        return 0.0


def _mean(values: Sequence[float]) -> float:
    """Arithmetic mean, returning 0.0 for an empty sequence."""
    if not values:
        return 0.0
    return statistics.mean(values)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RuleMetrics:
    """Per-rule accuracy, timing, and confidence metrics."""

    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_detection_time_ms: float = 0.0
    min_detection_time_ms: float = 0.0
    max_detection_time_ms: float = 0.0
    confidence_scores: List[float] = field(default_factory=list)
    confidence_mean: float = 0.0
    confidence_stddev: float = 0.0
    match_density: float = 0.0
    status: str = "stable"


@dataclass
class CategoryMetrics:
    """Aggregate metrics for a rule category (e.g. injection, crypto)."""

    category: str
    rule_count: int = 0
    total_tests: int = 0
    aggregate_precision: float = 0.0
    aggregate_recall: float = 0.0
    aggregate_f1: float = 0.0
    avg_detection_time_ms: float = 0.0
    rules_needing_tuning: List[str] = field(default_factory=list)
    coverage_percentage: float = 0.0


@dataclass
class LanguageMetrics:
    """Aggregate metrics scoped to a single programming language."""

    language: str
    rule_count: int = 0
    total_tests: int = 0
    aggregate_precision: float = 0.0
    aggregate_recall: float = 0.0
    aggregate_f1: float = 0.0


@dataclass
class EngineMetrics:
    """Global engine-wide statistics across every rule and test."""

    total_rules: int = 0
    total_tests: int = 0
    total_true_positives: int = 0
    total_false_positives: int = 0
    total_true_negatives: int = 0
    total_false_negatives: int = 0
    global_precision: float = 0.0
    global_recall: float = 0.0
    global_f1: float = 0.0
    avg_detection_time_ms: float = 0.0
    total_execution_time_s: float = 0.0
    rules_by_status: Dict[str, List[str]] = field(default_factory=dict)
    regex_compilation_time_ms: float = 0.0
    estimated_memory_mb: float = 0.0


# ---------------------------------------------------------------------------
# Core computation functions
# ---------------------------------------------------------------------------

def compute_rule_metrics(rule_id: str, results: Dict[str, Any]) -> RuleMetrics:
    """Compute comprehensive metrics for a single rule from raw test results.

    Parameters
    ----------
    rule_id:
        Unique identifier of the rule being evaluated.
    results:
        Dictionary produced by the test runner.  Expected keys:

        * ``true_positives``  (int)
        * ``false_positives`` (int)
        * ``true_negatives``  (int)
        * ``false_negatives`` (int)
        * ``detection_times_ms`` (list[float]) -- per-test-case durations
        * ``confidence_scores``  (list[float]) -- per-match confidence values
        * ``total_bytes_scanned`` (int)        -- bytes of source code scanned
        * ``total_matches``       (int)        -- raw match count

    Returns
    -------
    RuleMetrics
        Fully populated metrics object including derived status.
    """
    tp: int = results.get("true_positives", 0)
    fp: int = results.get("false_positives", 0)
    tn: int = results.get("true_negatives", 0)
    fn: int = results.get("false_negatives", 0)

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_f1(precision, recall)

    # Detection timing ---------------------------------------------------
    detection_times: List[float] = results.get("detection_times_ms", [])
    avg_time = _mean(detection_times)
    min_time = min(detection_times) if detection_times else 0.0
    max_time = max(detection_times) if detection_times else 0.0

    # Confidence ---------------------------------------------------------
    confidence_scores: List[float] = results.get("confidence_scores", [])
    conf_mean = _mean(confidence_scores)
    conf_std = _stddev(confidence_scores)

    # Match density (matches per KB) ------------------------------------
    total_bytes: int = results.get("total_bytes_scanned", 0)
    total_matches: int = results.get("total_matches", 0)
    kb_scanned = total_bytes / 1024.0 if total_bytes > 0 else 0.0
    match_density = _safe_div(total_matches, kb_scanned)

    # Status classification ---------------------------------------------
    status = classify_rule_health_from_values(
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=precision, recall=recall,
        confidence_stddev=conf_std,
    )

    metrics = RuleMetrics(
        rule_id=rule_id,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1_score=round(f1, 6),
        avg_detection_time_ms=round(avg_time, 3),
        min_detection_time_ms=round(min_time, 3),
        max_detection_time_ms=round(max_time, 3),
        confidence_scores=confidence_scores,
        confidence_mean=round(conf_mean, 6),
        confidence_stddev=round(conf_std, 6),
        match_density=round(match_density, 4),
        status=status,
    )
    logger.debug("Computed metrics for rule %s: P=%.4f R=%.4f F1=%.4f status=%s",
                 rule_id, precision, recall, f1, status)
    return metrics


def compute_category_metrics(
    category: str,
    rule_metrics_list: List[RuleMetrics],
) -> CategoryMetrics:
    """Aggregate rule-level metrics for a category using micro-averaging.

    Micro-averaging sums the individual TP/FP/FN counts across all rules
    before computing precision, recall, and F1 so that rules exercised by
    more test cases naturally receive proportionally more weight.

    Parameters
    ----------
    category:
        Human-readable category name (e.g. ``"injection"``).
    rule_metrics_list:
        All RuleMetrics objects belonging to this category.

    Returns
    -------
    CategoryMetrics
    """
    if not rule_metrics_list:
        logger.warning("No rule metrics provided for category '%s'", category)
        return CategoryMetrics(category=category)

    total_tp = sum(r.true_positives for r in rule_metrics_list)
    total_fp = sum(r.false_positives for r in rule_metrics_list)
    total_fn = sum(r.false_negatives for r in rule_metrics_list)

    precision = _safe_div(total_tp, total_tp + total_fp)
    recall = _safe_div(total_tp, total_tp + total_fn)
    f1 = _safe_f1(precision, recall)

    total_tests = sum(
        r.true_positives + r.false_positives + r.true_negatives + r.false_negatives
        for r in rule_metrics_list
    )

    detection_times = [r.avg_detection_time_ms for r in rule_metrics_list if r.avg_detection_time_ms > 0]
    avg_det = _mean(detection_times)

    rules_needing_tuning = [
        r.rule_id for r in rule_metrics_list
        if r.status not in ("stable",)
    ]

    rules_with_tests = sum(
        1 for r in rule_metrics_list
        if (r.true_positives + r.false_positives + r.true_negatives + r.false_negatives) > 0
    )
    coverage = _safe_div(rules_with_tests, len(rule_metrics_list)) * 100.0

    cat_metrics = CategoryMetrics(
        category=category,
        rule_count=len(rule_metrics_list),
        total_tests=total_tests,
        aggregate_precision=round(precision, 6),
        aggregate_recall=round(recall, 6),
        aggregate_f1=round(f1, 6),
        avg_detection_time_ms=round(avg_det, 3),
        rules_needing_tuning=rules_needing_tuning,
        coverage_percentage=round(coverage, 2),
    )
    logger.debug("Category '%s': %d rules, P=%.4f R=%.4f F1=%.4f coverage=%.1f%%",
                 category, len(rule_metrics_list), precision, recall, f1, coverage)
    return cat_metrics


def compute_language_metrics(
    language: str,
    rule_metrics_list: List[RuleMetrics],
) -> LanguageMetrics:
    """Aggregate rule-level metrics for a programming language (micro-averaged).

    Parameters
    ----------
    language:
        Language identifier (e.g. ``"python"``, ``"javascript"``).
    rule_metrics_list:
        All RuleMetrics for rules targeting *language*.

    Returns
    -------
    LanguageMetrics
    """
    if not rule_metrics_list:
        logger.warning("No rule metrics provided for language '%s'", language)
        return LanguageMetrics(language=language)

    total_tp = sum(r.true_positives for r in rule_metrics_list)
    total_fp = sum(r.false_positives for r in rule_metrics_list)
    total_fn = sum(r.false_negatives for r in rule_metrics_list)

    precision = _safe_div(total_tp, total_tp + total_fp)
    recall = _safe_div(total_tp, total_tp + total_fn)
    f1 = _safe_f1(precision, recall)

    total_tests = sum(
        r.true_positives + r.false_positives + r.true_negatives + r.false_negatives
        for r in rule_metrics_list
    )

    lang_metrics = LanguageMetrics(
        language=language,
        rule_count=len(rule_metrics_list),
        total_tests=total_tests,
        aggregate_precision=round(precision, 6),
        aggregate_recall=round(recall, 6),
        aggregate_f1=round(f1, 6),
    )
    logger.debug("Language '%s': %d rules, P=%.4f R=%.4f F1=%.4f",
                 language, len(rule_metrics_list), precision, recall, f1)
    return lang_metrics


def compute_engine_metrics(
    all_rule_metrics: List[RuleMetrics],
    compilation_times: Optional[Dict[str, float]] = None,
    total_time: float = 0.0,
) -> EngineMetrics:
    """Produce global engine-wide metrics from every evaluated rule.

    Parameters
    ----------
    all_rule_metrics:
        Complete list of per-rule metrics objects.
    compilation_times:
        Mapping of ``rule_id -> regex compilation time in ms``.  Used to
        compute the aggregate regex compilation overhead.
    total_time:
        Wall-clock execution time for the entire validation run, in seconds.

    Returns
    -------
    EngineMetrics
    """
    if compilation_times is None:
        compilation_times = {}

    total_tp = sum(r.true_positives for r in all_rule_metrics)
    total_fp = sum(r.false_positives for r in all_rule_metrics)
    total_tn = sum(r.true_negatives for r in all_rule_metrics)
    total_fn = sum(r.false_negatives for r in all_rule_metrics)

    precision = _safe_div(total_tp, total_tp + total_fp)
    recall = _safe_div(total_tp, total_tp + total_fn)
    f1 = _safe_f1(precision, recall)

    total_tests = sum(
        r.true_positives + r.false_positives + r.true_negatives + r.false_negatives
        for r in all_rule_metrics
    )

    detection_times = [r.avg_detection_time_ms for r in all_rule_metrics if r.avg_detection_time_ms > 0]
    avg_det = _mean(detection_times)

    # Regex compilation aggregate ----------------------------------------
    total_compilation = sum(compilation_times.values()) if compilation_times else 0.0

    # Memory estimation --------------------------------------------------
    pattern_count = len(all_rule_metrics)
    estimated_memory_mb = (pattern_count * AVG_PATTERN_SIZE_BYTES) / (1024.0 * 1024.0)

    # Rules grouped by status -------------------------------------------
    rules_by_status: Dict[str, List[str]] = {}
    for rm in all_rule_metrics:
        rules_by_status.setdefault(rm.status, []).append(rm.rule_id)

    engine = EngineMetrics(
        total_rules=len(all_rule_metrics),
        total_tests=total_tests,
        total_true_positives=total_tp,
        total_false_positives=total_fp,
        total_true_negatives=total_tn,
        total_false_negatives=total_fn,
        global_precision=round(precision, 6),
        global_recall=round(recall, 6),
        global_f1=round(f1, 6),
        avg_detection_time_ms=round(avg_det, 3),
        total_execution_time_s=round(total_time, 3),
        rules_by_status=rules_by_status,
        regex_compilation_time_ms=round(total_compilation, 3),
        estimated_memory_mb=round(estimated_memory_mb, 4),
    )
    logger.info(
        "Engine metrics: %d rules, %d tests, P=%.4f R=%.4f F1=%.4f, "
        "compile=%.1fms, mem~%.2fMB, wall=%.2fs",
        engine.total_rules, engine.total_tests, precision, recall, f1,
        total_compilation, estimated_memory_mb, total_time,
    )
    return engine


# ---------------------------------------------------------------------------
# Rule health classification
# ---------------------------------------------------------------------------

def classify_rule_health(rule_metrics: RuleMetrics) -> str:
    """Classify the operational health of a rule from its computed metrics.

    The classification hierarchy (evaluated top-to-bottom, first match wins):

    1. **noisy** -- false-positive rate exceeds ``FP_RATE_NOISY_THRESHOLD``.
    2. **under_sensitive** -- false-negative rate exceeds
       ``FN_RATE_UNDER_SENSITIVE_THRESHOLD``.
    3. **over_sensitive** -- F1 score is below ``F1_OVER_SENSITIVE_THRESHOLD``
       while precision remains high, suggesting the rule fires too
       aggressively.
    4. **unstable** -- confidence standard deviation exceeds
       ``CONFIDENCE_STDDEV_UNSTABLE_THRESHOLD``.
    5. **needs_tuning** -- precision or recall falls below the respective
       tuning threshold but the rule does not meet any of the above criteria.
    6. **stable** -- the default healthy state.

    Parameters
    ----------
    rule_metrics:
        A fully populated ``RuleMetrics`` instance.

    Returns
    -------
    str
        One of ``"stable"``, ``"noisy"``, ``"under_sensitive"``,
        ``"over_sensitive"``, ``"unstable"``, ``"needs_tuning"``.
    """
    return classify_rule_health_from_values(
        tp=rule_metrics.true_positives,
        fp=rule_metrics.false_positives,
        tn=rule_metrics.true_negatives,
        fn=rule_metrics.false_negatives,
        precision=rule_metrics.precision,
        recall=rule_metrics.recall,
        confidence_stddev=rule_metrics.confidence_stddev,
    )


def classify_rule_health_from_values(
    *,
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    precision: float,
    recall: float,
    confidence_stddev: float,
) -> str:
    """Low-level health classifier operating on raw values.

    This exists so that ``compute_rule_metrics`` can classify health before
    the ``RuleMetrics`` dataclass is fully instantiated, avoiding a circular
    dependency.
    """
    total_positives = tp + fp
    total_actual_positives = tp + fn

    fp_rate = _safe_div(fp, total_positives)
    fn_rate = _safe_div(fn, total_actual_positives)
    f1 = _safe_f1(precision, recall)

    # 1. Noisy
    if fp_rate > FP_RATE_NOISY_THRESHOLD:
        return "noisy"

    # 2. Under-sensitive
    if fn_rate > FN_RATE_UNDER_SENSITIVE_THRESHOLD:
        return "under_sensitive"

    # 3. Over-sensitive (high precision but poor overall F1)
    if f1 < F1_OVER_SENSITIVE_THRESHOLD and precision > PRECISION_TUNING_THRESHOLD:
        return "over_sensitive"

    # 4. Unstable confidence
    if confidence_stddev > CONFIDENCE_STDDEV_UNSTABLE_THRESHOLD:
        return "unstable"

    # 5. Needs tuning
    if precision < PRECISION_TUNING_THRESHOLD or recall < RECALL_TUNING_THRESHOLD:
        return "needs_tuning"

    # 6. Default
    return "stable"


# ---------------------------------------------------------------------------
# Confidence distribution
# ---------------------------------------------------------------------------

CONFIDENCE_BUCKETS = [
    ("0.00-0.50", 0.0, 0.50),
    ("0.50-0.70", 0.50, 0.70),
    ("0.70-0.85", 0.70, 0.85),
    ("0.85-0.95", 0.85, 0.95),
    ("0.95-1.00", 0.95, 1.01),  # upper bound slightly above 1.0 for inclusive check
]


def compute_confidence_distribution(scores: Sequence[float]) -> Dict[str, int]:
    """Bin confidence scores into predefined histogram buckets.

    Buckets:
        * ``0.00-0.50``
        * ``0.50-0.70``
        * ``0.70-0.85``
        * ``0.85-0.95``
        * ``0.95-1.00``

    Parameters
    ----------
    scores:
        Iterable of confidence values, each expected in ``[0.0, 1.0]``.

    Returns
    -------
    dict
        Mapping of bucket label to count of scores falling within that range.
        Bounds are ``[low, high)`` except the final bucket which is ``[0.95, 1.0]``.
    """
    distribution: Dict[str, int] = {label: 0 for label, _, _ in CONFIDENCE_BUCKETS}

    for score in scores:
        clamped = max(0.0, min(score, 1.0))
        placed = False
        for label, low, high in CONFIDENCE_BUCKETS:
            if low <= clamped < high:
                distribution[label] += 1
                placed = True
                break
        if not placed:
            # Edge case: score == 1.0 exactly lands in last bucket
            distribution[CONFIDENCE_BUCKETS[-1][0]] += 1

    logger.debug("Confidence distribution from %d scores: %s", len(scores), distribution)
    return distribution


# ---------------------------------------------------------------------------
# Performance tracking helpers
# ---------------------------------------------------------------------------

def track_compilation_overhead(
    compilation_times: Dict[str, float],
) -> Dict[str, Any]:
    """Summarise per-rule regex compilation times.

    Parameters
    ----------
    compilation_times:
        Mapping of ``rule_id -> compilation time in milliseconds``.

    Returns
    -------
    dict
        Summary containing ``total_ms``, ``mean_ms``, ``median_ms``,
        ``max_ms``, ``min_ms``, ``slowest_rule``, and ``count``.
    """
    if not compilation_times:
        return {
            "total_ms": 0.0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "max_ms": 0.0,
            "min_ms": 0.0,
            "slowest_rule": None,
            "count": 0,
        }

    times = list(compilation_times.values())
    slowest_rule = max(compilation_times, key=compilation_times.get)  # type: ignore[arg-type]

    return {
        "total_ms": round(sum(times), 3),
        "mean_ms": round(_mean(times), 3),
        "median_ms": round(statistics.median(times), 3),
        "max_ms": round(max(times), 3),
        "min_ms": round(min(times), 3),
        "slowest_rule": slowest_rule,
        "count": len(times),
    }


def estimate_memory_footprint(
    pattern_count: int,
    avg_pattern_size: int = AVG_PATTERN_SIZE_BYTES,
) -> float:
    """Estimate memory consumed by compiled regex patterns in megabytes.

    This is a heuristic -- compiled DFA/NFA representations are typically
    several times larger than the source pattern string.  A multiplier of
    ~10x is applied to approximate the in-memory representation.

    Parameters
    ----------
    pattern_count:
        Number of compiled regex patterns held in memory.
    avg_pattern_size:
        Average source-pattern length in bytes.

    Returns
    -------
    float
        Estimated memory in megabytes.
    """
    COMPILED_MULTIPLIER = 10
    raw_bytes = pattern_count * avg_pattern_size * COMPILED_MULTIPLIER
    mb = raw_bytes / (1024.0 * 1024.0)
    logger.debug("Estimated memory for %d patterns: %.4f MB", pattern_count, mb)
    return round(mb, 4)


def compute_match_density(
    total_matches: int,
    total_bytes_scanned: int,
) -> float:
    """Compute match density as matches per kilobyte of scanned source code.

    Parameters
    ----------
    total_matches:
        Aggregate number of pattern matches.
    total_bytes_scanned:
        Total bytes of source code scanned.

    Returns
    -------
    float
        Matches per KB, rounded to four decimal places.
    """
    kb = total_bytes_scanned / 1024.0 if total_bytes_scanned > 0 else 0.0
    density = _safe_div(total_matches, kb)
    return round(density, 4)
