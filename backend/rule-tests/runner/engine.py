"""Test execution engine for the rule validation framework.

Runs rules against test samples, records match results, classifies outcomes
(true/false positive/negative), and supports parallel execution.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .rule_loader import RuleDefinition, RuleRegistry
from .test_loader import TestCase, TestSuite

logger = logging.getLogger(__name__)


class Outcome(Enum):
    """Classification of a single rule-vs-test evaluation."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"


@dataclass
class MatchResult:
    """Result of applying one rule to one test file.

    Attributes:
        rule_id: Identifier of the rule that was evaluated.
        matched: Whether the rule produced at least one match.
        match_count: Total number of pattern matches found.
        match_locations: Line numbers where matches were found.
        execution_time_ms: Wall-clock time for the evaluation in milliseconds.
        confidence: Effective confidence for the match, accounting for
            anti-pattern suppression and rule base confidence.
    """

    rule_id: str
    matched: bool
    match_count: int
    match_locations: List[int]
    execution_time_ms: float
    confidence: float


@dataclass
class TestCaseResult:
    """Aggregated result for a single test case across all applicable rules.

    Attributes:
        test_case: The originating test case.
        match_results: Per-rule match results.
        outcomes: Mapping of rule_id to its ``Outcome`` classification.
        total_execution_time_ms: Sum of execution times for all rules.
    """

    test_case: TestCase
    match_results: List[MatchResult] = field(default_factory=list)
    outcomes: Dict[str, Outcome] = field(default_factory=dict)
    total_execution_time_ms: float = 0.0


@dataclass
class TestRunSummary:
    """High-level statistics for a complete test run.

    Attributes:
        true_positives: Number of TRUE_POSITIVE outcomes.
        false_positives: Number of FALSE_POSITIVE outcomes.
        true_negatives: Number of TRUE_NEGATIVE outcomes.
        false_negatives: Number of FALSE_NEGATIVE outcomes.
        total_rules_evaluated: Total rule evaluations performed.
        total_execution_time_ms: Wall-clock time for the entire run.
        precision: TP / (TP + FP), or 0.0 when undefined.
        recall: TP / (TP + FN), or 0.0 when undefined.
    """

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_rules_evaluated: int = 0
    total_execution_time_ms: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


@dataclass
class TestRunResult:
    """Complete output from a test run.

    Attributes:
        case_results: Per-test-case results.
        summary: Aggregated summary statistics.
    """

    case_results: List[TestCaseResult] = field(default_factory=list)
    summary: TestRunSummary = field(default_factory=TestRunSummary)


def _find_match_lines(content: str, pattern, timeout_ms: int) -> Tuple[int, List[int]]:
    """Run *pattern* against *content* and return match count and line numbers.

    Args:
        content: The full file content to search.
        pattern: A compiled ``re.Pattern``.
        timeout_ms: Not enforced at the regex level (Python ``re`` does not
            support timeouts), but the caller should check elapsed time.

    Returns:
        A tuple of ``(match_count, sorted_line_numbers)``.
    """
    line_numbers: List[int] = []
    match_count = 0

    # Pre-compute line start offsets for O(1) offset-to-line conversion.
    line_starts: List[int] = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            line_starts.append(i + 1)

    for m in pattern.finditer(content):
        match_count += 1
        offset = m.start()
        # Binary search for the line number.
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        line_numbers.append(lo + 1)  # 1-based

    return match_count, sorted(set(line_numbers))


def _check_anti_patterns(content: str, anti_patterns: List[str]) -> bool:
    """Return ``True`` if any anti-pattern string is found in *content*.

    Anti-patterns are matched as literal substrings (case-insensitive).

    Args:
        content: File content to check.
        anti_patterns: Strings whose presence should suppress a match.

    Returns:
        ``True`` if at least one anti-pattern was found.
    """
    content_lower = content.lower()
    for ap in anti_patterns:
        if ap.lower() in content_lower:
            logger.debug("Anti-pattern '%s' found; suppressing match.", ap)
            return True
    return False


def _evaluate_rule(
    rule: RuleDefinition,
    test_case: TestCase,
    confidence_threshold: float,
    timeout_ms: int,
) -> MatchResult:
    """Evaluate a single rule against a single test case.

    Args:
        rule: The rule to apply.
        test_case: The test sample to scan.
        confidence_threshold: Minimum confidence to count as a real match.
        timeout_ms: Per-rule time budget in milliseconds.

    Returns:
        A ``MatchResult`` describing whether and where the rule triggered.
    """
    start = time.perf_counter()

    total_count = 0
    all_locations: List[int] = []

    for pattern in rule.patterns:
        count, locations = _find_match_lines(test_case.content, pattern, timeout_ms)
        total_count += count
        all_locations.extend(locations)

    # Suppress if anti-patterns are present.
    suppressed = False
    if total_count > 0 and rule.anti_patterns:
        suppressed = _check_anti_patterns(test_case.content, rule.anti_patterns)

    effective_confidence = rule.confidence if (total_count > 0 and not suppressed) else 0.0
    matched = (
        total_count > 0
        and not suppressed
        and effective_confidence >= confidence_threshold
    )

    elapsed_ms = (time.perf_counter() - start) * 1000.0

    return MatchResult(
        rule_id=rule.rule_id,
        matched=matched,
        match_count=total_count if not suppressed else 0,
        match_locations=sorted(set(all_locations)) if not suppressed else [],
        execution_time_ms=elapsed_ms,
        confidence=effective_confidence,
    )


def _classify_outcome(
    rule_id: str,
    matched: bool,
    test_type: str,
    expected_rule_ids: List[str],
) -> Outcome:
    """Determine the outcome classification for a rule evaluation.

    Args:
        rule_id: The rule that was evaluated.
        matched: Whether the rule triggered.
        test_type: ``positive`` or ``negative``.
        expected_rule_ids: Rule ids listed in the test header.

    Returns:
        The appropriate ``Outcome`` enum value.
    """
    expected = rule_id in expected_rule_ids

    if test_type == "positive":
        if matched and expected:
            return Outcome.TRUE_POSITIVE
        if matched and not expected:
            return Outcome.FALSE_POSITIVE
        if not matched and expected:
            return Outcome.FALSE_NEGATIVE
        return Outcome.TRUE_NEGATIVE
    else:
        # Negative test: rules should NOT fire.
        if matched:
            return Outcome.FALSE_POSITIVE
        return Outcome.TRUE_NEGATIVE


def _select_applicable_rules(
    registry: RuleRegistry,
    test_case: TestCase,
) -> List[RuleDefinition]:
    """Select rules that apply to a test case based on language and category.

    A rule is applicable when its language matches the test case language **or**
    either side specifies a wildcard / ``"any"`` value.  Category is used as a
    secondary filter when the test case provides one other than
    ``"uncategorized"``.

    Args:
        registry: The loaded rule registry.
        test_case: The test case to match against.

    Returns:
        List of applicable rules.
    """
    candidates: List[RuleDefinition] = []

    for rule in registry.all_rules:
        lang_match = (
            rule.language == test_case.language
            or rule.language in ("any", "*")
            or test_case.language in ("any", "*", "unknown")
        )
        if not lang_match:
            continue

        cat_match = (
            test_case.category == "uncategorized"
            or rule.category == test_case.category
            or rule.category in ("any", "*")
        )
        if not cat_match:
            continue

        candidates.append(rule)

    return candidates


def _run_single_test(
    registry: RuleRegistry,
    test_case: TestCase,
    confidence_threshold: float,
    timeout_ms: int,
) -> TestCaseResult:
    """Execute all applicable rules against a single test case.

    Args:
        registry: Loaded rule registry.
        test_case: The test sample to evaluate.
        confidence_threshold: Minimum confidence for a valid match.
        timeout_ms: Per-rule timeout in milliseconds.

    Returns:
        A ``TestCaseResult`` with per-rule results and outcome classifications.
    """
    result = TestCaseResult(test_case=test_case)
    applicable_rules = _select_applicable_rules(registry, test_case)

    logger.debug(
        "Test %s: %d applicable rules.", test_case.file_path.name, len(applicable_rules)
    )

    for rule in applicable_rules:
        mr = _evaluate_rule(rule, test_case, confidence_threshold, timeout_ms)
        result.match_results.append(mr)
        result.total_execution_time_ms += mr.execution_time_ms

        outcome = _classify_outcome(
            mr.rule_id, mr.matched, test_case.test_type, test_case.expected_rule_ids
        )
        result.outcomes[mr.rule_id] = outcome

    # Check for expected rules that had no applicable rule loaded at all.
    evaluated_ids = {mr.rule_id for mr in result.match_results}
    for expected_id in test_case.expected_rule_ids:
        if expected_id not in evaluated_ids:
            logger.warning(
                "Expected rule '%s' was not evaluated for %s (not loaded or not applicable).",
                expected_id,
                test_case.file_path.name,
            )
            if test_case.test_type == "positive":
                result.outcomes[expected_id] = Outcome.FALSE_NEGATIVE

    return result


def _build_summary(case_results: List[TestCaseResult]) -> TestRunSummary:
    """Aggregate individual case results into a summary.

    Args:
        case_results: List of completed test case results.

    Returns:
        A ``TestRunSummary`` with counts and timing.
    """
    summary = TestRunSummary()
    for cr in case_results:
        summary.total_execution_time_ms += cr.total_execution_time_ms
        for outcome in cr.outcomes.values():
            summary.total_rules_evaluated += 1
            if outcome is Outcome.TRUE_POSITIVE:
                summary.true_positives += 1
            elif outcome is Outcome.FALSE_POSITIVE:
                summary.false_positives += 1
            elif outcome is Outcome.TRUE_NEGATIVE:
                summary.true_negatives += 1
            elif outcome is Outcome.FALSE_NEGATIVE:
                summary.false_negatives += 1
    return summary


def run_tests(
    registry: RuleRegistry,
    suite: TestSuite,
    confidence_threshold: float = 0.5,
    timeout_ms: int = 5000,
    parallel_workers: int = 1,
) -> TestRunResult:
    """Execute the full test suite against the loaded rules.

    Args:
        registry: A populated ``RuleRegistry``.
        suite: A populated ``TestSuite``.
        confidence_threshold: Minimum confidence for a match to count.
        timeout_ms: Per-rule timeout in milliseconds.
        parallel_workers: Number of threads.  Set to ``1`` for sequential
            execution (easier to debug).

    Returns:
        A ``TestRunResult`` containing all individual results and a summary.
    """
    run_result = TestRunResult()
    test_cases = suite.all_tests

    if not test_cases:
        logger.warning("No test cases to run.")
        return run_result

    logger.info(
        "Starting test run: %d tests, %d rules, %d workers.",
        len(test_cases),
        len(registry),
        parallel_workers,
    )

    overall_start = time.perf_counter()

    if parallel_workers <= 1:
        for tc in test_cases:
            cr = _run_single_test(registry, tc, confidence_threshold, timeout_ms)
            run_result.case_results.append(cr)
    else:
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            future_to_tc = {
                executor.submit(
                    _run_single_test, registry, tc, confidence_threshold, timeout_ms
                ): tc
                for tc in test_cases
            }
            for future in as_completed(future_to_tc):
                tc = future_to_tc[future]
                try:
                    cr = future.result()
                    run_result.case_results.append(cr)
                except Exception:
                    logger.exception("Error processing test %s", tc.file_path)

    overall_elapsed = (time.perf_counter() - overall_start) * 1000.0
    run_result.summary = _build_summary(run_result.case_results)
    run_result.summary.total_execution_time_ms = overall_elapsed

    logger.info(
        "Test run complete in %.1f ms: TP=%d FP=%d TN=%d FN=%d "
        "precision=%.3f recall=%.3f F1=%.3f",
        overall_elapsed,
        run_result.summary.true_positives,
        run_result.summary.false_positives,
        run_result.summary.true_negatives,
        run_result.summary.false_negatives,
        run_result.summary.precision,
        run_result.summary.recall,
        run_result.summary.f1_score,
    )

    return run_result
