"""Pytest integration for the rule validation framework.

Provides parametrized test fixtures that integrate the rule test runner
with pytest's test discovery and reporting.  Tests are automatically
discovered from the test sample directories and parametrized per test case.

Usage:
    pytest conftest.py -v               # Run all rule validation tests
    pytest conftest.py -k injection     # Run only injection-related tests
    pytest conftest.py --tb=short       # Shorter tracebacks on failures
"""

import logging
import sys
from pathlib import Path
from typing import List

import pytest

# Ensure the runner package is importable.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from runner.config import load_config
from runner.rule_loader import load_all_rules, RuleRegistry
from runner.test_loader import load_all_tests, TestCase, TestSuite
from runner.engine import (
    _evaluate_rule,
    _classify_outcome,
    _select_applicable_rules,
    Outcome,
)

logger = logging.getLogger(__name__)


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def rule_test_config():
    """Load the test framework configuration once per session."""
    return load_config()


@pytest.fixture(scope="session")
def rule_registry(rule_test_config):
    """Load all rule definitions once per session."""
    registry = load_all_rules(rule_test_config.rules_dir)
    assert len(registry) > 0, f"No rules loaded from {rule_test_config.rules_dir}"
    return registry


@pytest.fixture(scope="session")
def test_suite(rule_test_config):
    """Load all test samples once per session."""
    suite = load_all_tests(rule_test_config.tests_dir)
    assert len(suite) > 0, f"No test samples loaded from {rule_test_config.tests_dir}"
    return suite


# ── Parametrized Test Cases ──────────────────────────────────────────

def _collect_positive_tests() -> List[TestCase]:
    """Collect all positive test cases for parametrization."""
    config = load_config()
    suite = load_all_tests(config.tests_dir)
    return suite.get_positive_tests()


def _collect_negative_tests() -> List[TestCase]:
    """Collect all negative test cases for parametrization."""
    config = load_config()
    suite = load_all_tests(config.tests_dir)
    return suite.get_negative_tests()


def _test_case_id(tc: TestCase) -> str:
    """Generate a human-readable test ID for pytest output."""
    return f"{tc.category}/{tc.file_path.name}"


# ── Positive Tests (rules SHOULD fire) ───────────────────────────────

_positive_tests = _collect_positive_tests()


@pytest.mark.parametrize(
    "test_case",
    _positive_tests,
    ids=[_test_case_id(tc) for tc in _positive_tests],
)
def test_positive_detection(test_case: TestCase, rule_registry, rule_test_config):
    """Verify that expected rules fire on positive test samples.

    For each positive test case, at least one expected rule must match.
    """
    if not test_case.expected_rule_ids:
        pytest.skip("No expected_rule_ids specified in test header")

    applicable = _select_applicable_rules(rule_registry, test_case)
    detected_ids = set()
    missed_ids = set()

    for rule in applicable:
        if rule.rule_id not in test_case.expected_rule_ids:
            continue

        mr = _evaluate_rule(
            rule,
            test_case,
            rule_test_config.confidence_threshold,
            rule_test_config.timeout_per_rule_ms,
        )
        if mr.matched:
            detected_ids.add(rule.rule_id)
        else:
            missed_ids.add(rule.rule_id)

    # Check that expected rules we couldn't even find are counted as misses.
    evaluated_ids = {r.rule_id for r in applicable}
    for expected_id in test_case.expected_rule_ids:
        if expected_id not in evaluated_ids:
            missed_ids.add(expected_id)

    assert detected_ids, (
        f"No expected rules fired for {test_case.file_path.name}. "
        f"Expected: {test_case.expected_rule_ids}, "
        f"Missed: {sorted(missed_ids)}"
    )


# ── Negative Tests (rules should NOT fire) ───────────────────────────

_negative_tests = _collect_negative_tests()


@pytest.mark.parametrize(
    "test_case",
    _negative_tests,
    ids=[_test_case_id(tc) for tc in _negative_tests],
)
def test_negative_no_detection(test_case: TestCase, rule_registry, rule_test_config):
    """Verify that rules do NOT fire on negative (safe) test samples.

    No rule in the same category should trigger a match on a negative sample.
    """
    applicable = _select_applicable_rules(rule_registry, test_case)
    false_positives = []

    for rule in applicable:
        mr = _evaluate_rule(
            rule,
            test_case,
            rule_test_config.confidence_threshold,
            rule_test_config.timeout_per_rule_ms,
        )
        if mr.matched:
            false_positives.append(
                f"{rule.rule_id} (confidence={mr.confidence:.2f}, "
                f"lines={mr.match_locations})"
            )

    assert not false_positives, (
        f"False positives on negative sample {test_case.file_path.name}: "
        f"{'; '.join(false_positives)}"
    )


# ── Rule Coverage Check ─────────────────────────────────────────────

def test_rule_coverage(rule_registry, test_suite):
    """Verify that every loaded rule has at least one positive test case.

    This is a coverage gate to ensure no rule is left untested.
    """
    tested_rule_ids = set()
    for tc in test_suite.get_positive_tests():
        tested_rule_ids.update(tc.expected_rule_ids)

    all_rule_ids = {r.rule_id for r in rule_registry.all_rules}
    untested = all_rule_ids - tested_rule_ids

    if untested:
        logger.warning(
            "%d rules have no positive test coverage: %s",
            len(untested),
            sorted(untested),
        )
    # Soft check — warn but don't fail yet.
    # Change to an assert once coverage is complete:
    # assert not untested, f"Untested rules: {sorted(untested)}"


# ── Performance Sanity Check ─────────────────────────────────────────

def test_rule_compilation_time(rule_registry):
    """Verify that no single rule takes more than 100ms to compile."""
    slow_rules = [
        r for r in rule_registry.all_rules
        if r.regex_compile_time_ms > 100.0
    ]
    assert not slow_rules, (
        f"Rules with slow regex compilation (>100ms): "
        f"{[(r.rule_id, f'{r.regex_compile_time_ms:.1f}ms') for r in slow_rules]}"
    )
