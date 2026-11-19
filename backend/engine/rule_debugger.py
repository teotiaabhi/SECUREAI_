"""
Rule debugging and diagnostics system.

Provides detailed explanations of WHY a rule fired on a specific file,
including pattern matches, context analysis, confidence scoring breakdown,
and precondition evaluation.

Usage:
    secureai scan . --debug-rule LOGIC-IDOR-001
    secureai scan . --debug-rule PY-INJ-001 --debug-file app/views.py
"""

import logging
import os
import re
from typing import Dict, List, Optional, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.rule_debugger")

# ANSI color codes for terminal output
_BOLD = "\033[1m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_CYAN = "\033[96m"
_DIM = "\033[2m"
_RESET = "\033[0m"


class RuleDebugReport:
    """Structured debug report for a single rule execution."""

    def __init__(self, rule_id: str, file_name: str):
        self.rule_id = rule_id
        self.file_name = file_name
        self.precondition_result: Optional[Tuple[bool, str]] = None
        self.patterns_tested: List[Dict] = []
        self.anti_patterns_checked: List[Dict] = []
        self.context_signals: List[Dict] = []
        self.confidence_breakdown: List[Dict] = []
        self.final_confidence: Optional[float] = None
        self.confidence_level: Optional[str] = None
        self.verdict: str = "unknown"
        self.input_source: Optional[str] = None

    def add_pattern_result(
        self,
        pattern: str,
        matched: bool,
        line: Optional[int] = None,
        matched_text: Optional[str] = None,
    ):
        self.patterns_tested.append({
            "pattern": pattern[:120],
            "matched": matched,
            "line": line,
            "matched_text": (matched_text or "")[:80],
        })

    def add_anti_pattern_result(self, pattern: str, found: bool):
        self.anti_patterns_checked.append({
            "pattern": pattern,
            "found": found,
        })

    def add_context_signal(self, signal_type: str, value: str, modifier: float):
        self.context_signals.append({
            "type": signal_type,
            "value": value,
            "modifier": modifier,
        })

    def add_confidence_modifier(self, source: str, modifier: float, reason: str):
        self.confidence_breakdown.append({
            "source": source,
            "modifier": modifier,
            "reason": reason,
        })

    def format_terminal(self) -> str:
        """Format the debug report for terminal display."""
        lines = []
        lines.append(f"\n{_BOLD}{_CYAN}{'═' * 72}{_RESET}")
        lines.append(f"{_BOLD}{_CYAN}  RULE DEBUG: {self.rule_id}{_RESET}")
        lines.append(f"{_BOLD}{_CYAN}  FILE: {self.file_name}{_RESET}")
        lines.append(f"{_BOLD}{_CYAN}{'═' * 72}{_RESET}\n")

        # Preconditions
        lines.append(f"{_BOLD}  PRECONDITION CHECK:{_RESET}")
        if self.precondition_result:
            passed, reason = self.precondition_result
            if passed:
                lines.append(f"    {_GREEN}✓ PASSED{_RESET} {reason}")
            else:
                lines.append(f"    {_RED}✗ FAILED{_RESET} — {reason}")
        else:
            lines.append(f"    {_DIM}No preconditions defined{_RESET}")

        # Pattern matches
        lines.append(f"\n{_BOLD}  PATTERN MATCHES:{_RESET}")
        for pt in self.patterns_tested:
            if pt["matched"]:
                lines.append(f"    {_GREEN}✓ MATCH{_RESET} L{pt['line']}: {_DIM}{pt['pattern']}{_RESET}")
                if pt["matched_text"]:
                    lines.append(f"      → {_YELLOW}{pt['matched_text']}{_RESET}")
            else:
                lines.append(f"    {_DIM}✗ no match: {pt['pattern']}{_RESET}")

        # Anti-patterns
        if self.anti_patterns_checked:
            lines.append(f"\n{_BOLD}  ANTI-PATTERN CHECK:{_RESET}")
            for ap in self.anti_patterns_checked:
                if ap["found"]:
                    lines.append(f"    {_GREEN}✓ FOUND (suppresses rule): {ap['pattern']}{_RESET}")
                else:
                    lines.append(f"    {_DIM}✗ not found: {ap['pattern']}{_RESET}")

        # Context signals
        if self.context_signals:
            lines.append(f"\n{_BOLD}  CONTEXT SIGNALS:{_RESET}")
            for cs in self.context_signals:
                color = _GREEN if cs["modifier"] < 0 else _RED if cs["modifier"] > 0 else _DIM
                lines.append(
                    f"    {color}{cs['type']}: {cs['value']} "
                    f"({cs['modifier']:+.1f} confidence){_RESET}"
                )

        # Input source
        if self.input_source:
            lines.append(f"\n{_BOLD}  INPUT SOURCE:{_RESET}")
            color = _RED if self.input_source == "user_input" else _GREEN
            lines.append(f"    {color}{self.input_source}{_RESET}")

        # Confidence breakdown
        if self.confidence_breakdown:
            lines.append(f"\n{_BOLD}  CONFIDENCE BREAKDOWN:{_RESET}")
            for cb in self.confidence_breakdown:
                color = _GREEN if cb["modifier"] < 0 else _RED if cb["modifier"] > 0 else _DIM
                lines.append(
                    f"    {color}{cb['modifier']:+6.1f}  {cb['source']}: {cb['reason']}{_RESET}"
                )

        # Final verdict
        lines.append(f"\n{_BOLD}  FINAL VERDICT:{_RESET}")
        if self.final_confidence is not None:
            level_color = (
                _RED if self.confidence_level == "high"
                else _YELLOW if self.confidence_level == "medium"
                else _GREEN
            )
            lines.append(
                f"    Confidence: {level_color}{self.final_confidence:.1f} "
                f"({self.confidence_level or 'unknown'}){_RESET}"
            )
        lines.append(f"    Verdict: {_BOLD}{self.verdict}{_RESET}")
        lines.append(f"\n{_DIM}{'─' * 72}{_RESET}\n")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize for JSON output."""
        return {
            "rule_id": self.rule_id,
            "file_name": self.file_name,
            "precondition_result": {
                "passed": self.precondition_result[0] if self.precondition_result else None,
                "reason": self.precondition_result[1] if self.precondition_result else None,
            },
            "patterns_tested": self.patterns_tested,
            "anti_patterns_checked": self.anti_patterns_checked,
            "context_signals": self.context_signals,
            "confidence_breakdown": self.confidence_breakdown,
            "final_confidence": self.final_confidence,
            "confidence_level": self.confidence_level,
            "input_source": self.input_source,
            "verdict": self.verdict,
        }


def generate_debug_report(
    rule_id: str,
    finding: EngineFinding,
    file_content: str,
) -> RuleDebugReport:
    """Generate a full debug report for a finding.

    This is called when --debug-rule is active.
    """
    report = RuleDebugReport(rule_id=rule_id, file_name=finding.file_name)

    # Capture confidence modifiers
    base_conf = finding.confidence
    report.add_confidence_modifier("base", base_conf, f"Rule base confidence: {base_conf}")

    for mod_str in (finding.intelligence_modifiers or []):
        if ":" in mod_str:
            parts = mod_str.rsplit(":", 1)
            try:
                val = float(parts[-1])
                report.add_confidence_modifier("intelligence", val, mod_str)
            except (ValueError, IndexError):
                report.add_confidence_modifier("intelligence", 0, mod_str)

    report.final_confidence = finding.adjusted_confidence or finding.confidence
    if report.final_confidence >= 70:
        report.confidence_level = "high"
    elif report.final_confidence >= 40:
        report.confidence_level = "medium"
    else:
        report.confidence_level = "low"

    if report.final_confidence >= 40:
        report.verdict = "REPORTED (confidence >= medium threshold)"
    else:
        report.verdict = "SUPPRESSED (confidence below medium threshold)"

    return report


def format_debug_summary(
    findings: List[EngineFinding],
    debug_rule_id: str,
    file_contents: Dict[str, str],
) -> str:
    """Format a debug summary for all findings matching a rule ID.

    Used by CLI when --debug-rule is specified.
    """
    matching = [f for f in findings if f.rule_id == debug_rule_id]

    if not matching:
        return (
            f"\n{_BOLD}{_YELLOW}  No findings for rule {debug_rule_id}.{_RESET}\n"
            f"  The rule either didn't match any patterns or was suppressed by preconditions.\n"
        )

    reports = []
    for finding in matching:
        content = file_contents.get(finding.file_name, "")
        report = generate_debug_report(debug_rule_id, finding, content)
        reports.append(report.format_terminal())

    header = (
        f"\n{_BOLD}{_BLUE}{'═' * 72}{_RESET}\n"
        f"{_BOLD}{_BLUE}  DEBUG MODE: Rule {debug_rule_id}{_RESET}\n"
        f"{_BOLD}{_BLUE}  {len(matching)} finding(s) across {len(set(f.file_name for f in matching))} file(s){_RESET}\n"
        f"{_BOLD}{_BLUE}{'═' * 72}{_RESET}\n"
    )

    return header + "\n".join(reports)
