"""
Rule Execution Heatmap & Regex Performance Profiler.

Provides Parts 1–10 of the profiling system:
  1. Rule execution timing (per-pattern, per-file)
  2. Slow rule detection (threshold-based logging)
  3. Heatmap aggregation (per-rule stats in memory)
  4. Heatmap report (sorted by cost)
  5. Regex pattern safety analyzer (detect dangerous patterns)
  6. Automatic regex optimization suggestions
  7. Per-file rule profiling
  8. Performance summary report
  9. Minimal overhead (perf_counter, lock-free fast path)
 10. Combined output generation

Designed for multiprocess workers: each process maintains its own
RuleProfiler instance.  After scanning, the orchestrator collects
per-process snapshots via get_snapshot() and merges them with
merge_snapshots() to produce the global heatmap.
"""

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("engine.rule_profiler")

# ─── Part 2: Slow rule threshold ────────────────────────────────────
SLOW_RULE_THRESHOLD_MS: float = 100.0

# ─── Part 5: Dangerous regex patterns ───────────────────────────────
_DANGEROUS_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"\(\.\+\)\+"),
        "nested quantifier (.+)+",
        "Rewrite as (.+) without outer + or use atomic group",
    ),
    (
        re.compile(r"\(\.\*\)\+"),
        "nested quantifier (.*)+",
        "Remove outer + — (.*) already matches everything",
    ),
    (
        re.compile(r"\(\.\+\)\*"),
        "nested quantifier (.+)*",
        "Rewrite as (.+) without outer * or use atomic group",
    ),
    (
        re.compile(r"\(\.\*\)\*"),
        "nested quantifier (.*)*",
        "Remove outer * — (.*) already matches everything",
    ),
    (
        re.compile(r"(?<!\{)\.\*(?![?}])"),
        "unbounded wildcard .*",
        "Replace .* with .{0,200} to bound backtracking",
    ),
    (
        re.compile(r"(?<!\{)\.\+(?![?}])"),
        "unbounded wildcard .+",
        "Replace .+ with .{1,200} to bound backtracking",
    ),
]


# ─── Part 1/3: Per-rule aggregation ─────────────────────────────────

@dataclass
class RuleStats:
    """Aggregated execution statistics for a single rule."""
    rule_id: str
    executions: int = 0
    total_time_ms: float = 0.0
    max_time_ms: float = 0.0
    total_matches: int = 0
    slow_executions: int = 0
    pattern_strs: List[str] = field(default_factory=list)

    @property
    def avg_time_ms(self) -> float:
        if self.executions == 0:
            return 0.0
        return self.total_time_ms / self.executions

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "executions": self.executions,
            "avg_time_ms": round(self.avg_time_ms, 2),
            "max_time_ms": round(self.max_time_ms, 2),
            "total_time_ms": round(self.total_time_ms, 2),
            "total_matches": self.total_matches,
            "slow_executions": self.slow_executions,
            "pattern_strs": self.pattern_strs[:5],  # limit serialized size
        }


# ─── Part 7: Per-file profiling ─────────────────────────────────────

@dataclass
class FileProfile:
    """Per-file rule execution profile."""
    file_name: str
    rules_executed: int = 0
    slow_rules: int = 0
    total_time_ms: float = 0.0
    slowest_rule_id: str = ""
    slowest_rule_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "rules_executed": self.rules_executed,
            "slow_rules": self.slow_rules,
            "total_time_ms": round(self.total_time_ms, 2),
            "slowest_rule_id": self.slowest_rule_id,
            "slowest_rule_ms": round(self.slowest_rule_ms, 2),
        }


# ─── Part 5: Regex safety analysis result ───────────────────────────

@dataclass
class RegexIssue:
    """A problematic regex pattern detected by the safety analyzer."""
    rule_id: str
    pattern: str
    issue: str
    suggestion: str

    def to_dict(self) -> dict:
        # Truncate long patterns for readability
        p = self.pattern if len(self.pattern) <= 120 else self.pattern[:117] + "..."
        return {
            "rule_id": self.rule_id,
            "pattern": p,
            "issue": self.issue,
            "suggestion": self.suggestion,
        }


# ─── Main Profiler ──────────────────────────────────────────────────

class RuleProfiler:
    """Per-process rule execution profiler.

    Thread-safe (uses a lock for writes).  The fast path (record_execution
    with times below threshold) takes <1µs overhead because it's just
    two dict lookups and arithmetic.
    """

    def __init__(self, threshold_ms: float = SLOW_RULE_THRESHOLD_MS):
        self._threshold_ms = threshold_ms
        self._rule_stats: Dict[str, RuleStats] = {}
        self._file_profiles: Dict[str, FileProfile] = {}
        self._lock = Lock()

    # ── Part 1: Record a single rule execution ───────────────────

    def record_execution(
        self,
        rule_id: str,
        file_name: str,
        elapsed_ms: float,
        match_count: int,
        pattern_strs: Optional[List[str]] = None,
    ) -> None:
        """Record timing for one rule execution against one file.

        Called from detect_in_file() after each rule completes.
        """
        with self._lock:
            # Part 3: Heatmap aggregation
            stats = self._rule_stats.get(rule_id)
            if stats is None:
                stats = RuleStats(rule_id=rule_id)
                self._rule_stats[rule_id] = stats
            stats.executions += 1
            stats.total_time_ms += elapsed_ms
            stats.total_matches += match_count
            if elapsed_ms > stats.max_time_ms:
                stats.max_time_ms = elapsed_ms
            if pattern_strs and not stats.pattern_strs:
                stats.pattern_strs = list(pattern_strs[:5])

            # Part 2: Slow rule detection (log immediately)
            if elapsed_ms > self._threshold_ms:
                stats.slow_executions += 1
                logger.warning(
                    "[SLOW_RULE] rule_id=%s file=%s execution_time=%.0fms "
                    "matches=%d",
                    rule_id, file_name, elapsed_ms, match_count,
                )

            # Part 7: Per-file profiling
            fp = self._file_profiles.get(file_name)
            if fp is None:
                fp = FileProfile(file_name=file_name)
                self._file_profiles[file_name] = fp
            fp.rules_executed += 1
            fp.total_time_ms += elapsed_ms
            if elapsed_ms > self._threshold_ms:
                fp.slow_rules += 1
            if elapsed_ms > fp.slowest_rule_ms:
                fp.slowest_rule_ms = elapsed_ms
                fp.slowest_rule_id = rule_id

    # ── Part 4: Heatmap output ───────────────────────────────────

    def get_heatmap(self, top_n: int = 20) -> List[dict]:
        """Return top-N rules sorted by total execution cost (descending)."""
        with self._lock:
            sorted_rules = sorted(
                self._rule_stats.values(),
                key=lambda s: s.total_time_ms,
                reverse=True,
            )
            return [s.to_dict() for s in sorted_rules[:top_n]]

    def format_heatmap_report(self, top_n: int = 20) -> str:
        """Human-readable heatmap report string."""
        heatmap = self.get_heatmap(top_n)
        if not heatmap:
            return "No rule execution data collected."

        lines = ["", "=" * 60, "  RULE EXECUTION HEATMAP — Top Slow Rules", "=" * 60]
        for i, entry in enumerate(heatmap, 1):
            lines.append(
                f"\n{i}. {entry['rule_id']}\n"
                f"   executions={entry['executions']}  "
                f"avg={entry['avg_time_ms']:.1f}ms  "
                f"max={entry['max_time_ms']:.1f}ms  "
                f"total={entry['total_time_ms']:.1f}ms  "
                f"matches={entry['total_matches']}  "
                f"slow_hits={entry['slow_executions']}"
            )
        lines.append("=" * 60)
        return "\n".join(lines)

    # ── Part 7: Per-file report ──────────────────────────────────

    def get_file_profiles(self, top_n: int = 20) -> List[dict]:
        """Return top-N files sorted by total rule execution time."""
        with self._lock:
            sorted_files = sorted(
                self._file_profiles.values(),
                key=lambda f: f.total_time_ms,
                reverse=True,
            )
            return [f.to_dict() for f in sorted_files[:top_n]]

    def format_file_report(self, top_n: int = 10) -> str:
        """Human-readable per-file profiling report."""
        profiles = self.get_file_profiles(top_n)
        if not profiles:
            return ""
        lines = [
            "", "=" * 60,
            "  PER-FILE RULE PROFILING — Slowest Files",
            "=" * 60,
        ]
        for fp in profiles:
            lines.append(
                f"  file={fp['file_name']}\n"
                f"    rules_executed={fp['rules_executed']}  "
                f"slow_rules={fp['slow_rules']}  "
                f"total_time={fp['total_time_ms']:.1f}ms  "
                f"slowest={fp['slowest_rule_id']} ({fp['slowest_rule_ms']:.0f}ms)"
            )
        lines.append("=" * 60)
        return "\n".join(lines)

    # ── Part 8: Performance summary ──────────────────────────────

    def get_summary(self) -> dict:
        """Return aggregated performance summary."""
        with self._lock:
            total_executions = sum(s.executions for s in self._rule_stats.values())
            total_time = sum(s.total_time_ms for s in self._rule_stats.values())
            slow_count = sum(
                1 for s in self._rule_stats.values() if s.slow_executions > 0
            )
            files_count = len(self._file_profiles)
            files_with_slow = sum(
                1 for f in self._file_profiles.values() if f.slow_rules > 0
            )
            return {
                "total_rule_executions": total_executions,
                "total_rule_time_ms": round(total_time, 2),
                "unique_rules_executed": len(self._rule_stats),
                "slow_rules_detected": slow_count,
                "files_profiled": files_count,
                "files_with_slow_rules": files_with_slow,
            }

    def format_summary(self, scan_duration_s: float = 0.0,
                       files_scanned: int = 0) -> str:
        """Human-readable performance summary."""
        s = self.get_summary()
        lines = [
            "", "=" * 60,
            "  PERFORMANCE SUMMARY REPORT",
            "=" * 60,
            f"  scan_duration:        {scan_duration_s:.1f}s",
            f"  files_scanned:        {files_scanned}",
            f"  rules_executed:       {s['total_rule_executions']}",
            f"  unique_rules:         {s['unique_rules_executed']}",
            f"  total_rule_time:      {s['total_rule_time_ms']:.1f}ms",
            f"  slow_rules_detected:  {s['slow_rules_detected']}",
            f"  files_profiled:       {s['files_profiled']}",
            f"  files_with_slow_rules:{s['files_with_slow_rules']}",
            "=" * 60,
        ]
        return "\n".join(lines)

    # ── Snapshot/merge for multiprocess collection ───────────────

    def get_snapshot(self) -> dict:
        """Serialize profiler state for cross-process transfer."""
        with self._lock:
            return {
                "rule_stats": {
                    k: v.to_dict() for k, v in self._rule_stats.items()
                },
                "file_profiles": {
                    k: v.to_dict() for k, v in self._file_profiles.items()
                },
            }

    def merge_snapshot(self, snapshot: dict) -> None:
        """Merge a snapshot from another process into this profiler."""
        with self._lock:
            for rule_id, sd in snapshot.get("rule_stats", {}).items():
                stats = self._rule_stats.get(rule_id)
                if stats is None:
                    stats = RuleStats(rule_id=rule_id)
                    self._rule_stats[rule_id] = stats
                stats.executions += sd.get("executions", 0)
                stats.total_time_ms += sd.get("total_time_ms", 0.0)
                stats.total_matches += sd.get("total_matches", 0)
                stats.slow_executions += sd.get("slow_executions", 0)
                mx = sd.get("max_time_ms", 0.0)
                if mx > stats.max_time_ms:
                    stats.max_time_ms = mx
                if not stats.pattern_strs:
                    stats.pattern_strs = sd.get("pattern_strs", [])

            for file_name, fd in snapshot.get("file_profiles", {}).items():
                fp = self._file_profiles.get(file_name)
                if fp is None:
                    fp = FileProfile(file_name=file_name)
                    self._file_profiles[file_name] = fp
                fp.rules_executed += fd.get("rules_executed", 0)
                fp.slow_rules += fd.get("slow_rules", 0)
                fp.total_time_ms += fd.get("total_time_ms", 0.0)
                ms = fd.get("slowest_rule_ms", 0.0)
                if ms > fp.slowest_rule_ms:
                    fp.slowest_rule_ms = ms
                    fp.slowest_rule_id = fd.get("slowest_rule_id", "")


# ─── Part 5/6: Regex Safety Analyzer ────────────────────────────────

def analyze_regex_safety(
    rule_id: str,
    pattern_strs: List[str],
) -> List[RegexIssue]:
    """Analyze regex patterns for dangerous constructs.

    Returns list of RegexIssue objects describing problems and
    suggested fixes.
    """
    issues: List[RegexIssue] = []
    for pat_str in pattern_strs:
        for detector, issue_desc, suggestion in _DANGEROUS_PATTERNS:
            if detector.search(pat_str):
                issues.append(RegexIssue(
                    rule_id=rule_id,
                    pattern=pat_str,
                    issue=issue_desc,
                    suggestion=suggestion,
                ))
    return issues


def analyze_slow_rules(profiler: RuleProfiler) -> List[dict]:
    """For each slow rule in the profiler, run regex safety analysis
    and generate optimization suggestions (Parts 5+6).

    Returns list of dicts with rule_id, issues, and suggestions.
    """
    results = []
    with profiler._lock:
        for rule_id, stats in profiler._rule_stats.items():
            if stats.slow_executions == 0:
                continue
            issues = analyze_regex_safety(rule_id, stats.pattern_strs)
            entry = {
                "rule_id": rule_id,
                "avg_time_ms": round(stats.avg_time_ms, 1),
                "max_time_ms": round(stats.max_time_ms, 1),
                "slow_executions": stats.slow_executions,
                "issues": [i.to_dict() for i in issues],
                "suggestions": [],
            }
            # Part 6: Generate optimization suggestions
            if issues:
                for iss in issues:
                    entry["suggestions"].append(
                        f"Rule {rule_id}: {iss.issue} → {iss.suggestion}"
                    )
            elif stats.max_time_ms > 500:
                entry["suggestions"].append(
                    f"Rule {rule_id}: max execution {stats.max_time_ms:.0f}ms "
                    f"— consider splitting into smaller patterns or adding "
                    f"early-exit literals"
                )
            results.append(entry)
    return results


def format_optimization_report(profiler: RuleProfiler) -> str:
    """Human-readable optimization suggestions report (Parts 5+6)."""
    analysis = analyze_slow_rules(profiler)
    if not analysis:
        return ""
    lines = [
        "", "=" * 60,
        "  REGEX OPTIMIZATION SUGGESTIONS",
        "=" * 60,
    ]
    for entry in analysis:
        lines.append(f"\n  Rule: {entry['rule_id']}")
        lines.append(f"    avg={entry['avg_time_ms']:.1f}ms  max={entry['max_time_ms']:.1f}ms  slow_hits={entry['slow_executions']}")
        if entry["issues"]:
            for iss in entry["issues"]:
                lines.append(f"    Problem: {iss['issue']}")
                lines.append(f"    Suggestion: {iss['suggestion']}")
                pat_display = iss['pattern']
                lines.append(f"    Pattern: {pat_display}")
        for sug in entry["suggestions"]:
            lines.append(f"    → {sug}")
    lines.append("=" * 60)
    return "\n".join(lines)


# ─── Part 10: Combined report generator ─────────────────────────────

def generate_full_report(
    profiler: RuleProfiler,
    scan_duration_s: float = 0.0,
    files_scanned: int = 0,
) -> str:
    """Generate the complete profiling report (Parts 4+7+8+5/6).

    Returns a single string containing:
      - Performance summary
      - Rule execution heatmap
      - Per-file profiling
      - Regex optimization suggestions
    """
    parts = [
        profiler.format_summary(scan_duration_s, files_scanned),
        profiler.format_heatmap_report(top_n=20),
        profiler.format_file_report(top_n=10),
        format_optimization_report(profiler),
    ]
    return "\n".join(p for p in parts if p)


# ─── Per-process singleton ──────────────────────────────────────────

_profiler: Optional[RuleProfiler] = None


def get_profiler() -> RuleProfiler:
    """Return the per-process RuleProfiler singleton."""
    global _profiler
    if _profiler is None:
        _profiler = RuleProfiler()
    return _profiler


def reset_profiler() -> None:
    """Reset the per-process profiler (for tests)."""
    global _profiler
    _profiler = RuleProfiler()


def get_profiler_snapshot() -> dict:
    """Get serializable snapshot from per-process profiler.

    Called by worker_scan_file() to return profiling data alongside
    findings — this data is piggybacked on the existing cross-process
    transfer mechanism.
    """
    return get_profiler().get_snapshot()
