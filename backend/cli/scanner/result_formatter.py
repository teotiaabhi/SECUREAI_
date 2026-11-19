"""Terminal output formatting for scan results."""

import sys
from collections import Counter
from typing import Dict, List

# ANSI color codes (disabled if not a tty)
_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "green": "\033[92m",
    "magenta": "\033[95m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

SEVERITY_SYMBOLS = {
    "critical": "✖",
    "high": "✖",
    "medium": "▲",
    "low": "●",
    "info": "ℹ",
}


def _c(color: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def print_banner() -> None:
    print(_c("bold", "\n  SecureAI Code Analyzer"))
    print(_c("dim", "  Static Application Security Testing\n"))


def print_scan_start(path: str, file_count: int, lang_count: int) -> None:
    print(f"  Target     : {path}")
    print(f"  Files      : {file_count}")
    print(f"  Languages  : {lang_count}")
    print()


def print_progress(current: int, total: int, filename: str) -> None:
    """Print a single-line progress update (overwrites previous line)."""
    bar_width = 30
    pct = current / total if total else 1.0
    filled = int(bar_width * pct)
    bar = "█" * filled + "░" * (bar_width - filled)

    short_name = filename
    if len(short_name) > 40:
        short_name = "..." + short_name[-37:]

    line = f"\r  [{bar}] {current}/{total}  {short_name}"
    sys.stdout.write(line.ljust(100))
    sys.stdout.flush()

    if current == total:
        sys.stdout.write("\n\n")
        sys.stdout.flush()


def print_findings(findings: List[Dict], severity_filter: str = None) -> None:
    """Print findings grouped by file, with aggregated occurrence counts.

    Args:
        findings: List of finding dicts (from EngineFinding.to_dict() or aggregated)
        severity_filter: Minimum severity to display
    """
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_sev = severity_order.get(severity_filter, 0) if severity_filter else 0

    filtered = [
        f for f in findings
        if severity_order.get(f.get("severity", "info"), 0) >= min_sev
    ]

    if not filtered:
        print(_c("green", "  ✓ No vulnerabilities found.\n"))
        return

    # Group by file
    by_file: Dict[str, List[Dict]] = {}
    for f in filtered:
        fname = f.get("file_name", "unknown")
        by_file.setdefault(fname, []).append(f)

    # Sort files, sort findings within each file by severity desc then line
    for fname in sorted(by_file.keys()):
        file_findings = sorted(
            by_file[fname],
            key=lambda x: (-severity_order.get(x.get("severity", "info"), 0), x.get("line", 0)),
        )

        print(_c("bold", f"  ── {fname} "))

        for f in file_findings:
            sev = f.get("severity", "info").lower()
            sym = SEVERITY_SYMBOLS.get(sev, "?")
            color = SEVERITY_COLORS.get(sev, "dim")
            line_num = f.get("line", "?")
            title = f.get("rule_title", f.get("vulnerability_type", "Unknown"))
            cwe = f.get("cwe", "")
            occurrence_count = f.get("occurrence_count", 1)

            # PART 4: Show aggregated occurrence count
            count_suffix = ""
            if occurrence_count > 1:
                count_suffix = f"  ({occurrence_count} occurrences)"

            print(
                f"    {_c(color, sym)} {_c(color, sev.upper()):<12} "
                f"L{line_num:<6} {title}"
                + (f"  ({cwe})" if cwe else "")
                + _c("dim", count_suffix)
            )

            # Show affected lines for aggregated findings
            affected_lines = f.get("affected_lines", [])
            if len(affected_lines) > 1:
                lines_str = ", ".join(f"L{l}" for l in affected_lines[:10])
                if len(affected_lines) > 10:
                    lines_str += f" ... +{len(affected_lines) - 10} more"
                print(f"      {_c('dim', f'Lines: {lines_str}')}")

            snippet = f.get("code_snippet", "")
            if snippet:
                # Show first line of snippet, trimmed
                first_line = snippet.strip().split("\n")[0][:80]
                print(f"      {_c('dim', first_line)}")

        print()


def print_summary(findings: List[Dict], elapsed_sec: float, files_scanned: int) -> None:
    """Print final summary table."""
    severity_order = ["critical", "high", "medium", "low", "info"]
    counts = Counter(f.get("severity", "info").lower() for f in findings)

    print(_c("bold", "  Summary"))
    print(f"  {'─' * 50}")
    print(f"  Files scanned  : {files_scanned}")
    print(f"  Time elapsed   : {elapsed_sec:.1f}s")
    print(f"  Total findings : {len(findings)}")
    print()

    for sev in severity_order:
        count = counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "dim")
            print(f"    {_c(color, sev.upper()):<16} {count}")

    print()
