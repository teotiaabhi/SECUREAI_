#!/usr/bin/env python3
"""
SecureAI Code Analyzer — CLI Entry Point.

Production-grade SAST scanner for local codebases.

Usage:
    secureai scan <path> [options]
    secureai scan <path> --ai          AI-powered scan with Codex
    secureai rules [options]
    secureai version
"""

import argparse
import sys

from cli import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secureai",
        description="SecureAI Code Analyzer — Static Application Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  secureai scan .                        Scan current directory\n"
            "  secureai scan ./src --severity high     Only high+ severity\n"
            "  secureai scan ./app -o report.json      Custom report path\n"
            "  secureai scan . --lang python,java      Filter by language\n"
            "  secureai scan . --ai                    AI scan with Codex FP removal\n"
            "  secureai rules                          List all loaded rules\n"
            "  secureai rules --lang python             Rules for Python only\n"
            "  secureai version                        Show version info\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ──────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory or file for security vulnerabilities",
    )
    scan_parser.add_argument(
        "path",
        help="Path to file or directory to scan",
    )
    scan_parser.add_argument(
        "-o", "--output",
        default="secureai-report.json",
        help="Output report path (default: secureai-report.json)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity threshold to report",
    )
    scan_parser.add_argument(
        "--lang",
        default=None,
        help="Comma-separated list of languages to scan (e.g. python,javascript)",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON to stdout (no terminal formatting)",
    )
    scan_parser.add_argument(
        "--no-progress",
        action="store_true",
        default=False,
        help="Disable progress output during scan",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers (default: auto)",
    )
    scan_parser.add_argument(
        "--confidence-threshold",
        choices=["low", "medium", "high"],
        default="medium",
        help="Minimum confidence level to report (default: medium)",
    )
    scan_parser.add_argument(
        "--show-low-confidence",
        action="store_true",
        default=False,
        help="Include low-confidence findings in output",
    )
    scan_parser.add_argument(
        "--debug-rule",
        default=None,
        metavar="RULE_ID",
        help="Debug a specific rule (shows detailed analysis for all matches)",
    )
    scan_parser.add_argument(
        "--debug-file",
        default=None,
        metavar="FILE_PATH",
        help="Limit debug output to a specific file (use with --debug-rule)",
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        default=False,
        help="Enable AI-powered scan with OpenAI Codex false-positive removal",
    )
    scan_parser.add_argument(
        "--ai-timeout",
        type=int,
        default=180,
        help="Timeout in seconds for Codex AI analysis (default: 180)",
    )

    # ── rules ─────────────────────────────────────────────────────────
    rules_parser = subparsers.add_parser(
        "rules",
        help="List available security rules",
    )
    rules_parser.add_argument(
        "--lang",
        default=None,
        help="Filter rules by language",
    )
    rules_parser.add_argument(
        "--severity",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Filter rules by severity",
    )
    rules_parser.add_argument(
        "--category",
        default=None,
        help="Filter rules by category",
    )

    # ── version ───────────────────────────────────────────────────────
    subparsers.add_parser("version", help="Show version information")

    return parser


def main() -> int:
    """CLI main entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        from cli.commands.version_command import run_version
        return run_version()

    if args.command == "rules":
        from cli.commands.rules_command import run_rules
        return run_rules(
            lang=args.lang,
            severity=args.severity,
            category=args.category,
        )

    if args.command == "scan":
        # Check if AI mode requested (--ai flag or path is literally "ai")
        use_ai = getattr(args, "ai", False)

        # Support "secureai scan ai ." as alias for "secureai scan . --ai"
        if args.path == "ai":
            # Shift: treat next positional as actual path
            remaining = [a for a in sys.argv[sys.argv.index("ai") + 1:] if not a.startswith("-")]
            actual_path = remaining[0] if remaining else "."
            args.path = actual_path
            use_ai = True

        if use_ai:
            from cli.commands.scan_ai_command import run_scan_ai
            return run_scan_ai(
                path=args.path,
                output=args.output if args.output != "secureai-report.json" else "secureai-ai-report.json",
                severity=args.severity,
                lang=args.lang,
                json_output=args.json,
                show_progress=not args.no_progress,
                workers=args.workers,
                confidence_threshold=args.confidence_threshold,
                show_low_confidence=args.show_low_confidence,
                timeout=args.ai_timeout,
            )

        from cli.commands.scan_command import run_scan
        return run_scan(
            path=args.path,
            output=args.output,
            severity=args.severity,
            lang=args.lang,
            json_output=args.json,
            show_progress=not args.no_progress,
            workers=args.workers,
            confidence_threshold=args.confidence_threshold,
            show_low_confidence=args.show_low_confidence,
            debug_rule=args.debug_rule,
            debug_file=args.debug_file,
        )

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
