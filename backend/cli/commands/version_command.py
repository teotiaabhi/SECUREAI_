"""secureai version — display version and engine info."""

import sys

from cli import __version__


def run_version() -> int:
    """Print version info and exit."""
    from engine.rule_loader import get_rule_index

    rule_index = get_rule_index()
    stats = rule_index.stats

    print(f"SecureAI Code Analyzer v{__version__}")
    print(f"  Rules loaded : {stats['total']}")
    print(f"  Languages    : {stats['languages']}")
    print(f"  Categories   : {stats['categories']}")
    print(f"  Python       : {sys.version.split()[0]}")
    return 0
