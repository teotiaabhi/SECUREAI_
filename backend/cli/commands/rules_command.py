"""secureai rules — list available security rules."""

from typing import Optional


def run_rules(
    lang: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
) -> int:
    """Print loaded rules, optionally filtered."""
    from engine.rule_loader import get_rule_index

    rule_index = get_rule_index()
    rules = rule_index.all_rules

    # Apply filters
    if lang:
        lang_lower = lang.lower()
        rules = [r for r in rules if r.language == lang_lower]
    if severity:
        sev_lower = severity.lower()
        rules = [r for r in rules if r.severity == sev_lower]
    if category:
        cat_lower = category.lower()
        rules = [r for r in rules if r.category.lower() == cat_lower]

    if not rules:
        print("No rules match the given filters.")
        return 0

    # Sort by language then severity weight descending
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    rules.sort(key=lambda r: (r.language, -severity_order.get(r.severity, 0)))

    # Print header
    print(f"{'RULE ID':<30} {'SEVERITY':<10} {'LANGUAGE':<15} {'CATEGORY':<20} TITLE")
    print("-" * 120)

    for r in rules:
        print(
            f"{r.rule_id:<30} {r.severity.upper():<10} {r.language:<15} "
            f"{r.category:<20} {r.title[:50]}"
        )

    print(f"\nTotal: {len(rules)} rules")
    return 0
