"""
Fix framework_misuse/laravel_symfony.yaml - double-quoted strings with invalid YAML escapes.

In YAML double-quoted strings, \s, \w, \d etc. are NOT valid escape sequences.
PyYAML throws "unknown escape character" on these.

Fix: In double-quoted string values, replace bare \s with \\s, \w with \\w, etc.
Uses a function-based re.sub to avoid backreference issues.
"""
import re
import yaml

fpath = "rules/framework_misuse/laravel_symfony.yaml"

with open(fpath, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Match a bare backslash followed by s/w/d/S/W/D (not preceded by another backslash)
INVALID_ESCAPE = re.compile(r'(?<!\\)\\([swdSWD])')

def fix_escape(m):
    """Replace \\s with \\\\s (add extra backslash)."""
    return '\\\\' + m.group(1)

fixes = 0
for i, line in enumerate(lines):
    stripped = line.rstrip('\n')

    # Detect double-quoted string values
    # Pattern: leading whitespace + optional (key: or - ) + "..."
    m = re.match(r'^(\s*(?:-\s+|\w+:\s+)?)(".*")\s*$', stripped)
    if not m:
        continue

    prefix = m.group(1)
    quoted_str = m.group(2)

    # Check if it has invalid escapes
    if not INVALID_ESCAPE.search(quoted_str):
        continue

    # Fix using function-based replacement
    fixed_str = INVALID_ESCAPE.sub(fix_escape, quoted_str)

    if fixed_str != quoted_str:
        lines[i] = prefix + fixed_str + '\n'
        fixes += 1
        old_short = quoted_str[:120]
        new_short = fixed_str[:120]
        print(f"  Line {i+1}: {old_short}")
        print(f"        -> {new_short}")

print(f"\nTotal lines fixed: {fixes}")

with open(fpath, "w", encoding="utf-8") as f:
    f.writelines(lines)

# Verify YAML parse
try:
    with open(fpath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f.read())
    if data:
        rules_list = data.get("rules", [])
        print(f"\nYAML parse: OK ({len(rules_list)} rules loaded)")

        # Count patterns
        total_patterns = 0
        for rule in rules_list:
            patterns = rule.get("patterns", [])
            total_patterns += len(patterns)
        print(f"Total patterns: {total_patterns}")
    else:
        print("\nYAML parse: OK (but empty)")
except yaml.YAMLError as e:
    print(f"\nYAML parse ERROR: {e}")
    if hasattr(e, "problem_mark") and e.problem_mark:
        mark = e.problem_mark
        with open(fpath, "r", encoding="utf-8") as f:
            file_lines = f.readlines()
        ln = mark.line
        print(f"\nContext around line {ln + 1}:")
        for j in range(max(0, ln - 2), min(len(file_lines), ln + 3)):
            marker = ">>>" if j == ln else "   "
            print(f"  {marker} {j+1:4d}: {file_lines[j].rstrip()[:150]}")
