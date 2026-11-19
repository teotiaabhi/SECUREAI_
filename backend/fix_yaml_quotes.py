"""
Fix corrupted injection/php.yaml - handles current state where:
1. Spaces after 'pattern:' are missing
2. '' was replaced with ' (undoing the original corruption but over-correcting)

Strategy:
- Add space after pattern: where missing
- For character classes ["\'] that break YAML, replace with ["'']
"""
import re
import yaml

fpath = "rules/injection/php.yaml"

with open(fpath, "r", encoding="utf-8") as f:
    content = f.read()

lines = content.split("\n")

# Step 1: Fix missing spaces after pattern:
space_fixes = 0
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("pattern:") and not stripped.startswith("pattern: "):
        # Missing space - add it back
        indent_end = len(line) - len(line.lstrip())
        lines[i] = line[:indent_end] + "pattern: " + stripped[len("pattern:"):]
        space_fixes += 1

print(f"Step 1: Fixed {space_fixes} missing spaces after pattern:")

# Step 2: Fix ["\'] character classes in single-quoted YAML strings
# The problem: in YAML single-quoted strings, ["\'] has \' which breaks quoting
# The fix: change \' to '' inside character classes
#
# We match: ["\'] or [^"\'] in the raw text and replace with ["''] or [^"'']
# These patterns have: [ then optionally ^ then " then \ then ' then ]
# We want:             [ then optionally ^ then " then ' then ' then ]

charclass_fixes = 0
# Match ["\'...] patterns - the key is finding the \' inside brackets
# Pattern: [ optionally ^ then " then \' then ]
charclass_re = re.compile(r'''(\[(?:\^)?")(\\')(])''')

for i, line in enumerate(lines):
    stripped = line.strip()
    # Only process pattern lines and context pattern lines
    if not ("pattern:" in stripped or (stripped.startswith("- '") and "\\" in stripped)):
        continue

    new_line = charclass_re.sub(r"\1''\3", line)
    if new_line != line:
        lines[i] = new_line
        charclass_fixes += 1
        # May have multiple instances on same line, loop
        while True:
            newer = charclass_re.sub(r"\1''\3", lines[i])
            if newer == lines[i]:
                break
            lines[i] = newer

print(f"Step 2: Fixed character classes on {charclass_fixes} lines")

content_out = "\n".join(lines)

with open(fpath, "w", encoding="utf-8") as f:
    f.write(content_out)

# Step 3: Verify
try:
    with open(fpath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f.read())
    if data:
        rules_list = data.get("rules", [])
        print(f"YAML parse: OK ({len(rules_list)} rules loaded)")
    else:
        print("YAML parse: OK (but empty)")
except yaml.YAMLError as e:
    print(f"YAML parse ERROR: {e}")
    if hasattr(e, "problem_mark") and e.problem_mark:
        mark = e.problem_mark
        file_lines = content_out.split("\n")
        ln = mark.line
        print(f"\nContext around line {ln + 1}:")
        for j in range(max(0, ln - 2), min(len(file_lines), ln + 3)):
            marker = ">>>" if j == ln else "   "
            print(f"  {marker} {j+1:4d}: {file_lines[j][:150]}")
