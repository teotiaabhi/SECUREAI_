"""
Fix corrupted framework_misuse/laravel_symfony.yaml

The file was corrupted by a bad fix script that replaced all bare \s
(and \S) in double-quoted YAML strings with \\\1 (literal) instead of \\s.

This script:
1. Replaces [\\\1\\\1] with [\\s\\S] (character class for any char)
2. Replaces remaining \\\1 with \\s (whitespace metachar)
3. Fixes bare \. in double-quoted strings -> \\.
4. Verifies YAML parse
"""
import yaml

fpath = "rules/framework_misuse/laravel_symfony.yaml"

with open(fpath, "r", encoding="utf-8") as f:
    content = f.read()

# Step 1: Fix character classes [\\\1\\\1] -> [\\s\\S]
# These represent [\s\S] (match any character including newline)
# In the raw file, \\\1 is 4 chars: \, \, \, 1
# We need [\\s\\S] which is [, \, \, s, \, \, S, ]
old_charclass = "[\\\\\\\\\\\\1\\\\\\\\\\\\1]"  # [\\\1\\\1] in raw file
new_charclass = "[\\\\s\\\\S]"  # [\\s\\S] in raw file

count1 = content.count("\\\\\\\u0031")  # Count raw \\\1
print(f"Total \\\\\\\\1 occurrences before fix: {count1}")

# Actually, let me work directly with the raw bytes
# In the file, what we see as \\\1 is the characters: backslash backslash backslash 1
# Let me use a simpler approach - just read and do string replacement

# The corrupted pattern in the file is literally these 4 bytes: \ \ \ 1
bad_pattern = "\\\\\\\x31"  # \\\1 as raw characters: \\\ then 1
# Actually let me just use the literal
bad = "\\\\\\1"  # This Python string literal is 4 chars: \, \, \, 1
good = "\\\\s"   # This Python string literal is 3 chars: \, \, s

# First handle the [\\\1\\\1] -> [\\s\\S] case
# [\\\1\\\1] is 10 chars: [, \, \, \, 1, \, \, \, 1, ]
bad_cc = "[" + bad + bad + "]"  # [\\\1\\\1] - 10 chars
good_cc = "[\\\\s\\\\S]"        # [\\s\\S] - 8 chars

count_cc = content.count(bad_cc)
print(f"Character class [\\\\\\\\1\\\\\\\\1] occurrences: {count_cc}")
content = content.replace(bad_cc, good_cc)
print(f"  -> Replaced {count_cc} character class patterns with [\\\\s\\\\S]")

# Step 2: Replace remaining \\\1 with \\s
count_bare = content.count(bad)
print(f"Remaining \\\\\\\\1 occurrences: {count_bare}")
content = content.replace(bad, good)
print(f"  -> Replaced {count_bare} bare patterns with \\\\s")

# Step 3: Fix \. in double-quoted YAML strings (lines 614, 632)
# 'kernel\.debug' inside a double-quoted YAML string
# \. is not a valid YAML escape in double-quoted strings
# Need to change to \\.
# But only in double-quoted pattern strings, not in single-quoted ones

lines = content.split("\n")
dot_fixes = 0
for i, line in enumerate(lines):
    stripped = line.strip()
    # Only fix double-quoted strings containing 'kernel\.debug'
    if 'kernel\\.debug' in stripped:
        continue  # Already fixed
    if "kernel\\.debug" in stripped:
        continue  # Already uses proper escaping
    if "kernel\\.debug" in line:
        continue
    # Check for bare \. in double-quoted values
    if '"' in stripped and "kernel\\.debug" not in stripped and "kernel\\.debug" not in line:
        # Look for pattern values or anti-pattern values in double-quoted strings
        if ("kernel\\.debug" in line):
            continue
        # Check if this line has a DQ string with kernel\.debug
        import re
        dq_match = re.search(r'"[^"]*kernel\\\.debug[^"]*"', line)
        if dq_match:
            # Found kernel\.debug inside double quotes - fix \. to \\.
            old_str = dq_match.group(0)
            new_str = old_str.replace("kernel\\.debug", "kernel\\\\.debug")
            lines[i] = line.replace(old_str, new_str)
            dot_fixes += 1
            print(f"  Line {i+1}: Fixed \\. -> \\\\. in kernel.debug pattern")

# Hmm, the above logic is getting complicated. Let me take a simpler approach.
# Just scan for specific known patterns.

content2 = "\n".join(lines)

# Actually, let me directly fix the known problematic lines.
# In the current content after steps 1-2, lines 614 and 632 will have:
#   "'kernel\.debug'\\s*=>\\s*true"  and  "'kernel\.debug'\\s*=>\\s*false"
# The \. needs to become \\.

# In double-quoted YAML, kernel\.debug has \. which is invalid
# Fix: kernel\\.debug  (\\. = literal \.)
old_dot1 = "\"'kernel\\.debug'\\\\s*=>\\\\s*true\""
new_dot1 = "\"'kernel\\\\.debug'\\\\s*=>\\\\s*true\""

old_dot2 = "\"'kernel\\.debug'\\\\s*=>\\\\s*false\""
new_dot2 = "\"'kernel\\\\.debug'\\\\s*=>\\\\s*false\""

if old_dot1 in content2:
    content2 = content2.replace(old_dot1, new_dot1)
    dot_fixes += 1
    print(f"  Fixed kernel\\.debug -> kernel\\\\.debug in pattern (true)")

if old_dot2 in content2:
    content2 = content2.replace(old_dot2, new_dot2)
    dot_fixes += 1
    print(f"  Fixed kernel\\.debug -> kernel\\\\.debug in anti-pattern (false)")

print(f"Step 3: Fixed {dot_fixes} bare \\. escapes")

with open(fpath, "w", encoding="utf-8") as f:
    f.write(content2)

# Step 4: Verify YAML parse
try:
    with open(fpath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f.read())
    if data:
        rules_list = data.get("rules", [])
        print(f"\nYAML parse: OK ({len(rules_list)} rules loaded)")
        for rule in rules_list:
            rid = rule.get("rule_id", "?")
            patterns = rule.get("patterns", [])
            print(f"  {rid}: {len(patterns)} patterns")
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
