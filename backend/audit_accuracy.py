"""
Real-World Accuracy Audit — identifies root causes of low accuracy.

Scans actual code files, analyzes findings, and identifies:
1. False Positives (flagged but safe code)
2. Pattern quality issues
3. Confidence miscalibration
4. Anti-pattern gaps
5. Context blindness
"""
import sys, os, time, json, re
from collections import Counter, defaultdict

sys.path.insert(0, '.')

from engine.models import EngineFinding, EngineRule
from engine.rule_loader import get_rule_index
from engine.worker import worker_init, worker_scan_file
from engine.file_classifier import classify_language

# ═══════════════════════════════════════════════════════════════════
# PART 1: Scan real files and collect raw findings
# ═══════════════════════════════════════════════════════════════════

print("=" * 70)
print("REAL-WORLD ACCURACY AUDIT")
print("=" * 70)

# Initialize worker (loads + compiles all rules)
worker_init()

# Load rules for info
rule_index = get_rule_index()
print(f"Rules loaded: {len(rule_index.all_rules)} across {len(rule_index.languages)} languages")

# Scan the backend engine itself (real Python code)
scan_targets = []
for root, dirs, files in os.walk("engine"):
    dirs[:] = [d for d in dirs if d != '__pycache__']
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            scan_targets.append(path)

for root, dirs, files in os.walk("app"):
    dirs[:] = [d for d in dirs if d != '__pycache__']
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            scan_targets.append(path)

print(f"Files to scan: {len(scan_targets)}")

all_findings = []
file_contents = {}

for path in scan_targets:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read()
    except Exception:
        continue

    if not content or len(content) > 500_000:
        continue

    lang = classify_language(path)
    if not lang:
        continue

    file_contents[path] = content
    # Use worker_scan_file which returns list of dicts
    finding_dicts = worker_scan_file(content, path, lang)
    for d in finding_dicts:
        try:
            all_findings.append(EngineFinding.from_dict(d))
        except Exception:
            pass

print(f"\nRaw findings: {len(all_findings)}")

# ═══════════════════════════════════════════════════════════════════
# PART 2: Classify findings by FP likelihood
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PART 2: FALSE POSITIVE ANALYSIS")
print("=" * 70)

# FP Pattern 1: Findings on import lines
import_fps = []
comment_fps = []
string_fps = []
docstring_fps = []
test_fps = []
dead_code_fps = []
normal_findings = []

for f in all_findings:
    content = file_contents.get(f.file_name, "")
    lines = content.splitlines()
    line_idx = f.line - 1

    if 0 <= line_idx < len(lines):
        line = lines[line_idx]
        stripped = line.strip()
        stripped_lower = stripped.lower()

        # Import line FP
        if any(stripped_lower.startswith(p) for p in ['import ', 'from ', 'require(', '#include']):
            import_fps.append(f)
            continue

        # Comment line FP
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            comment_fps.append(f)
            continue

        # Docstring / string literal FP
        if stripped.startswith('"""') or stripped.startswith("'''") or stripped.startswith('"') or stripped.startswith("'"):
            string_fps.append(f)
            continue

        # Inside a docstring (check if between triple quotes)
        in_docstring = False
        triple_count = 0
        for i in range(line_idx):
            l = lines[i]
            triple_count += l.count('"""') + l.count("'''")
        if triple_count % 2 == 1:
            docstring_fps.append(f)
            continue

    # Test file
    fname_lower = f.file_name.lower()
    if '/test' in fname_lower or '\\test' in fname_lower or fname_lower.endswith('_test.py'):
        test_fps.append(f)
        continue

    normal_findings.append(f)

print(f"\n--- FP Classification ---")
print(f"  Import-line FPs:    {len(import_fps):3d}  (flagging 'import X' lines)")
print(f"  Comment-line FPs:   {len(comment_fps):3d}  (flagging commented code)")
print(f"  String-literal FPs: {len(string_fps):3d}  (flagging strings/docs)")
print(f"  Docstring FPs:      {len(docstring_fps):3d}  (inside docstrings)")
print(f"  Test-file FPs:      {len(test_fps):3d}  (in test directories)")
print(f"  Normal findings:    {len(normal_findings):3d}  (potentially real)")
total_fp = len(import_fps) + len(comment_fps) + len(string_fps) + len(docstring_fps) + len(test_fps)
print(f"\n  ESTIMATED FP RATE:  {total_fp}/{len(all_findings)} = {total_fp*100/max(len(all_findings),1):.1f}%")

# ═══════════════════════════════════════════════════════════════════
# PART 3: Top FP-generating rules
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PART 3: TOP FP-GENERATING RULES")
print("=" * 70)

fp_by_rule = Counter()
for f in import_fps + comment_fps + string_fps + docstring_fps:
    fp_by_rule[f.rule_id] += 1

print("\nRules generating most FPs:")
for rule_id, count in fp_by_rule.most_common(20):
    # Find a sample finding for this rule
    sample = None
    for f in all_findings:
        if f.rule_id == rule_id:
            sample = f
            break
    desc = sample.rule_title if sample else ""
    sev = sample.severity if sample else ""
    print(f"  {rule_id:35s} | {count:3d} FPs | sev={sev:8s} | {desc[:50]}")

# ═══════════════════════════════════════════════════════════════════
# PART 4: Duplicate/overlapping findings
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PART 4: DUPLICATE FINDINGS")
print("=" * 70)

# Group by (file, line_range)
line_groups = defaultdict(list)
for f in all_findings:
    # Group findings within 3 lines of each other
    bucket = f.line // 3
    key = (f.file_name, bucket)
    line_groups[key].append(f)

dupe_groups = {k: v for k, v in line_groups.items() if len(v) > 1}
print(f"\nLines with multiple findings: {len(dupe_groups)}")
total_dupes = sum(len(v) - 1 for v in dupe_groups.values())
print(f"Total duplicate findings:     {total_dupes}")

# Show worst cases
print("\nWorst duplicate clusters:")
for key, group in sorted(dupe_groups.items(), key=lambda x: -len(x[1]))[:10]:
    fname = os.path.basename(key[0])
    lines = sorted(set(f.line for f in group))
    rules = [f.rule_id for f in group]
    print(f"  {fname}:{lines[0]}-{lines[-1]} | {len(group)} findings | rules: {', '.join(rules[:3])}...")

# ═══════════════════════════════════════════════════════════════════
# PART 5: Pattern quality issues
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PART 5: PATTERN QUALITY ISSUES")
print("=" * 70)

# Find rules that match too many times (noisy patterns)
matches_per_rule = Counter()
for f in all_findings:
    matches_per_rule[f.rule_id] += 1

noisy_rules = [(r, c) for r, c in matches_per_rule.most_common() if c > 10]
print(f"\nNoisy rules (>10 matches across codebase): {len(noisy_rules)}")
for rule_id, count in noisy_rules[:15]:
    sample = next((f for f in all_findings if f.rule_id == rule_id), None)
    title = sample.rule_title if sample else ""
    matched = sample.matched_pattern[:40] if sample else ""
    print(f"  {rule_id:35s} | {count:3d} matches | {matched}")

# ═══════════════════════════════════════════════════════════════════
# PART 6: Confidence calibration check
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PART 6: CONFIDENCE CALIBRATION")
print("=" * 70)

fp_findings = import_fps + comment_fps + string_fps + docstring_fps

high_conf_fps = [f for f in fp_findings if f.confidence > 80]
print(f"\nHigh-confidence (>80) FPs:  {len(high_conf_fps)} / {len(fp_findings)} total FPs")
print(f"These are the WORST accuracy problems - scanner is CONFIDENT but WRONG")

for f in high_conf_fps[:10]:
    content = file_contents.get(f.file_name, "")
    lines = content.splitlines()
    line_idx = f.line - 1
    line_text = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""
    print(f"  {f.rule_id:30s} | conf={f.confidence:5.1f} | {os.path.basename(f.file_name)}:{f.line}")
    print(f"    Line: {line_text[:80]}")

# ═══════════════════════════════════════════════════════════════════
# PART 7: Matched pattern analysis (what's actually being flagged)
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PART 7: WHAT'S BEING MATCHED (top matched strings)")
print("=" * 70)

match_counter = Counter()
for f in all_findings:
    # Normalize matched text
    mt = f.matched_pattern.strip()[:60] if f.matched_pattern else "(empty)"
    match_counter[mt] += 1

print("\nMost frequently matched patterns:")
for pattern, count in match_counter.most_common(20):
    # Check if this is FP or real
    is_fp = any(
        f.matched_pattern and f.matched_pattern.strip()[:60] == pattern
        for f in fp_findings
    )
    marker = " [FP]" if is_fp else ""
    print(f"  {count:3d}x | {pattern}{marker}")

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("ROOT CAUSE SUMMARY")
print("=" * 70)
print(f"""
TOTAL FINDINGS: {len(all_findings)}
ESTIMATED FPs:  {total_fp} ({total_fp*100/max(len(all_findings),1):.1f}%)
DUPLICATES:     {total_dupes}
NOISY RULES:    {len(noisy_rules)}

ROOT CAUSES:
1. IMPORT-LINE MATCHING:  {len(import_fps)} findings on import lines
2. COMMENT MATCHING:      {len(comment_fps)} findings in comments
3. STRING/DOCSTRING:      {len(string_fps) + len(docstring_fps)} findings in strings/docstrings
4. DUPLICATE ALERTS:      {total_dupes} redundant findings
5. NOISY RULES:           {len(noisy_rules)} rules with >10 matches each
6. HIGH-CONF FPs:         {len(high_conf_fps)} wrong + confident findings
""")
