"""Accuracy analysis script — identifies improvement opportunities."""
import yaml, os, glob, re, json
from collections import Counter, defaultdict

rules_dir = "rules"
all_rules = []

for f in glob.glob(os.path.join(rules_dir, "**", "*.yaml"), recursive=True):
    try:
        with open(f, encoding="utf-8", errors="replace") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        continue
    if not data or "rules" not in data:
        continue
    for r in data["rules"]:
        all_rules.append(r)

# Analysis 1: Short patterns
print("=" * 60)
print("ANALYSIS 1: Short Patterns (< 15 chars) — High FP Risk")
print("=" * 60)
short = []
for r in all_rules:
    for p in r.get("patterns", []):
        pat = p.get("pattern", "")
        if len(pat) < 15 and pat:
            short.append((r["rule_id"], r["language"], pat))
for rid, lang, pat in sorted(short, key=lambda x: len(x[2])):
    print(f"  {rid:35s} | {lang:12s} | {pat!r} ({len(pat)} chars)")
print(f"\nTotal: {len(short)} short patterns")

# Analysis 2: Overlapping rules (same CWE + same language)
print("\n" + "=" * 60)
print("ANALYSIS 2: Rule Overlap (same CWE + language)")
print("=" * 60)
cwe_lang = defaultdict(list)
for r in all_rules:
    key = (r.get("cwe", ""), r.get("language", ""))
    if key[0]:
        cwe_lang[key].append(r["rule_id"])
overlaps = {k: v for k, v in cwe_lang.items() if len(v) > 3}
for (cwe, lang), rids in sorted(overlaps.items(), key=lambda x: -len(x[1]))[:15]:
    print(f"  {cwe:10s} | {lang:12s} | {len(rids)} rules: {', '.join(rids[:4])}...")
print(f"\nOverlapping groups (>3 rules same CWE+lang): {len(overlaps)}")

# Analysis 3: Anti-pattern quality
print("\n" + "=" * 60)
print("ANALYSIS 3: Anti-Pattern Quality")
print("=" * 60)
weak_anti = []
for r in all_rules:
    aps = r.get("anti_patterns", [])
    if aps and all(len(str(a)) < 5 for a in aps):
        weak_anti.append((r["rule_id"], aps))
print(f"Rules with very short anti-patterns (<5 chars): {len(weak_anti)}")
for rid, aps in weak_anti[:10]:
    print(f"  {rid}: {aps}")

# Analysis 4: Pattern complexity (simple patterns that catch too much)
print("\n" + "=" * 60)
print("ANALYSIS 4: Overly Broad Patterns (high FP risk)")
print("=" * 60)
broad = []
BROAD_INDICATORS = [r".*", r".+", r"\w+", r"\s*\("]
for r in all_rules:
    for p in r.get("patterns", []):
        pat = p.get("pattern", "")
        # Check for patterns that are basically just a function name
        if re.match(r'^\\?\w+\(?$', pat.replace("\\s*", "").replace("\\(", "(")):
            broad.append((r["rule_id"], r["language"], pat))
for rid, lang, pat in broad[:15]:
    print(f"  {rid:35s} | {lang:12s} | {pat!r}")
print(f"\nTotal overly broad: {len(broad)}")

# Analysis 5: Confidence distribution
print("\n" + "=" * 60)
print("ANALYSIS 5: Confidence Distribution")
print("=" * 60)
conf_dist = Counter()
for r in all_rules:
    c = r.get("confidence", 0)
    bucket = f"{int(c*10)*10}-{int(c*10)*10+9}%"
    conf_dist[bucket] += 1
for bucket in sorted(conf_dist.keys()):
    print(f"  {bucket:10s}: {conf_dist[bucket]:3d} rules")

# Analysis 6: Missing context requirements
print("\n" + "=" * 60)
print("ANALYSIS 6: Rules that SHOULD have context gating but don't")
print("=" * 60)
ctx_candidates = []
for r in all_rules:
    rid = r["rule_id"]
    title = r.get("title", "").lower()
    desc = r.get("description", "").lower()
    # Rules about web-specific vulns that should require route context
    if any(kw in title for kw in ["injection", "xss", "csrf", "ssrf", "idor"]):
        if r.get("confidence", 0) > 0.8:
            ctx_candidates.append((rid, r["language"], r.get("confidence", 0), r.get("title", "")))
print(f"High-confidence web vuln rules without context gating: {len(ctx_candidates)}")
for rid, lang, conf, title in ctx_candidates[:10]:
    print(f"  {rid:35s} | {lang:12s} | conf={conf:.2f} | {title[:50]}")

print("\n" + "=" * 60)
print("SUMMARY: Key Accuracy Improvement Areas")
print("=" * 60)
print(f"1. Short patterns (FP risk):        {len(short)}")
print(f"2. Rule overlap (duplicate alerts):  {len(overlaps)} groups")
print(f"3. Weak anti-patterns:               {len(weak_anti)}")
print(f"4. Overly broad patterns:            {len(broad)}")
print(f"5. Context gating candidates:        {len(ctx_candidates)}")
