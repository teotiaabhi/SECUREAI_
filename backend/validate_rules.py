"""Phase 10 — Validate all rules load."""
import sys, time, re
from collections import Counter

sys.path.insert(0, ".")
from engine.rule_loader import get_rule_index

start = time.perf_counter()
idx = get_rule_index()
load_time = time.perf_counter() - start

stats = idx.stats if isinstance(idx.stats, dict) else idx.stats()
total = stats["total"]
print(f"Rules loaded: {total}")
print(f"Languages: {stats['languages']}")
print(f"Categories: {stats['categories']}")
print(f"Universal: {stats['universal']}")
print(f"Load time: {load_time:.3f}s")
print()

# Count by category
cat_counts = Counter(r.category for r in idx.all_rules)
for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {cnt}")
print()

# Check for duplicate rule_ids
ids = [r.rule_id for r in idx.all_rules]
dupes = [rid for rid in set(ids) if ids.count(rid) > 1]
if dupes:
    print(f"DUPLICATE RULE IDs: {dupes}")
else:
    print(f"No duplicate rule IDs (all {len(ids)} unique)")
print()

# Verify new rule files loaded
new_ids = [
    "INJ-NOSQL-PY-001", "INJ-SSTI-PY-001", "INJ-CRLF-JAVA-001",
    "AUTH-JWT-001", "AUTH-RACE-001", "AUTH-IDOR-001",
    "DESER-JAVA-002", "DESER-CS-002",
    "SUPPLY-DEP-001", "SUPPLY-LOCK-001",
    "CLOUD-IAM-001", "CLOUD-K8S-001",
    "CICD-PIPE-001", "CICD-GHA-002", "CICD-SLESS-001",
    "CORR-CHAIN-001", "CORR-CHAIN-003",
    "BIZ-RATE-001", "BIZ-PAY-001", "BIZ-FLOW-001",
]
found = sum(1 for r in idx.all_rules if r.rule_id in new_ids)
print(f"Spot-check: {found}/{len(new_ids)} new rule IDs found in index")
print()

# Test pattern compilation
errors = []
for r in idx.all_rules:
    for pat_str, flags in r.pattern_strings:
        try:
            re.compile(pat_str, flags)
        except re.error as e:
            errors.append((r.rule_id, str(e)[:80]))
if errors:
    print(f"REGEX ERRORS ({len(errors)}):")
    for rid, err in errors[:20]:
        print(f"  {rid}: {err}")
else:
    print("All patterns compile successfully")
