"""Direct scan — bypasses ProcessPoolExecutor for Windows compat."""
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass


def main():
    from engine.rule_loader import get_rule_index
    from engine.worker import worker_init, worker_scan_file
    from engine.file_classifier import classify_language, should_skip_file
    from engine.models import EngineFinding
    from engine.rule_intelligence import apply_rule_intelligence
    from engine.logic_detectors import apply_logic_detectors
    from engine.clustering import cluster_findings
    from engine.confidence_calibration import calibrate_confidence
    from engine.deduplication import deduplicate_findings
    from engine.exploit_chains import detect_exploit_chains
    from engine.severity import apply_severity_normalization

    project_root = r"c:\Users\Admin\Desktop\security"
    skip_dirs = {
        "node_modules", ".git", "__pycache__", ".next", "venv", "env",
        ".venv", "dist", "build", ".mypy_cache", ".pytest_cache",
    }

    # 1. Collect files
    scan_jobs = []
    for root, dirs, filenames in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fn in filenames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, project_root)
            if should_skip_file(rel):
                continue
            lang = classify_language(rel)
            if not lang:
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            if content.strip():
                scan_jobs.append((content, rel, lang))

    # 2. Load + init rules (worker_init loads from disk, no serialization)
    ri = get_rule_index()

    worker_init()

    print(f"Project: {project_root}")
    print(f"Files to scan: {len(scan_jobs)}")
    print(f"Rules loaded: {len(ri.all_rules)}")
    print(f"Languages: {sorted(ri.languages)}")
    print("=" * 70)

    # 3. Scan all files (in-process)
    start = time.time()
    all_dicts = []
    for content, fname, lang in scan_jobs:
        dicts = worker_scan_file(content, fname, lang)
        all_dicts.extend(dicts)

    # 4. Reconstruct + pipeline
    findings = [EngineFinding.from_dict(d) for d in all_dicts if d]
    file_contents = {fname: content for content, fname, _lang in scan_jobs}
    findings = apply_rule_intelligence(findings, ri, file_contents)
    findings = apply_logic_detectors(findings, file_contents)
    findings = cluster_findings(findings)
    findings = calibrate_confidence(findings)
    findings = deduplicate_findings(findings)
    findings = detect_exploit_chains(findings)
    findings = apply_severity_normalization(findings)

    elapsed = time.time() - start
    print(f"Scan completed in {elapsed:.1f}s")
    print(f"Total vulnerabilities found: {len(findings)}")

    # 5. Analyze
    by_sev = Counter()
    by_lang = Counter()
    by_cat = Counter()
    by_rule = Counter()

    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby",
        ".php": "PHP", ".rs": "Rust", ".cs": "C#", ".sh": "Shell",
        ".sql": "SQL", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
        ".jsx": "JavaScript", ".mjs": "JavaScript", ".mts": "TypeScript",
        ".ini": "YAML", "": "other",
    }

    for f in findings:
        by_sev[f.severity] += 1
        ext = os.path.splitext(f.file_name)[1].lower()
        by_lang[lang_map.get(ext, ext)] += 1
        by_cat[f.category] += 1
        by_rule[f.rule_id] += 1

    print()
    print("=== SEVERITY BREAKDOWN ===")
    for s in ["critical", "high", "medium", "low", "info"]:
        if by_sev[s]:
            print(f"  {s.upper():10}: {by_sev[s]}")

    print()
    print("=== LANGUAGES WITH VULNERABILITIES ===")
    for lang, cnt in by_lang.most_common():
        print(f"  {lang:15}: {cnt}")

    print()
    print("=== CATEGORIES ===")
    for cat, cnt in by_cat.most_common(15):
        print(f"  {cat:35}: {cnt}")

    print()
    print("=== TOP 25 RULES TRIGGERED ===")
    for rule, cnt in by_rule.most_common(25):
        print(f"  {rule:40}: {cnt}")

    print()
    print("=== FULL VULNERABILITY LIST ===")
    for i, f in enumerate(findings):
        print(f"  {i+1:3}. [{f.severity.upper():8}] {f.rule_id:35} {f.file_name}:{f.line}")
        print(f"       -> {f.rule_title}")

    print()
    print("SCAN COMPLETE.")


if __name__ == "__main__":
    main()
