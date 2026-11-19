"""Scan the project and list all vulnerabilities by language."""
import os
import time
from collections import Counter
from dataclasses import dataclass
from engine.pipeline import scan_files
from engine.file_classifier import classify_language, should_skip_file


@dataclass
class FakeFile:
    filename: str
    content: str
    extension: str
    path: str = ""


# Walk the project and build IngestedFile-like objects
project_root = r"c:\Users\Admin\Desktop\security"
skip_dirs = {
    "node_modules", ".git", "__pycache__", ".next", "venv", "env",
    ".venv", "dist", "build", ".mypy_cache", ".pytest_cache",
}

files = []
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

        if not content.strip():
            continue

        ext = os.path.splitext(fn)[1]
        files.append(FakeFile(filename=rel, content=content, extension=ext, path=rel))


def main():
    print(f"Project: {project_root}")
print(f"Files to scan: {len(files)}")
print("=" * 70)

start = time.time()
results = scan_files(files)
elapsed = time.time() - start

print(f"Scan completed in {elapsed:.1f}s")
print(f"Total vulnerabilities found: {len(results)}")

by_sev = Counter()
by_lang = Counter()
by_cat = Counter()
by_rule = Counter()
details = []

lang_map = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby",
    ".php": "PHP", ".rs": "Rust", ".cs": "C#", ".sh": "Shell",
    ".sql": "SQL", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
    ".jsx": "JavaScript", ".mjs": "JavaScript",
}

for r in results:
    d = r if isinstance(r, dict) else r.__dict__
    sev = d.get("severity", "?")
    by_sev[sev] += 1
    ext = os.path.splitext(d.get("file_name", ""))[1].lower()
    by_lang[lang_map.get(ext, ext or "other")] += 1
    by_cat[d.get("category", "?")] += 1
    rid = d.get("rule_id", "?")
    by_rule[rid] += 1
    details.append(d)

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
for i, d in enumerate(details):
    sev = d.get("severity", "?").upper()
    rid = d.get("rule_id", "?")
    fname = d.get("file_name", "?")
    line = d.get("line", "?")
    title = d.get("rule_title", d.get("title", "?"))
    print(f"  {i+1:3}. [{sev:8}] {rid:35} {fname}:{line}")
    print(f"       -> {title}")

print()
print("SCAN COMPLETE.")


if __name__ == "__main__":
    main()
