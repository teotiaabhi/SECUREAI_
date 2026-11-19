"""OpenAI Codex CLI integration utilities.

Provides helpers for:
- Checking/installing the Codex CLI (`@openai/codex`)
- Running Codex analysis via subprocess (headless mode)
- Enhancing SAST findings with actual source-code lines
- Parsing structured JSON from Codex output

Note: Codex CLI uses its own auth (`codex auth`) — no API key needed.
Users sign in with their ChatGPT account (free tier works).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple


# ── Safe print for Windows consoles ──────────────────────────────────

def _safe_print(text: str) -> None:
    """Print text, replacing chars that can't be encoded on Windows cp1252."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


# ── Codex availability ───────────────────────────────────────────────


def _get_codex_cmd() -> Optional[str]:
    """Find the codex executable, handling Windows .cmd wrappers."""
    # Try direct lookup
    cmd = shutil.which("codex")
    if cmd:
        return cmd
    # Windows: npm installs as codex.cmd
    cmd = shutil.which("codex.cmd")
    if cmd:
        return cmd
    # Check common npm global path on Windows
    npm_global = os.path.join(
        os.environ.get("APPDATA", ""), "npm", "codex.cmd"
    )
    if os.path.isfile(npm_global):
        return npm_global
    return None


def check_codex_installed() -> bool:
    """Return True if the `codex` CLI is on PATH and runnable."""
    cmd = _get_codex_cmd()
    if cmd is None:
        return False
    try:
        result = subprocess.run(
            [cmd, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=(sys.platform == "win32"),
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def install_codex() -> Tuple[bool, str]:
    """Attempt to install `@openai/codex` globally via npm.

    Returns:
        (success: bool, message: str)
    """
    npm = shutil.which("npm")
    if npm is None:
        return False, (
            "npm not found. Install Node.js 22+ first, then run:\n"
            "  npm install -g @openai/codex"
        )

    try:
        result = subprocess.run(
            ["npm", "install", "-g", "@openai/codex"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, "OpenAI Codex CLI installed successfully."
        return False, f"npm install failed:\n{result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "npm install timed out after 120 seconds."
    except OSError as exc:
        return False, f"Failed to run npm: {exc}"


def check_codex_auth() -> bool:
    """Check if Codex CLI is authenticated (user has run `codex auth`)."""
    try:
        result = subprocess.run(
            ["codex", "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # If codex runs at all, auth is handled by the CLI itself
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


# ── Finding enhancement ─────────────────────────────────────────────


def _read_source_line(file_path: str, line_no: int) -> Optional[str]:
    """Read a single line from a source file (1-indexed)."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if i == line_no:
                    return line.rstrip("\r\n")
    except (OSError, IOError):
        pass
    return None


def enhance_findings_with_code(
    findings: List[Dict],
    scan_target: str,
) -> List[Dict]:
    """Enrich each finding dict with the actual source-code line.

    Adds ``source_line`` (the verbatim code) and ``code_context`` (a
    human-readable string combining file, line number, code, and finding
    title) to every finding where the source file is readable.
    """
    enhanced: List[Dict] = []
    for finding in findings:
        f = dict(finding)  # shallow copy
        file_name = f.get("file_name", "")
        line_no = f.get("line")

        if file_name and line_no:
            abs_path = os.path.join(scan_target, file_name)
            source_line = _read_source_line(abs_path, int(line_no))
            if source_line is not None:
                f["source_line"] = source_line
                f["code_context"] = (
                    f"File: {file_name}, Line {line_no}: {source_line}\n"
                    f"  -> Finding: {f.get('rule_title', 'Unknown')} "
                    f"[{f.get('severity', 'info').upper()}] "
                    f"({f.get('cwe', 'N/A')})"
                )

        enhanced.append(f)

    return enhanced


# ── Codex invocation ─────────────────────────────────────────────────

_CODEX_SYSTEM_PROMPT = """\
You are an expert application-security engineer performing a secondary \
review of SAST (Static Application Security Testing) findings.

You will receive a JSON array of vulnerability findings. Each finding \
contains:
- rule_id, rule_title, severity, confidence
- file_name, line (line number in the source file)
- source_line (the actual code at that line)
- code_snippet (surrounding context)
- description, impact, remediation

Your task:
1. Analyze each finding against its source_line and code_snippet.
2. Determine if the finding is a TRUE POSITIVE (genuine vulnerability) \
or a FALSE POSITIVE (benign code incorrectly flagged).
3. For false positives, explain WHY it is not a real vulnerability.
4. Return ONLY the true-positive findings as a JSON array.

Rules:
- Be precise. Migration SQL files with ALTER TABLE in a migration script \
are NOT SQL injection - they are static DDL.
- Dataclass/model definitions named "Session" are NOT auth bypass.
- Route handlers with Depends(get_current_user) already have auth checks.
- Code in comments or docstring examples is NOT a vulnerability.
- Variable assignments like `token = None` followed by proper validation \
are NOT vulnerabilities.

Return a JSON object with this exact schema:
{
  "validated_findings": [ ...only true-positive finding dicts... ],
  "removed_findings": [
    {
      "rule_id": "...",
      "file_name": "...",
      "line": N,
      "reason": "Why this is a false positive"
    }
  ],
  "summary": {
    "total_reviewed": N,
    "true_positives": N,
    "false_positives_removed": N
  }
}

Return ONLY valid JSON. No markdown fences, no commentary outside JSON.
"""


def run_codex_analysis(
    findings: List[Dict],
    timeout_sec: int = 180,
) -> Tuple[bool, Dict[str, Any]]:
    """Send findings to Codex CLI for false-positive analysis.

    Uses Codex directly via subprocess. Codex handles its own auth
    (user signs in via `codex auth` with ChatGPT account, free tier works).

    Args:
        findings: Enhanced finding dicts (with source_line).
        timeout_sec: Max seconds to wait for Codex.

    Returns:
        (success, result_dict) -- on failure result_dict has an "error" key.
    """
    if not check_codex_installed():
        return False, {"error": "Codex CLI is not installed."}

    codex_cmd = _get_codex_cmd()

    # Prepare input -- strip heavy fields to stay within context limits
    slim_findings = []
    for f in findings:
        slim = {
            "rule_id": f.get("rule_id", ""),
            "rule_title": f.get("rule_title", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", 0),
            "file_name": f.get("file_name", ""),
            "line": f.get("line", 0),
            "source_line": f.get("source_line", ""),
            "code_snippet": f.get("code_snippet", "")[:500],
            "description": f.get("description", "")[:300],
            "cwe": f.get("cwe", ""),
            "matched_pattern": f.get("matched_pattern", "")[:200],
        }
        slim_findings.append(slim)

    findings_json = json.dumps(slim_findings, indent=2)

    # Write findings to a temp file for codex to read
    tmp_dir = tempfile.mkdtemp(prefix="secureai_codex_")
    input_path = os.path.join(tmp_dir, "findings_input.json")
    with open(input_path, "w", encoding="utf-8") as fh:
        fh.write(findings_json)

    prompt = (
        f"Review these {len(slim_findings)} SAST security findings and "
        f"remove false positives. The findings are in: {input_path}\n\n"
        f"Here are the findings:\n\n{findings_json}"
    )

    _is_win = sys.platform == "win32"

    try:
        # Try codex exec mode first (headless)
        result = subprocess.run(
            [
                codex_cmd,
                "exec",
                "--prompt", prompt,
                "--system-prompt", _CODEX_SYSTEM_PROMPT,
                "--output-format", "json",
                "--approval-mode", "auto-edit",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            shell=_is_win,
        )

        if result.returncode != 0:
            # Fallback: simpler invocation
            result = subprocess.run(
                [
                    codex_cmd,
                    "--quiet",
                    prompt,
                ],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                shell=_is_win,
            )

        output = result.stdout.strip()
        if not output:
            output = result.stderr.strip()

        parsed = parse_codex_response(output)
        if parsed is not None:
            return True, parsed

        return False, {
            "error": "Could not parse Codex response as JSON.",
            "raw_output": output[:2000],
        }

    except subprocess.TimeoutExpired:
        return False, {"error": f"Codex timed out after {timeout_sec}s."}
    except OSError as exc:
        return False, {"error": f"Failed to invoke Codex: {exc}"}
    finally:
        # Clean up temp file
        try:
            os.remove(input_path)
            os.rmdir(tmp_dir)
        except OSError:
            pass


def parse_codex_response(raw: str) -> Optional[Dict[str, Any]]:
    """Extract the JSON object from Codex output.

    Handles cases where Codex wraps JSON in markdown fences or adds
    commentary around it.
    """
    if not raw:
        return None

    # Try direct parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code fences
    fence_match = re.search(r"```(?:json)?\s*\n(.*?)\n```", raw, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding the first { ... } block
    brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    return None
