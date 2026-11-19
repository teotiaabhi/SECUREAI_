"""
PR Comment Service — post scan delta summaries to GitHub pull requests.

Creates or updates a GitHub PR comment with a structured security scan
summary including new/fixed/unchanged findings, regression alerts, and
risk/severity indicators.

Fails gracefully: never crashes the scan pipeline. Logs errors but does
not raise fatal exceptions to the caller.

No orchestration logic. No baseline management. No delta computation.
"""

from typing import Optional

import httpx

from app.core.logging import get_logger
from app.core.config import get_settings
from app.services.delta_engine import DeltaResult

logger = get_logger("pr_comment_service")

# Hidden HTML marker for identifying/updating existing bot comments
BOT_COMMENT_MARKER = "<!-- secureai-scan-report -->"

# Severity ordering for threshold checks and "highest severity" display
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_LABELS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}


# ── Comment Formatting ──────────────────────────────────────

def _highest_severity(severity_summary: dict) -> str:
    """Determine the highest severity among new findings."""
    highest = 0
    for sev, count in severity_summary.items():
        if count > 0:
            level = _SEVERITY_ORDER.get(sev, 0)
            if level > highest:
                highest = level
    return _SEVERITY_LABELS.get(highest, "None")


def _compute_risk_score(delta: DeltaResult) -> float:
    """Compute a simple risk score from the delta.

    Weighted sum: critical=10, high=5, medium=2, low=0.5, info=0.
    Capped at 100.
    """
    weights = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}
    score = 0.0
    for f in delta.new_findings:
        score += weights.get(f.severity, 0.0)
    return min(score, 100.0)


def format_pr_comment(delta: DeltaResult, scan_url: str = "") -> str:
    """Generate GitHub-flavored markdown comment body for a PR.

    Args:
        delta: DeltaResult from delta_engine.compute_delta().
        scan_url: URL to the full scan report (optional).

    Returns:
        Markdown string for the PR comment.
    """
    new_count = delta.new_count
    fixed_count = delta.fixed_count
    unchanged_count = delta.unchanged_count
    regression = delta.regression_detected
    severity_summary = delta.severity_summary
    highest_sev = _highest_severity(severity_summary)
    risk_score = _compute_risk_score(delta)

    # Status header
    if regression:
        status_icon = "REGRESSION DETECTED"
        status_line = (
            "**Regression detected** — new critical/high severity "
            "vulnerabilities found."
        )
    elif new_count == 0 and fixed_count > 0:
        status_icon = "IMPROVED"
        status_line = (
            "Security posture improved — vulnerabilities fixed "
            "with no new issues."
        )
    elif new_count == 0:
        status_icon = "PASSED"
        status_line = "No new vulnerabilities introduced."
    else:
        status_icon = "FINDINGS"
        status_line = f"{new_count} new vulnerability(ies) detected."

    lines = [
        BOT_COMMENT_MARKER,
        f"## Security Scan Report — {status_icon}",
        "",
        status_line,
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| New vulnerabilities | {new_count} |",
        f"| Fixed vulnerabilities | {fixed_count} |",
        f"| Unchanged | {unchanged_count} |",
        f"| Highest Severity | {highest_sev} |",
        f"| Risk Score | {risk_score:.1f} |",
        f"| Regression detected | {'Yes' if regression else 'No'} |",
    ]

    # Severity breakdown for new findings
    if severity_summary:
        lines.append("")
        lines.append("### New Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_summary.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.capitalize()} | {count} |")

    # New findings detail (top 15)
    if delta.new_findings:
        lines.append("")
        lines.append("### New Findings")
        lines.append("")
        lines.append("| Severity | File | Type |")
        lines.append("|----------|------|------|")
        for finding in delta.new_findings[:15]:
            sev = finding.severity.capitalize()
            fname = finding.file_name
            vtype = finding.vulnerability_type
            lines.append(f"| {sev} | `{fname}` | {vtype} |")
        if len(delta.new_findings) > 15:
            remaining = len(delta.new_findings) - 15
            lines.append(f"| ... | *{remaining} more* | |")

    # Fixed findings summary (top 10)
    if delta.fixed_findings:
        lines.append("")
        lines.append(f"### Fixed Findings ({fixed_count})")
        lines.append("")
        for finding in delta.fixed_findings[:10]:
            fname = finding.file_name
            vtype = finding.vulnerability_type
            lines.append(f"- ~~`{fname}` — {vtype}~~")
        if len(delta.fixed_findings) > 10:
            remaining = len(delta.fixed_findings) - 10
            lines.append(f"- *...and {remaining} more*")

    # Link to full report
    if scan_url:
        lines.append("")
        lines.append(f"[View full report]({scan_url})")

    lines.append("")
    lines.append("---")
    lines.append("*Automated by SecureAI Code Analyzer*")

    return "\n".join(lines)


# ── Find Existing Bot Comment ──────────────────────────────

async def _find_existing_comment(
    client: httpx.AsyncClient,
    token: str,
    repo_full_name: str,
    pr_number: int,
    api_base: str,
) -> Optional[int]:
    """Find an existing bot comment on a PR by the marker string.

    Returns:
        Comment ID if found, None otherwise.
    """
    try:
        resp = await client.get(
            f"{api_base}/repos/{repo_full_name}/issues/{pr_number}/comments",
            params={"per_page": 50},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        resp.raise_for_status()
        comments = resp.json()

        for comment in comments:
            body = comment.get("body", "")
            if BOT_COMMENT_MARKER in body:
                return comment["id"]

    except Exception:
        # Non-fatal: if we can't find existing, we'll just create a new one
        pass

    return None


# ── Post / Update PR Comment ───────────────────────────────

async def post_pr_comment(
    token: str,
    repo_full_name: str,
    pr_number: int,
    delta: DeltaResult,
    scan_url: str = "",
) -> Optional[str]:
    """Post or update a scan results comment on a GitHub pull request.

    Checks for an existing bot comment (identified by BOT_COMMENT_MARKER)
    and updates it instead of creating duplicates.

    Respects config settings:
    - PR_COMMENT_ENABLED: master toggle
    - PR_COMMENT_MIN_SEVERITY: only comment if new findings meet threshold
    - GITHUB_COMMENT_TIMEOUT_SECONDS: HTTP timeout for API calls
    - GITHUB_API_BASE: API base URL

    Fails gracefully: logs errors but never raises to the caller.

    Args:
        token: GitHub installation or user access token.
        repo_full_name: Repository full name (owner/repo).
        pr_number: Pull request number.
        delta: DeltaResult from delta_engine.compute_delta().
        scan_url: URL to the full scan report.

    Returns:
        URL of the created/updated comment, or None on failure/skip.
    """
    settings = get_settings()

    # Master toggle
    if not settings.PR_COMMENT_ENABLED:
        logger.info("pr_comment_disabled", repo=repo_full_name, pr=pr_number)
        return None

    # Severity threshold check
    min_severity = settings.PR_COMMENT_MIN_SEVERITY
    min_level = _SEVERITY_ORDER.get(min_severity, 2)

    has_reportable = any(
        _SEVERITY_ORDER.get(f.severity, 0) >= min_level
        for f in delta.new_findings
    )

    # Always comment if there are no new findings (to show "clear" status)
    # or if there are fixed findings (to show improvement). Skip only when
    # there ARE new findings but none meet the severity threshold.
    if not has_reportable and delta.new_findings:
        logger.info(
            "pr_comment_below_threshold",
            repo=repo_full_name,
            pr=pr_number,
            min_severity=min_severity,
        )
        return None

    body = format_pr_comment(delta, scan_url)
    api_base = settings.GITHUB_API_BASE
    timeout = float(settings.GITHUB_COMMENT_TIMEOUT_SECONDS)

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            # Check for existing bot comment to update
            existing_comment_id = await _find_existing_comment(
                client, token, repo_full_name, pr_number, api_base
            )

            if existing_comment_id:
                # Update existing comment
                resp = await client.patch(
                    f"{api_base}/repos/{repo_full_name}/issues/comments/{existing_comment_id}",
                    json={"body": body},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                resp.raise_for_status()
                comment_url = resp.json().get("html_url", "")
                logger.info(
                    "pr_comment_updated",
                    repo=repo_full_name,
                    pr=pr_number,
                    comment_id=existing_comment_id,
                )
            else:
                # Create new comment
                resp = await client.post(
                    f"{api_base}/repos/{repo_full_name}/issues/{pr_number}/comments",
                    json={"body": body},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                resp.raise_for_status()
                comment_url = resp.json().get("html_url", "")
                logger.info(
                    "pr_comment_created",
                    repo=repo_full_name,
                    pr=pr_number,
                )

            return comment_url

        except httpx.TimeoutException:
            logger.error(
                "pr_comment_timeout",
                repo=repo_full_name,
                pr=pr_number,
                timeout=timeout,
            )
            return None
        except httpx.HTTPStatusError as exc:
            logger.error(
                "pr_comment_http_error",
                repo=repo_full_name,
                pr=pr_number,
                status=exc.response.status_code,
                detail=exc.response.text[:200],
            )
            return None
        except Exception as exc:
            logger.error(
                "pr_comment_error",
                repo=repo_full_name,
                pr=pr_number,
                error=str(exc),
            )
            return None
