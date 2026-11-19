"""
Diff Detector Service — detect changed files between commits via GitHub API.

Fetches changed files for diff scanning using the GitHub compare API.
Supports GitHub App JWT authentication with installation token exchange.
Applies safety limits (max files, fallback thresholds) and filters
binary/removed files.

No DB writes. No scan creation. No orchestration logic.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from app.core.logging import get_logger
from app.core.config import get_settings
from app.services.circuit_breaker import github_api_breaker, CircuitBreakerOpen

logger = get_logger("diff_detector")

# Binary / non-code extensions to skip
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".lock", ".sum",
    ".pyc", ".pyo", ".class", ".wasm",
})


# ── Exception ───────────────────────────────────────────────

class DiffDetectionError(Exception):
    """Raised when diff detection fails (API error, timeout, auth failure)."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        self.status_code = status_code
        super().__init__(message)


# ── Structured Result ───────────────────────────────────────

@dataclass
class DiffResult:
    """Structured result from detect_changed_files()."""
    changed_files: List[str] = field(default_factory=list)
    total_changed: int = 0
    fallback_to_full: bool = False
    file_details: List[dict] = field(default_factory=list)


# ── GitHub App JWT Authentication ───────────────────────────

def _create_app_jwt(app_id: str, private_key_pem: str) -> str:
    """Create a short-lived JWT for GitHub App authentication.

    The JWT is valid for 10 minutes (GitHub's maximum).

    Args:
        app_id: GitHub App ID.
        private_key_pem: PEM-encoded RSA private key.

    Returns:
        Signed JWT string.

    Raises:
        DiffDetectionError: If key is missing or JWT creation fails.
    """
    if not app_id or not private_key_pem:
        raise DiffDetectionError(
            "GitHub App credentials not configured "
            "(GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY required)"
        )

    try:
        import jwt as pyjwt

        now = int(time.time())
        payload = {
            "iat": now - 60,        # Issued 60s ago (clock skew tolerance)
            "exp": now + (10 * 60), # Expires in 10 minutes
            "iss": app_id,
        }
        return pyjwt.encode(payload, private_key_pem, algorithm="RS256")
    except ImportError:
        raise DiffDetectionError(
            "PyJWT with cryptography backend required: "
            "pip install PyJWT[crypto]"
        )
    except Exception as exc:
        raise DiffDetectionError(f"JWT creation failed: {exc}")


async def get_installation_token(
    app_id: str,
    private_key_pem: str,
    installation_id: int,
    api_base: Optional[str] = None,
) -> str:
    """Exchange a GitHub App JWT for an installation access token.

    Args:
        app_id: GitHub App ID.
        private_key_pem: PEM-encoded RSA private key.
        installation_id: GitHub App installation ID (from webhook payload).
        api_base: GitHub API base URL (defaults to config value).

    Returns:
        Installation access token string.

    Raises:
        DiffDetectionError: On auth failure or HTTP error.
    """
    settings = get_settings()
    base = api_base or settings.GITHUB_API_BASE

    app_jwt = _create_app_jwt(app_id, private_key_pem)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{base}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 401:
                raise DiffDetectionError(
                    "GitHub App JWT authentication failed", status_code=401
                )
            resp.raise_for_status()
            token = resp.json().get("token", "")
            if not token:
                raise DiffDetectionError("Empty token in installation response")

            logger.info(
                "installation_token_acquired",
                installation_id=installation_id,
            )
            return token

    except httpx.TimeoutException:
        raise DiffDetectionError("Timeout acquiring installation token")
    except DiffDetectionError:
        raise
    except httpx.HTTPStatusError as exc:
        raise DiffDetectionError(
            f"GitHub API error: {exc.response.status_code}",
            status_code=exc.response.status_code,
        )


# ── File Filtering ──────────────────────────────────────────

def _is_binary(filename: str) -> bool:
    """Check if a filename has a binary / non-code extension."""
    if "." not in filename:
        return False
    ext = "." + filename.rsplit(".", 1)[-1].lower()
    return ext in _BINARY_EXTENSIONS


def _filter_scannable(raw_files: List[dict]) -> List[dict]:
    """Filter to scannable files: exclude removed and binary files.

    Args:
        raw_files: Raw file dicts from the GitHub compare API.

    Returns:
        Filtered list of file dicts.
    """
    scannable = []
    for f in raw_files:
        status = f.get("status", "")
        filename = f.get("filename", "")

        # Skip removed files — nothing to scan
        if status == "removed":
            continue

        # Skip binary / non-code files
        if _is_binary(filename):
            continue

        scannable.append(f)

    return scannable


# ── Compare API ─────────────────────────────────────────────

async def _fetch_compare(
    token: str,
    repo_full_name: str,
    base_sha: str,
    head_sha: str,
    api_base: str,
    timeout: float,
) -> List[dict]:
    """Fetch changed files via GET /repos/{owner}/{repo}/compare/{base}...{head}.

    Returns raw file dicts from the GitHub API response.

    Raises:
        DiffDetectionError: On API error or timeout.
    """
    url = f"{api_base}/repos/{repo_full_name}/compare/{base_sha}...{head_sha}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 404:
                raise DiffDetectionError(
                    f"Compare endpoint not found for {repo_full_name} "
                    f"({base_sha[:8]}...{head_sha[:8]})",
                    status_code=404,
                )
            resp.raise_for_status()
            data = resp.json()

    except httpx.TimeoutException:
        raise DiffDetectionError(
            f"Timeout fetching compare for {repo_full_name}"
        )
    except DiffDetectionError:
        raise
    except httpx.HTTPStatusError as exc:
        raise DiffDetectionError(
            f"GitHub compare API error: {exc.response.status_code}",
            status_code=exc.response.status_code,
        )

    raw_files = data.get("files", [])

    return [
        {
            "filename": f.get("filename", ""),
            "status": f.get("status", ""),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            "patch": f.get("patch", ""),
            "contents_url": f.get("contents_url", ""),
            "previous_filename": f.get("previous_filename"),
        }
        for f in raw_files
    ]


async def _fetch_pr_files(
    token: str,
    repo_full_name: str,
    pr_number: int,
    api_base: str,
    timeout: float,
    max_files: int,
) -> List[dict]:
    """Fetch changed files via GET /repos/{owner}/{repo}/pulls/{pr}/files.

    Paginates to collect all files up to max_files.

    Raises:
        DiffDetectionError: On API error or timeout.
    """
    changed_files: List[dict] = []
    page = 1
    per_page = 100

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            while len(changed_files) < max_files:
                resp = await client.get(
                    f"{api_base}/repos/{repo_full_name}/pulls/{pr_number}/files",
                    params={"per_page": per_page, "page": page},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                if resp.status_code == 404:
                    raise DiffDetectionError(
                        f"PR #{pr_number} not found for {repo_full_name}",
                        status_code=404,
                    )
                resp.raise_for_status()
                files = resp.json()

                if not files:
                    break

                for f in files:
                    changed_files.append({
                        "filename": f.get("filename", ""),
                        "status": f.get("status", ""),
                        "additions": f.get("additions", 0),
                        "deletions": f.get("deletions", 0),
                        "patch": f.get("patch", ""),
                        "contents_url": f.get("contents_url", ""),
                        "previous_filename": f.get("previous_filename"),
                    })

                if len(files) < per_page:
                    break
                page += 1

    except httpx.TimeoutException:
        raise DiffDetectionError(
            f"Timeout fetching PR files for {repo_full_name}#{pr_number}"
        )
    except DiffDetectionError:
        raise
    except httpx.HTTPStatusError as exc:
        raise DiffDetectionError(
            f"GitHub PR files API error: {exc.response.status_code}",
            status_code=exc.response.status_code,
        )

    return changed_files


# ── File Content Fetch ──────────────────────────────────────

async def fetch_file_at_ref(
    token: str,
    repo_full_name: str,
    file_path: str,
    ref: str,
    api_base: Optional[str] = None,
) -> Optional[str]:
    """Download a single file's content at a specific commit ref.

    Args:
        token: GitHub access token.
        repo_full_name: Repository full name (owner/repo).
        file_path: Path within the repo.
        ref: Git ref (SHA, branch, tag).
        api_base: Override API base URL.

    Returns:
        File content as string, or None if not found or binary.
    """
    settings = get_settings()
    base = api_base or settings.GITHUB_API_BASE

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{base}/repos/{repo_full_name}/contents/{file_path}",
                params={"ref": ref},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3.raw",
                },
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()

            content_type = resp.headers.get("content-type", "")
            if "application/octet-stream" in content_type:
                return None

            return resp.text

    except (httpx.TimeoutException, httpx.HTTPStatusError):
        logger.warning(
            "file_fetch_failed",
            repo=repo_full_name,
            file=file_path,
            ref=ref[:8],
        )
        return None


# ── Main Entrypoint ─────────────────────────────────────────

async def detect_changed_files(
    *,
    token: str,
    repo_full_name: str,
    base_sha: str,
    head_sha: str,
    pr_number: Optional[int] = None,
) -> DiffResult:
    """Detect files changed between two commits.

    Primary entrypoint for the diff detector. Fetches changed files,
    applies safety limits, and filters binary/removed files.

    Uses PR files API when pr_number is provided (more accurate).
    Falls back to compare API otherwise.

    Args:
        token: GitHub access token (installation or user token).
        repo_full_name: Repository full name (owner/repo).
        base_sha: Base commit SHA.
        head_sha: Head commit SHA.
        pr_number: PR number (optional; uses PR files API if provided).

    Returns:
        DiffResult with changed_files, total_changed, fallback_to_full.

    Raises:
        DiffDetectionError: On API failure or timeout.
    """
    settings = get_settings()
    api_base = settings.GITHUB_API_BASE
    timeout = float(settings.AI_REQUEST_TIMEOUT)
    max_files = settings.DIFF_SCAN_MAX_FILES
    fallback_threshold = settings.DIFF_FALLBACK_TO_FULL_THRESHOLD

    # Fetch raw changed files (circuit breaker wraps GitHub API calls)
    try:
        if pr_number is not None:
            raw_files = await github_api_breaker.execute(
                _fetch_pr_files,
                token, repo_full_name, pr_number,
                api_base, timeout, fallback_threshold + 1,
            )
        else:
            raw_files = await github_api_breaker.execute(
                _fetch_compare,
                token, repo_full_name, base_sha, head_sha,
                api_base, timeout,
            )
    except CircuitBreakerOpen as e:
        raise DiffDetectionError(
            f"GitHub API circuit breaker open — {e.name} retry after {e.retry_after:.0f}s"
        )

    total_raw = len(raw_files)

    # Safety: if above hard fallback threshold → full scan
    if total_raw > fallback_threshold and settings.DIFF_SCAN_FALLBACK_ENABLED:
        logger.info(
            "diff_fallback_to_full",
            repo=repo_full_name,
            total_changed=total_raw,
            threshold=fallback_threshold,
        )
        return DiffResult(
            changed_files=[],
            total_changed=total_raw,
            fallback_to_full=True,
        )

    # Filter binary and removed files
    scannable = _filter_scannable(raw_files)

    # Truncate to max_files if still too many
    truncated = scannable[:max_files] if len(scannable) > max_files else scannable

    filenames = [f["filename"] for f in truncated]

    logger.info(
        "diff_detected",
        repo=repo_full_name,
        total_raw=total_raw,
        scannable=len(scannable),
        returned=len(truncated),
        pr_number=pr_number,
    )

    return DiffResult(
        changed_files=filenames,
        total_changed=total_raw,
        fallback_to_full=False,
        file_details=truncated,
    )


# ── Backward-Compatible Aliases ─────────────────────────────
# The orchestrator currently imports these names directly.
# These wrappers maintain compatibility until the orchestrator
# is updated to use detect_changed_files() in Phase 6.

async def fetch_pr_changed_files(
    token: str,
    repo_full_name: str,
    pr_number: int,
) -> List[dict]:
    """Fetch changed files for a PR (backward-compatible wrapper)."""
    settings = get_settings()
    return await _fetch_pr_files(
        token, repo_full_name, pr_number,
        settings.GITHUB_API_BASE,
        float(settings.AI_REQUEST_TIMEOUT),
        max_files=settings.DIFF_FALLBACK_TO_FULL_THRESHOLD + 1,
    )


async def fetch_compare_files(
    token: str,
    repo_full_name: str,
    base_sha: str,
    head_sha: str,
) -> List[dict]:
    """Fetch changed files between commits (backward-compatible wrapper)."""
    settings = get_settings()
    return await _fetch_compare(
        token, repo_full_name, base_sha, head_sha,
        settings.GITHUB_API_BASE,
        float(settings.AI_REQUEST_TIMEOUT),
    )


def should_fallback_to_full(changed_files: List[dict], max_files: int) -> bool:
    """Check if diff is too large for diff scanning."""
    return len(changed_files) > max_files


def filter_scannable_files(changed_files: List[dict]) -> List[dict]:
    """Filter to scannable files (backward-compatible wrapper)."""
    return _filter_scannable(changed_files)
