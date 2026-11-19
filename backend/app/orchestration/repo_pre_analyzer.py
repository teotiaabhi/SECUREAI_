"""
Repository Pre-Analyzer — fetch GitHub metadata *advisory only*.

All checks are best-effort: if the GitHub API is unreachable, returns
a rate-limit response, or errors for any reason, the precheck logs a
warning and returns a partial/empty PrecheckResult so the pipeline
can continue with cloning.

All HTTP calls use httpx with timeouts to avoid blocking the asyncio
event loop.

Logging prefix: [PRECHECK]
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("orchestration.repo_pre_analyzer")

# ── Defaults (overridden by Settings when called from the service layer) ──
DEFAULT_MAX_REPO_SIZE_MB = 1024       # 1 GB
DEFAULT_MAX_ESTIMATED_FILES = 50_000
API_TIMEOUT_SEC = 15                  # per-request timeout

# Regex to pull owner/repo from common GitHub URLs
_GITHUB_URL_RE = re.compile(
    r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+?)(?:\.git)?/?$"
)


@dataclass
class PrecheckResult:
    """Structured result of repository pre-analysis."""
    owner: str
    repo: str
    size_mb: float = 0.0
    default_branch: str = "main"
    languages: Dict[str, int] = field(default_factory=dict)
    estimated_files: int = 0
    has_large_files: bool = False
    large_file_paths: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def parse_github_url(url: str) -> Tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL.

    Supports:
        https://github.com/user/repo
        https://github.com/user/repo.git
        git@github.com:user/repo.git

    Returns (owner, repo) with no trailing '.git'.
    Raises ValueError if the URL cannot be parsed.
    """
    m = _GITHUB_URL_RE.search(url)
    if not m:
        raise ValueError(f"Cannot extract owner/repo from URL: {url}")
    return m.group("owner"), m.group("repo")


def _build_headers(token: Optional[str]) -> Dict[str, str]:
    """Build GitHub API request headers."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _is_rate_limited(resp: httpx.Response) -> bool:
    """Return True if GitHub returned a rate-limit response."""
    if resp.status_code in (403, 429):
        remaining = resp.headers.get("x-ratelimit-remaining", "")
        if remaining == "0" or resp.status_code == 429:
            return True
    return False


def _empty_result(owner: str, repo: str, warning: str) -> PrecheckResult:
    """Return a best-effort empty result with a recorded warning."""
    return PrecheckResult(owner=owner, repo=repo, warnings=[warning])


async def precheck_repository(
    owner: str,
    repo: str,
    token: Optional[str] = None,
    max_size_mb: int = DEFAULT_MAX_REPO_SIZE_MB,
    max_files: int = DEFAULT_MAX_ESTIMATED_FILES,
) -> PrecheckResult:
    """Fetch repo metadata from GitHub API — *advisory only*.

    This function **never raises**.  If any API call fails (network error,
    rate-limit, 404, etc.) it logs a warning and returns a partial
    PrecheckResult so the scan pipeline can continue with cloning.
    """
    headers = _build_headers(token)
    base = f"https://api.github.com/repos/{owner}/{repo}"
    warnings: List[str] = []

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT_SEC, headers=headers) as client:
            # ── 1. Repository metadata ───────────────────────────
            resp = await client.get(base)

            if _is_rate_limited(resp):
                msg = "GitHub API rate limit reached — continuing with clone"
                logger.warning("[PRECHECK] %s", msg)
                return _empty_result(owner, repo, msg)

            if resp.status_code == 404:
                msg = f"Repository {owner}/{repo} not found — continuing with clone"
                logger.warning("[PRECHECK] %s", msg)
                return _empty_result(owner, repo, msg)

            if resp.status_code >= 400:
                msg = f"repo metadata fetch failed (HTTP {resp.status_code}) — continuing with clone"
                logger.warning("[PRECHECK] %s", msg)
                return _empty_result(owner, repo, msg)

            data = resp.json()

            size_mb = data.get("size", 0) / 1024  # GitHub returns KB
            default_branch = data.get("default_branch", "main")

            logger.info("[PRECHECK] repo=%s/%s size=%.1fMB", owner, repo, size_mb)

            if size_mb > max_size_mb:
                msg = (
                    f"repo size {size_mb:.0f}MB exceeds {max_size_mb}MB limit "
                    f"— continuing with clone"
                )
                logger.warning("[PRECHECK] %s", msg)
                warnings.append(msg)

            # ── 2. Language distribution ─────────────────────────
            lang_resp = await client.get(f"{base}/languages")
            languages: Dict[str, int] = {}
            if _is_rate_limited(lang_resp):
                logger.warning("[PRECHECK] rate limit hit on /languages — skipping")
            elif lang_resp.status_code == 200:
                languages = lang_resp.json()

            logger.info(
                "[PRECHECK] languages detected: %s",
                list(languages.keys()) or ["unknown"],
            )

            # ── 3. Estimated file count via tree API ─────────────
            tree_url = (
                f"https://api.github.com/repos/{owner}/{repo}"
                f"/git/trees/{default_branch}?recursive=1"
            )
            tree_resp = await client.get(tree_url)
            estimated_files = 0
            has_large_files = False
            large_file_paths: List[str] = []

            if _is_rate_limited(tree_resp):
                logger.warning("[PRECHECK] rate limit hit on /git/trees — skipping")
            elif tree_resp.status_code == 200:
                tree_data = tree_resp.json()
                tree_items = tree_data.get("tree", [])
                estimated_files = len(tree_items)

                # Detect files > 10 MB (GitHub stores size for blobs)
                for item in tree_items:
                    if item.get("type") == "blob":
                        blob_size = item.get("size", 0)
                        if blob_size and blob_size > 10 * 1024 * 1024:
                            has_large_files = True
                            large_file_paths.append(item.get("path", ""))
                            if len(large_file_paths) >= 10:
                                break  # cap the list

            logger.info(
                "[PRECHECK] estimated file count: %d  large_files: %s",
                estimated_files, has_large_files,
            )

            if estimated_files > max_files:
                msg = (
                    f"estimated {estimated_files} files exceeds {max_files} limit "
                    f"— continuing with clone"
                )
                logger.warning("[PRECHECK] %s", msg)
                warnings.append(msg)

        return PrecheckResult(
            owner=owner,
            repo=repo,
            size_mb=size_mb,
            default_branch=default_branch,
            languages=languages,
            estimated_files=estimated_files,
            has_large_files=has_large_files,
            large_file_paths=large_file_paths,
            warnings=warnings,
        )

    except Exception as exc:
        msg = f"repo metadata fetch failed ({exc}) — continuing with clone"
        logger.warning("[PRECHECK] %s", msg)
        return _empty_result(owner, repo, msg)
