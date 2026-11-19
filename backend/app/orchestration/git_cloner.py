"""
SecureGitCloner — shallow-clone Git repos with security hardening.

Security measures:
- Shallow clone (--depth 1) to minimize data transfer
- Token never appears in logs (sanitized error messages)
- GIT_TERMINAL_PROMPT=0 prevents interactive auth
- Post-clone size check against configurable limit
- .git directory removed after clone
- Timeout enforcement via asyncio.wait_for
"""

import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("orchestration.git_cloner")


class GitCloneError(Exception):
    """Raised when git clone fails."""
    pass


class GitCloneSizeError(GitCloneError):
    """Raised when cloned repo exceeds size limit."""
    pass


class GitCloneTimeoutError(GitCloneError):
    """Raised when clone exceeds timeout."""
    pass


class SecureGitCloner:
    """Secure Git repository cloner with hardened defaults.

    Supports per-repo commit-based caching: when cache_dir is set and a
    specific commit is requested, the cloned tree (sans .git) is stored
    under {cache_dir}/{owner_repo}/{commit_sha[:12]}/. Subsequent clones
    for the same commit copy from cache instead of hitting the network.

    Uses subprocess.run via asyncio.to_thread for Windows compatibility.
    On Windows, uvicorn --reload workers use SelectorEventLoop which does
    NOT support asyncio.create_subprocess_exec (NotImplementedError).
    """

    def __init__(
        self,
        timeout: int = 120,
        max_size_mb: int = 500,
        temp_dir: Optional[str] = None,
        cache_dir: Optional[str] = None,
    ):
        self._timeout = timeout
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._temp_dir = temp_dir
        self._cache_dir = cache_dir

    @staticmethod
    def _safe_repo_name(url: str) -> str:
        """Extract owner/repo for safe logging (no tokens)."""
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        parts = path.split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}/{parts[-1]}"
        return parts[-1] if parts else "unknown"

    @staticmethod
    def _inject_token(url: str, token: str) -> str:
        """Inject auth token into HTTPS URL."""
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http"):
            raise GitCloneError(f"Unsupported scheme: {parsed.scheme}")
        authed = parsed._replace(
            netloc=f"oauth2:{token}@{parsed.hostname}"
            + (f":{parsed.port}" if parsed.port else "")
        )
        return authed.geturl()

    @staticmethod
    def _sanitize_error(message: str, token: Optional[str] = None) -> str:
        """Remove tokens/credentials from error messages."""
        sanitized = message
        if token:
            sanitized = sanitized.replace(token, "***")
        # Remove any URL with credentials
        sanitized = re.sub(
            r"https?://[^@]+@", "https://***@", sanitized
        )
        return sanitized

    @staticmethod
    def _get_dir_size(path: str) -> int:
        """Calculate total size of a directory in bytes."""
        total = 0
        for dirpath, _dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
        return total

    def _cache_path(self, url: str, commit: str) -> Optional[str]:
        """Build a cache directory path for the given repo + commit.

        Returns None if caching is disabled.
        Structure: {cache_dir}/{owner_repo}/{commit_sha[:12]}/
        """
        if not self._cache_dir or not commit:
            return None
        safe = self._safe_repo_name(url).replace("/", "_").replace("\\", "_")
        return os.path.join(self._cache_dir, safe, commit[:12])

    @staticmethod
    def _run_git(args: list[str], env: dict, timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess:
        """Run a git command synchronously (called via asyncio.to_thread).

        Uses subprocess.run which works on all Windows event loop policies,
        unlike asyncio.create_subprocess_exec which requires ProactorEventLoop.
        """
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            timeout=timeout,
        )

    async def clone(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        github_token: Optional[str] = None,
        tag: Optional[str] = None,
        commit: Optional[str] = None,
    ) -> str:
        """Clone a git repository securely.

        If caching is enabled and a commit SHA is specified, checks the
        per-repo/commit cache first. On cache hit, copies the cached tree
        to a temp dir (much faster than a network clone). On cache miss,
        clones normally and stores the result in cache for future use.

        Returns the path to the cloned directory.
        Raises GitCloneError on failure.
        """
        safe_name = self._safe_repo_name(repo_url)
        logger.info("[CLONE] started: %s", safe_name)
        base_dir = self._temp_dir or tempfile.gettempdir()
        start_time = time.time()

        # ── Cache check ──────────────────────────────────────────
        cached = self._cache_path(repo_url, commit or "")
        if cached and os.path.isdir(cached) and os.listdir(cached):
            clone_dir = tempfile.mkdtemp(prefix="scan-clone-", dir=base_dir)
            try:
                await asyncio.to_thread(
                    shutil.copytree, cached, clone_dir, dirs_exist_ok=True,
                )
                logger.info(
                    "Cache hit: %s @ %s (%s)",
                    safe_name, commit[:8], cached,
                )
                return clone_dir
            except Exception as exc:
                logger.warning("Cache copy failed, falling through to clone: %s", exc)
                shutil.rmtree(clone_dir, ignore_errors=True)

        # ── Network clone ────────────────────────────────────────
        clone_url = repo_url
        if github_token:
            clone_url = self._inject_token(repo_url, github_token)

        clone_dir = tempfile.mkdtemp(prefix="scan-clone-", dir=base_dir)

        clone_args = [
            "git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--recurse-submodules=no"
        ]
        logger.info("[CLONE] shallow clone enabled")
        if branch:
            clone_args.extend(["--branch", branch])
        elif tag:
            clone_args.extend(["--branch", tag])
        clone_args.extend([clone_url, clone_dir])

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = ""
        env["GIT_LFS_SKIP_SMUDGE"] = "1"

        try:
            result = await asyncio.to_thread(
                self._run_git, clone_args, env, self._timeout,
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode("utf-8", errors="replace").strip()
                shutil.rmtree(clone_dir, ignore_errors=True)
                logger.error("[CLONE] failed: %s", self._sanitize_error(error_msg, github_token))
                raise GitCloneError(
                    f"Clone failed for {safe_name}: "
                    f"{self._sanitize_error(error_msg, github_token)}"
                )

        except subprocess.TimeoutExpired:
            shutil.rmtree(clone_dir, ignore_errors=True)
            logger.error("[CLONE] timeout after %ds", self._timeout)
            raise GitCloneTimeoutError(
                f"Clone timed out after {self._timeout}s for {safe_name}"
            )
        except OSError as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            logger.error("[CLONE] error: %s", self._sanitize_error(str(exc), github_token))
            raise GitCloneError(
                f"Clone failed for {safe_name}: "
                f"{self._sanitize_error(str(exc), github_token)}"
            ) from exc

        # Checkout specific commit if requested
        if commit:
            try:
                await asyncio.to_thread(
                    self._run_git,
                    ["git", "fetch", "--depth", "1", "origin", commit],
                    env, 30, clone_dir,
                )
                await asyncio.to_thread(
                    self._run_git,
                    ["git", "checkout", commit],
                    env, 10, clone_dir,
                )
            except Exception as exc:
                logger.warning(
                    "Commit checkout failed for %s/%s: %s",
                    safe_name, commit[:8], exc,
                )

        # Post-clone size check
        clone_size = await asyncio.to_thread(self._get_dir_size, clone_dir)
        if clone_size > self._max_size_bytes:
            shutil.rmtree(clone_dir, ignore_errors=True)
            size_mb = clone_size / (1024 * 1024)
            limit_mb = self._max_size_bytes / (1024 * 1024)
            logger.error("[CLONE] repo size %.1fMB exceeds limit (%dMB)", size_mb, limit_mb)
            raise GitCloneSizeError(
                f"Clone of {safe_name} is {size_mb:.0f}MB, "
                f"exceeds {limit_mb:.0f}MB limit"
            )

        elapsed = time.time() - start_time
        logger.info("[CLONE] completed in %.2fs", elapsed)

        # Remove .git directory to save space and prevent code execution
        git_dir = os.path.join(clone_dir, ".git")
        if os.path.isdir(git_dir):
            await asyncio.to_thread(shutil.rmtree, git_dir, True)

        logger.info(
            "Clone complete: %s (%d bytes)", safe_name, clone_size,
        )

        # ── Populate cache ───────────────────────────────────────
        if cached:
            try:
                os.makedirs(os.path.dirname(cached), exist_ok=True)
                await asyncio.to_thread(
                    shutil.copytree, clone_dir, cached, dirs_exist_ok=True,
                )
                logger.info("Cached clone: %s @ %s", safe_name, commit[:8])
            except Exception as exc:
                logger.warning("Failed to cache clone for %s: %s", safe_name, exc)

        return clone_dir


