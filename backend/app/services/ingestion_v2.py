"""
RepoIngestionService — extended ingestion for repo-scale scanning.

Extends the existing ingestion module with:
- Git clone integration via SecureGitCloner
- Secure ZIP extraction via ZipExtractor
- Streaming directory walk for large repos
- File classification with security-critical priority
"""

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from typing import List, Optional

from app.services.ingestion import (
    IngestedFile,
    IGNORED_DIRS,
    IGNORED_EXTENSIONS,
    CODE_EXTENSIONS,
    _should_ignore,
    _is_code_file,
    _validate_file,
    _is_binary_file,
)
from app.core.config import get_settings
from app.orchestration.git_cloner import SecureGitCloner
from app.orchestration.zip_extractor import ZipExtractor

logger = logging.getLogger("ingestion_v2")

# Patterns that indicate security-critical files
SECURITY_CRITICAL_PATTERNS = {
    "auth", "login", "session", "token", "jwt", "crypto", "secret",
    "admin", "password", "middleware", "guard", "policy", "permission",
    "oauth", "saml", "cors", "csrf", "sanitize", "encrypt", "decrypt",
    "certificate", "credential", "apikey", "webhook",
}

# Config file patterns (priority 1)
CONFIG_PATTERNS = {
    ".env", "config", "settings", "docker-compose", "dockerfile",
    "nginx", "apache", "webpack", "babel", "tsconfig", "package.json",
    "requirements", "pipfile", "cargo.toml", "go.mod", "pom.xml",
    "build.gradle", "gemfile", "composer.json",
}

# Monorepo root-level directories that contain application source code
MONOREPO_SOURCE_DIRS = {"apps", "services", "packages", "modules", "libs", "projects"}

# Post-clone cleanup directories (superset of IGNORED_DIRS for aggressive cleanup)
POST_CLONE_REMOVE_DIRS = {
    "node_modules", "vendor", "dist", "build", "target", "coverage",
    ".git", "__pycache__", ".cache", ".next", ".nuxt",
}

# Repo size guard
MAX_EXTRACTED_SIZE_MB = 500

# File discovery limit
MAX_SCAN_FILES = 20000

# File size limit
MAX_FILE_SIZE_BYTES = 1_048_576

@dataclass
class ClassifiedFile:
    """A file with classification metadata for prioritized scanning."""
    ingested: IngestedFile
    language: str
    priority: int   # 0=security-critical, 1=config, 2=normal
    category: str   # "security", "config", "source", "template", etc.


class RepoIngestionService:
    """Extended ingestion service for repo-scale scanning."""

    def __init__(self):
        settings = get_settings()
        self._max_files = settings.MAX_FILES_PER_SCAN_LARGE
        self._max_file_size = settings.MAX_FILE_SIZE_MB * 1024 * 1024
        self._cloner = SecureGitCloner(
            timeout=settings.GIT_CLONE_TIMEOUT,
            max_size_mb=settings.GIT_CLONE_MAX_SIZE_MB,
            temp_dir=settings.SCAN_TEMP_DIR or None,
            cache_dir=settings.CLONE_CACHE_DIR or None,
        )
        self._extractor = ZipExtractor(
            max_extracted_size_mb=settings.ZIP_MAX_EXTRACTED_SIZE_MB,
            max_file_count=settings.ZIP_MAX_FILE_COUNT,
            max_compression_ratio=settings.ZIP_MAX_COMPRESSION_RATIO,
            temp_dir=settings.SCAN_TEMP_DIR or None,
        )

    async def ingest_git_clone(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        github_token: Optional[str] = None,
        tag: Optional[str] = None,
        commit: Optional[str] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> tuple:
        """Clone a git repo and ingest files.

        Returns:
            Tuple of (List[IngestedFile], temp_dir_path)
        """
        clone_dir = await self._cloner.clone(
            repo_url=repo_url,
            branch=branch,
            github_token=github_token,
            tag=tag,
            commit=commit,
        )

        files = await self._walk_directory_streaming(clone_dir, cancel_event)
        return files, clone_dir

    async def ingest_zip_secure(
        self,
        zip_path: str,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> tuple:
        """Extract a ZIP and ingest files securely.

        Returns:
            Tuple of (List[IngestedFile], temp_dir_path)
        """
        extract_dir = await self._extractor.extract(zip_path)
        files = await self._walk_directory_streaming(extract_dir, cancel_event)
        return files, extract_dir

    async def _walk_directory_streaming(
        self,
        root_dir: str,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> List[IngestedFile]:
        """Walk a directory and ingest code files.

        Uses asyncio.to_thread to avoid blocking the event loop.
        Respects IGNORED_DIRS, file count limits, and file size limits.
        """
        def _collect_paths() -> tuple:
            paths = []
            dirs_ignored = 0
            files_skipped_size = 0
            files_skipped_ignored = 0
            files_skipped_traversal = 0
            files_skipped_symlink = 0
            files_skipped_error = 0
            real_root = os.path.realpath(root_dir)
            for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
                # Part 5: Remove ignored directories and symlinked directories
                original_count = len(dirnames)
                removed_dirs = [
                    d for d in dirnames
                    if d in IGNORED_DIRS
                    or os.path.islink(os.path.join(dirpath, d))
                ]
                for d in removed_dirs:
                    rel_d = os.path.relpath(os.path.join(dirpath, d), root_dir)
                    logger.info("[SKIP] %s/ (ignored directory)", rel_d)
                dirnames[:] = [d for d in dirnames if d not in removed_dirs]
                dirs_ignored += len(removed_dirs)

                for fname in filenames:
                    # Part 2: file count limit
                    if len(paths) >= self._max_files:
                        logger.warning(
                            "walk_file_limit_reached: limit=%d dir=%s",
                            self._max_files, root_dir,
                        )
                        return paths, dirs_ignored, files_skipped_size, files_skipped_ignored, files_skipped_traversal, files_skipped_symlink, files_skipped_error

                    fpath = os.path.join(dirpath, fname)

                    # Skip symlinks
                    if os.path.islink(fpath):
                        logger.debug("walk_symlink_skipped: %s", fpath)
                        files_skipped_symlink += 1
                        continue

                    # Part 1: Validate resolved path stays under root_dir
                    real_path = os.path.realpath(fpath)
                    if not real_path.startswith(real_root):
                        logger.warning("walk_traversal_blocked: %s -> %s", fpath, real_path)
                        files_skipped_traversal += 1
                        continue

                    rel_path = os.path.relpath(fpath, root_dir)

                    if _should_ignore(rel_path):
                        logger.debug("[SKIP] %s (ignored path/extension)", rel_path)
                        files_skipped_ignored += 1
                        continue
                    if not _is_code_file(rel_path):
                        logger.debug("[SKIP] %s (unsupported file type)", rel_path)
                        files_skipped_ignored += 1
                        continue

                    try:
                        size = os.path.getsize(fpath)
                        # Part 3: file size limit
                        if size > self._max_file_size:
                            size_mb = size / (1024 * 1024)
                            logger.info(
                                "[SKIP] %s (%.1fMB > %dMB limit)",
                                rel_path, size_mb,
                                self._max_file_size // (1024 * 1024),
                            )
                            files_skipped_size += 1
                            continue
                        if size == 0:
                            continue
                    except OSError as exc:
                        logger.warning("walk_stat_error: %s — %s", fpath, exc)
                        files_skipped_error += 1
                        continue

                    paths.append(fpath)
            return paths, dirs_ignored, files_skipped_size, files_skipped_ignored, files_skipped_traversal, files_skipped_symlink, files_skipped_error

        result = await asyncio.to_thread(_collect_paths)
        file_paths = result[0]
        dirs_ignored = result[1]
        files_skipped_size = result[2]
        files_skipped_ignored = result[3]
        files_skipped_traversal = result[4]
        files_skipped_symlink = result[5]
        files_skipped_error = result[6]
        # Part 7: comprehensive summary logging
        logger.info(
            "walk_summary: found=%d dirs_ignored=%d "
            "skipped_size=%d skipped_ignored=%d "
            "skipped_traversal=%d skipped_symlink=%d skipped_error=%d dir=%s",
            len(file_paths), dirs_ignored,
            files_skipped_size, files_skipped_ignored,
            files_skipped_traversal, files_skipped_symlink, files_skipped_error,
            root_dir,
        )

        # Read files
        files: List[IngestedFile] = []
        binary_skipped = 0
        read_errors = 0
        for fpath in file_paths:
            if cancel_event and cancel_event.is_set():
                logger.info("Ingestion cancelled after %d files", len(files))
                break

            try:
                # Part 6: _read_file uses context managers internally
                content = await asyncio.to_thread(self._read_file, fpath)
                rel_path = os.path.relpath(fpath, root_dir)
                # Part 4: binary detection (returns None for binary)
                if content is None:
                    logger.info("[SKIP] %s (binary file)", rel_path)
                    binary_skipped += 1
                    continue

                ext = os.path.splitext(fpath)[1].lower()
                errors = _validate_file(content, rel_path)

                files.append(IngestedFile(
                    filename=os.path.basename(fpath),
                    path=rel_path.replace("\\", "/"),
                    extension=ext,
                    content=content,
                    size=len(content.encode("utf-8", errors="ignore")),
                    errors=errors,
                ))
            except Exception as exc:
                # Part 8: log error, continue scanning remaining files
                logger.warning("read_file_error: %s — %s", fpath, exc)
                read_errors += 1

        # Part 7: ingestion summary
        logger.info(
            "ingest_summary: ingested=%d binary_skipped=%d "
            "read_errors=%d dir=%s",
            len(files), binary_skipped, read_errors, root_dir,
        )
        return files

    @staticmethod
    def _read_file(path: str) -> Optional[str]:
        """Read a file and return its content as string, or None on failure.

        Part 4: Returns None for binary files (null-byte heuristic + magic bytes).
        Part 6: Uses context manager for file handle safety.
        """
        try:
            with open(path, "rb") as f:
                raw = f.read()
            # Part 4: Skip binary files
            if _is_binary_file(raw):
                logger.debug("binary_file_skipped: %s", path)
                return None
            return raw.decode("utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("read_file_failed: %s — %s", path, exc)
            return None

    def classify_and_filter(
        self, files: List[IngestedFile]
    ) -> List[ClassifiedFile]:
        """Classify files by language, priority, and category.

        Returns files sorted by priority (security-critical first).
        """
        from engine.file_classifier import classify_language

        classified: List[ClassifiedFile] = []

        for f in files:
            # Skip files with critical errors
            if f.errors:
                continue

            # Paste scans keep their display filename (for example, paste.txt)
            # while storing the selected language extension separately.
            classification_path = f.path or f.filename
            path_extension = os.path.splitext(classification_path)[1].lower()
            if f.extension and path_extension != f.extension.lower():
                classification_path = os.path.splitext(classification_path)[0] + f.extension

            # Detect language
            lang = classify_language(classification_path)
            if lang is None:
                continue

            # Determine priority and category
            priority, category = self._classify_priority(f.path or f.filename)

            classified.append(ClassifiedFile(
                ingested=f,
                language=lang,
                priority=priority,
                category=category,
            ))

        # Sort by priority (0 first), then by size descending
        classified.sort(key=lambda c: (c.priority, -c.ingested.size))

        logger.info(
            "Classified %d files: %d security-critical, %d config, %d normal",
            len(classified),
            sum(1 for c in classified if c.priority == 0),
            sum(1 for c in classified if c.priority == 1),
            sum(1 for c in classified if c.priority == 2),
        )
        return classified

    @staticmethod
    def _classify_priority(path: str) -> tuple:
        """Classify a file's priority and category.

        Returns (priority, category) tuple.
        """
        lower_path = path.lower().replace("\\", "/")
        basename = os.path.basename(lower_path)

        # Priority 0: Security-critical files
        for pattern in SECURITY_CRITICAL_PATTERNS:
            if pattern in lower_path:
                return 0, "security"

        # Priority 1: Config files
        for pattern in CONFIG_PATTERNS:
            if pattern in basename:
                return 1, "config"

        # Priority 2: Normal source files
        return 2, "source"

    # ── Post-clone processing (Parts 4, 5, 9) ───────────────────

    async def post_clone_filter(self, root_dir: str) -> None:
        """Remove dependency/build directories immediately after clone.

        Part 4: aggressive directory removal before any scanning begins.
        Part 12: log every removed directory with [FILTER] prefix.
        """
        def _remove():
            removed = 0
            for name in POST_CLONE_REMOVE_DIRS:
                target = os.path.join(root_dir, name)
                if os.path.isdir(target):
                    shutil.rmtree(target, ignore_errors=True)
                    logger.info("[FILTER] removed directory: %s", name)
                    removed += 1
            # Also walk one level deep for monorepo subprojects
            try:
                for entry in os.scandir(root_dir):
                    if entry.is_dir(follow_symlinks=False):
                        for name in POST_CLONE_REMOVE_DIRS:
                            nested = os.path.join(entry.path, name)
                            if os.path.isdir(nested):
                                shutil.rmtree(nested, ignore_errors=True)
                                rel = os.path.relpath(nested, root_dir)
                                logger.info("[FILTER] removed directory: %s", rel)
                                removed += 1
            except OSError:
                pass
            logger.info("[FILTER] post-clone cleanup removed %d directories", removed)

        await asyncio.to_thread(_remove)

    async def check_extracted_size(self, root_dir: str) -> float:
        """Measure total extracted size and abort if over limit.

        Part 5: repository size guard (500 MB default).
        Returns size in MB.
        """
        def _measure():
            total = 0
            for dirpath, _, filenames in os.walk(root_dir):
                for f in filenames:
                    try:
                        total += os.path.getsize(os.path.join(dirpath, f))
                    except OSError:
                        continue
            return total

        total_bytes = await asyncio.to_thread(_measure)
        size_mb = total_bytes / (1024 * 1024)
        logger.info("[PRECHECK] extracted size: %.1fMB", size_mb)
        if size_mb > MAX_EXTRACTED_SIZE_MB:
            raise RuntimeError(
                f"Extracted repository is {size_mb:.0f}MB, "
                f"exceeds {MAX_EXTRACTED_SIZE_MB}MB limit"
            )
        return size_mb

    @staticmethod
    def detect_monorepo(root_dir: str) -> bool:
        """Detect monorepo patterns (apps/, services/, packages/).

        Part 9: returns True if the root directory contains monorepo markers.
        """
        try:
            entries = {
                e.name for e in os.scandir(root_dir) if e.is_dir(follow_symlinks=False)
            }
        except OSError:
            return False
        matches = entries & MONOREPO_SOURCE_DIRS
        if matches:
            logger.info(
                "[PRECHECK] monorepo detected — source dirs: %s",
                sorted(matches),
            )
            return True
        return False
