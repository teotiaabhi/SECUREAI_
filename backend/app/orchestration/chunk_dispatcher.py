"""
ChunkDispatcher — groups classified files into language-aware batches
for parallel scanning with optimal rule cache locality.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger("orchestration.chunk_dispatcher")


@dataclass
class ScanBatch:
    """A batch of files to scan together."""
    batch_id: int
    files: list = field(default_factory=list)  # List of ClassifiedFile
    language: str = ""
    total_size: int = 0
    priority: int = 2  # min priority in batch (0 = highest)


class ChunkDispatcher:
    """Dispatches classified files into optimized scan batches."""

    def __init__(
        self,
        batch_max_size_mb: int = 10,
        batch_max_files: int = 50,
    ):
        self._max_size_bytes = batch_max_size_mb * 1024 * 1024
        self._max_files = batch_max_files

    def create_batches(self, files: list) -> List[ScanBatch]:
        """Create scan batches from classified files.

        Strategy:
        1. Group files by language (rule cache locality)
        2. Within each language, sort by priority (security-critical first)
        3. Split into batches respecting size and file count limits
        4. Sort batches by priority, then by size descending

        Args:
            files: List of ClassifiedFile objects.

        Returns:
            List of ScanBatch objects ready for parallel scanning.
        """
        if not files:
            return []

        # Group by language
        lang_groups = defaultdict(list)
        for f in files:
            lang_groups[f.language].append(f)

        # Create batches
        batches: List[ScanBatch] = []
        batch_id = 0

        for language, lang_files in lang_groups.items():
            # Sort by priority within language
            lang_files.sort(key=lambda f: (f.priority, -f.ingested.size))

            current_batch = ScanBatch(
                batch_id=batch_id,
                language=language,
            )

            for cf in lang_files:
                file_size = cf.ingested.size

                # Check if adding this file would exceed limits
                would_exceed_size = (
                    current_batch.total_size + file_size > self._max_size_bytes
                )
                would_exceed_count = len(current_batch.files) >= self._max_files

                if current_batch.files and (would_exceed_size or would_exceed_count):
                    # Finalize current batch and start a new one
                    batches.append(current_batch)
                    batch_id += 1
                    current_batch = ScanBatch(
                        batch_id=batch_id,
                        language=language,
                    )

                current_batch.files.append(cf)
                current_batch.total_size += file_size
                current_batch.priority = min(
                    current_batch.priority, cf.priority
                )

            # Don't forget the last batch
            if current_batch.files:
                batches.append(current_batch)
                batch_id += 1

        # Sort batches: priority first (0=highest), then by size descending
        batches.sort(key=lambda b: (b.priority, -b.total_size))

        logger.info(
            "Created %d batches from %d files across %d languages",
            len(batches),
            len(files),
            len(lang_groups),
        )

        for b in batches:
            logger.debug(
                "  Batch %d: lang=%s, files=%d, size=%dKB, priority=%d",
                b.batch_id,
                b.language,
                len(b.files),
                b.total_size // 1024,
                b.priority,
            )

        return batches
