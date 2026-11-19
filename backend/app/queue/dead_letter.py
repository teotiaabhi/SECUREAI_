"""
Dead-letter queue for permanently failed scan tasks.

Captures tasks that have exhausted retry attempts, providing
visibility into persistent failures and manual retry capability.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from uuid import UUID

from app.queue.base import ScanTask
from app.core.logging import get_logger

logger = get_logger("queue.dlq")


@dataclass
class DeadLetterEntry:
    """A failed task with failure metadata."""

    task: ScanTask
    error: str
    attempts: int
    failed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "scan_id": str(self.task.scan_id),
            "user_id": str(self.task.user_id),
            "priority": self.task.priority,
            "source_type": self.task.source_type,
            "error": self.error,
            "attempts": self.attempts,
            "failed_at": self.failed_at,
            "enqueued_at": self.task.enqueued_at,
        }


class DeadLetterQueue:
    """In-memory dead-letter queue for failed scan tasks.

    Provides push/list/retry/purge operations for tasks that
    have exceeded the maximum retry count.
    """

    def __init__(self, max_size: int = 1000):
        self._entries: Dict[UUID, DeadLetterEntry] = {}
        self._max_size = max_size
        self._lock = asyncio.Lock()

    async def push(self, task: ScanTask, error: str, attempts: int) -> None:
        """Add a failed task to the dead-letter queue.

        If the queue exceeds max_size, the oldest entry is evicted.
        """
        async with self._lock:
            # Evict oldest if at capacity
            if len(self._entries) >= self._max_size:
                oldest_id = min(
                    self._entries,
                    key=lambda sid: self._entries[sid].failed_at,
                )
                del self._entries[oldest_id]

            self._entries[task.scan_id] = DeadLetterEntry(
                task=task,
                error=error,
                attempts=attempts,
            )

        logger.warning(
            "dlq_task_added",
            scan_id=str(task.scan_id),
            error=error[:200],
            attempts=attempts,
        )

    async def list_failed(self, limit: int = 50) -> List[dict]:
        """List failed tasks, most recent first."""
        async with self._lock:
            sorted_entries = sorted(
                self._entries.values(),
                key=lambda e: e.failed_at,
                reverse=True,
            )
            return [e.to_dict() for e in sorted_entries[:limit]]

    async def get(self, scan_id: UUID) -> Optional[DeadLetterEntry]:
        """Get a specific dead-letter entry."""
        async with self._lock:
            return self._entries.get(scan_id)

    async def remove(self, scan_id: UUID) -> Optional[ScanTask]:
        """Remove and return a task from the DLQ (for retry).

        Returns:
            The ScanTask if found, None otherwise.
        """
        async with self._lock:
            entry = self._entries.pop(scan_id, None)
            if entry:
                logger.info("dlq_task_removed", scan_id=str(scan_id))
                return entry.task
            return None

    async def purge(self, older_than_days: int = 30) -> int:
        """Remove entries older than the specified number of days.

        Returns:
            Number of purged entries.
        """
        cutoff = time.time() - (older_than_days * 86400)
        purged = 0

        async with self._lock:
            to_remove = [
                sid
                for sid, entry in self._entries.items()
                if entry.failed_at < cutoff
            ]
            for sid in to_remove:
                del self._entries[sid]
                purged += 1

        if purged:
            logger.info("dlq_purged", count=purged, older_than_days=older_than_days)
        return purged

    async def size(self) -> int:
        """Return current number of entries in the DLQ."""
        async with self._lock:
            return len(self._entries)
