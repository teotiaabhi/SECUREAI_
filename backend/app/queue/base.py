"""
Queue backend abstract interface and ScanTask data model.

Defines the contract that all queue backends must implement.
ScanTask is a serializable dataclass transported through the queue.
"""

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from uuid import UUID


@dataclass
class ScanTask:
    """Serializable scan task for queue transport.

    Represents a single scan job that can be enqueued, dequeued,
    and processed by any worker node.
    """

    scan_id: UUID
    user_id: UUID
    priority: int = 10          # 0 = highest (paid), 10 = default (free)
    source_type: str = "paste"  # paste, upload, zip, github
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    enqueued_at: float = field(default_factory=time.time)
    attempt: int = 1            # retry attempt counter

    def to_json(self) -> str:
        """Serialize to JSON for Redis transport."""
        d = asdict(self)
        d["scan_id"] = str(d["scan_id"])
        d["user_id"] = str(d["user_id"])
        return json.dumps(d)

    @classmethod
    def from_json(cls, data: str) -> "ScanTask":
        """Deserialize from JSON."""
        d = json.loads(data)
        d["scan_id"] = UUID(d["scan_id"])
        d["user_id"] = UUID(d["user_id"])
        return cls(**d)

    def __lt__(self, other: "ScanTask") -> bool:
        """Priority comparison for PriorityQueue ordering."""
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.enqueued_at < other.enqueued_at


class QueueBackend(ABC):
    """Abstract queue backend interface.

    All queue implementations must provide these methods.
    The interface supports both blocking (dequeue) and non-blocking
    (peek, size) operations.
    """

    @abstractmethod
    async def enqueue(self, task: ScanTask) -> int:
        """Add a task to the queue.

        Args:
            task: ScanTask to enqueue.

        Returns:
            Approximate queue position (0-based).
        """

    @abstractmethod
    async def dequeue(self, timeout: float = 0) -> Optional[ScanTask]:
        """Remove and return the highest-priority task.

        Args:
            timeout: Max seconds to wait. 0 = non-blocking.

        Returns:
            ScanTask or None if queue is empty / timeout.
        """

    @abstractmethod
    async def size(self) -> int:
        """Return current number of tasks in the queue."""

    @abstractmethod
    async def peek(self, limit: int = 10) -> List[ScanTask]:
        """Return tasks without removing them (for monitoring).

        Args:
            limit: Max number of tasks to return.

        Returns:
            List of ScanTask in priority order.
        """

    @abstractmethod
    async def remove(self, scan_id: UUID) -> bool:
        """Remove a specific task by scan_id (for cancellation).

        Returns:
            True if task was found and removed.
        """

    @abstractmethod
    async def shutdown(self) -> None:
        """Clean up resources (close connections, etc.)."""
