"""
In-memory queue backend using asyncio.PriorityQueue.

Default backend for single-process deployments. Provides identical
behavior to the original session_manager queue implementation.
"""

import asyncio
from typing import Dict, List, Optional
from uuid import UUID

from app.queue.base import QueueBackend, ScanTask
from app.core.logging import get_logger

logger = get_logger("queue.memory")


class MemoryQueueBackend(QueueBackend):
    """In-memory priority queue backed by asyncio.PriorityQueue.

    Maintains a secondary dict for O(1) lookup by scan_id,
    enabling efficient cancellation and peek operations.
    """

    def __init__(self, maxsize: int = 0):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=maxsize)
        self._tasks: Dict[UUID, ScanTask] = {}  # scan_id -> task for lookup
        self._removed: set = set()  # scan_ids marked for removal
        self._lock = asyncio.Lock()

    async def enqueue(self, task: ScanTask) -> int:
        async with self._lock:
            self._tasks[task.scan_id] = task
            await self._queue.put((task.priority, task.enqueued_at, task))
            position = self._queue.qsize() - 1
            logger.debug(
                "task_enqueued",
                scan_id=str(task.scan_id),
                priority=task.priority,
                position=position,
            )
            return position

    async def dequeue(self, timeout: float = 0) -> Optional[ScanTask]:
        while True:
            try:
                if timeout > 0:
                    priority, enqueued_at, task = await asyncio.wait_for(
                        self._queue.get(), timeout=timeout
                    )
                else:
                    # Non-blocking
                    priority, enqueued_at, task = self._queue.get_nowait()
            except (asyncio.TimeoutError, asyncio.QueueEmpty):
                return None

            async with self._lock:
                # Skip tasks that were cancelled
                if task.scan_id in self._removed:
                    self._removed.discard(task.scan_id)
                    self._tasks.pop(task.scan_id, None)
                    continue

                self._tasks.pop(task.scan_id, None)
                return task

    async def size(self) -> int:
        async with self._lock:
            # Subtract removed tasks that are still in the queue
            return max(0, self._queue.qsize() - len(self._removed))

    async def peek(self, limit: int = 10) -> List[ScanTask]:
        async with self._lock:
            tasks = sorted(
                (t for sid, t in self._tasks.items() if sid not in self._removed),
                key=lambda t: (t.priority, t.enqueued_at),
            )
            return tasks[:limit]

    async def remove(self, scan_id: UUID) -> bool:
        async with self._lock:
            if scan_id in self._tasks:
                self._removed.add(scan_id)
                logger.debug("task_removed", scan_id=str(scan_id))
                return True
            return False

    async def shutdown(self) -> None:
        async with self._lock:
            self._tasks.clear()
            self._removed.clear()
        logger.info("memory_queue_shutdown")
