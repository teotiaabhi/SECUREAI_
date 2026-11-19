"""
Redis queue backend using sorted sets for distributed scan processing.

Enables multi-node worker architectures where multiple processes/containers
pull from a shared Redis queue. Uses ZADD with priority as score and
BZPOPMIN for blocking dequeue.

Requires: redis[asyncio] package (optional dependency).
"""

import asyncio
import time
from typing import List, Optional
from uuid import UUID

from app.queue.base import QueueBackend, ScanTask
from app.core.logging import get_logger

logger = get_logger("queue.redis")

_QUEUE_KEY = "secureai:scan_queue"
_TASK_PREFIX = "secureai:task:"


class RedisQueueBackend(QueueBackend):
    """Redis sorted set queue backend for distributed deployments.

    Tasks are stored as:
    - Sorted set (ZADD): score = priority * 1e12 + enqueued_at for ordering
    - Hash per task: full ScanTask JSON for data retrieval

    Falls back gracefully if Redis is unavailable.
    """

    def __init__(self, redis_url: str, queue_key: str = _QUEUE_KEY):
        self._redis_url = redis_url
        self._queue_key = queue_key
        self._redis = None
        self._connected = False

    async def _ensure_connection(self):
        """Lazy connection to Redis."""
        if self._redis is not None:
            return

        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise RuntimeError(
                "redis[asyncio] package required for Redis queue backend. "
                "Install with: pip install redis[asyncio]"
            )

        try:
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=10,
                retry_on_timeout=True,
            )
            await self._redis.ping()
            self._connected = True
            logger.info("redis_queue_connected", url=self._redis_url[:30] + "...")
        except Exception as e:
            self._redis = None
            raise RuntimeError(f"Failed to connect to Redis: {e}")

    def _score(self, task: ScanTask) -> float:
        """Compute sort score: lower priority + earlier time = higher precedence."""
        return task.priority * 1e12 + task.enqueued_at

    async def enqueue(self, task: ScanTask) -> int:
        await self._ensure_connection()

        score = self._score(task)
        task_key = f"{_TASK_PREFIX}{task.scan_id}"

        pipe = self._redis.pipeline()
        pipe.zadd(self._queue_key, {str(task.scan_id): score})
        pipe.set(task_key, task.to_json(), ex=86400)  # 24h TTL
        await pipe.execute()

        position = await self._redis.zrank(self._queue_key, str(task.scan_id))
        logger.debug(
            "redis_task_enqueued",
            scan_id=str(task.scan_id),
            priority=task.priority,
            position=position,
        )
        return position or 0

    async def dequeue(self, timeout: float = 0) -> Optional[ScanTask]:
        await self._ensure_connection()

        if timeout > 0:
            # Blocking pop with timeout
            result = await self._redis.bzpopmin(self._queue_key, timeout=timeout)
            if result is None:
                return None
            # result = (key, member, score)
            _, scan_id_str, _ = result
        else:
            # Non-blocking: get lowest score member
            members = await self._redis.zrange(
                self._queue_key, 0, 0, withscores=False
            )
            if not members:
                return None
            scan_id_str = members[0]
            await self._redis.zrem(self._queue_key, scan_id_str)

        # Retrieve full task data
        task_key = f"{_TASK_PREFIX}{scan_id_str}"
        task_json = await self._redis.get(task_key)
        if task_json is None:
            logger.warning("redis_task_data_missing", scan_id=scan_id_str)
            return None

        await self._redis.delete(task_key)
        return ScanTask.from_json(task_json)

    async def size(self) -> int:
        await self._ensure_connection()
        return await self._redis.zcard(self._queue_key)

    async def peek(self, limit: int = 10) -> List[ScanTask]:
        await self._ensure_connection()

        members = await self._redis.zrange(self._queue_key, 0, limit - 1)
        tasks = []
        for scan_id_str in members:
            task_key = f"{_TASK_PREFIX}{scan_id_str}"
            task_json = await self._redis.get(task_key)
            if task_json:
                tasks.append(ScanTask.from_json(task_json))
        return tasks

    async def remove(self, scan_id: UUID) -> bool:
        await self._ensure_connection()

        removed = await self._redis.zrem(self._queue_key, str(scan_id))
        task_key = f"{_TASK_PREFIX}{scan_id}"
        await self._redis.delete(task_key)

        if removed:
            logger.debug("redis_task_removed", scan_id=str(scan_id))
        return bool(removed)

    async def shutdown(self) -> None:
        if self._redis is not None:
            await self._redis.close()
            self._redis = None
            self._connected = False
        logger.info("redis_queue_shutdown")
