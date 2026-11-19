"""
Distributed lock abstraction with memory and Redis backends.

Provides mutual exclusion for operations that must be serialized
across worker nodes (e.g., per-repo scan dedup, baseline writes).

In single-process mode, uses asyncio.Lock (zero overhead).
In multi-node mode, uses Redis SET NX EX pattern.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional

from app.core.logging import get_logger

logger = get_logger("distributed_lock")


class LockBackend(ABC):
    """Abstract lock backend interface."""

    @abstractmethod
    async def acquire(self, key: str, ttl_seconds: int = 30) -> bool:
        """Acquire a lock for the given key.

        Args:
            key: Lock identifier (e.g., "scan:repo:owner/name").
            ttl_seconds: Auto-release timeout to prevent deadlocks.

        Returns:
            True if lock acquired, False if already held.
        """

    @abstractmethod
    async def release(self, key: str) -> None:
        """Release a previously acquired lock."""

    @abstractmethod
    async def extend(self, key: str, ttl_seconds: int) -> bool:
        """Extend the TTL of a held lock.

        Returns:
            True if extended, False if lock not held.
        """


class MemoryLockBackend(LockBackend):
    """In-memory lock backend using asyncio.Lock per key.

    Suitable for single-process deployments. Zero external dependencies.
    """

    def __init__(self):
        self._locks: Dict[str, asyncio.Lock] = {}
        self._owners: Dict[str, float] = {}  # key -> expiry timestamp
        self._meta_lock = asyncio.Lock()

    async def acquire(self, key: str, ttl_seconds: int = 30) -> bool:
        async with self._meta_lock:
            # Check if existing lock has expired
            if key in self._owners:
                if time.time() > self._owners[key]:
                    # Expired — clean up
                    del self._owners[key]
                    if key in self._locks and self._locks[key].locked():
                        self._locks[key].release()
                else:
                    return False  # Still held

            if key not in self._locks:
                self._locks[key] = asyncio.Lock()

        acquired = self._locks[key].locked()
        if not acquired:
            await self._locks[key].acquire()
            async with self._meta_lock:
                self._owners[key] = time.time() + ttl_seconds
            return True

        return False

    async def release(self, key: str) -> None:
        async with self._meta_lock:
            self._owners.pop(key, None)
            lock = self._locks.get(key)
            if lock and lock.locked():
                lock.release()

    async def extend(self, key: str, ttl_seconds: int) -> bool:
        async with self._meta_lock:
            if key in self._owners:
                self._owners[key] = time.time() + ttl_seconds
                return True
            return False


class RedisLockBackend(LockBackend):
    """Redis-based distributed lock using SET NX EX pattern.

    Provides mutual exclusion across multiple processes/containers.
    Requires redis[asyncio] package.
    """

    def __init__(self, redis_url: str, prefix: str = "secureai:lock:"):
        self._redis_url = redis_url
        self._prefix = prefix
        self._redis = None
        self._lock_token = f"worker-{id(self)}-{time.time()}"

    async def _ensure_connection(self):
        if self._redis is not None:
            return
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await self._redis.ping()
        except Exception as e:
            self._redis = None
            raise RuntimeError(f"Redis lock connection failed: {e}")

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def acquire(self, key: str, ttl_seconds: int = 30) -> bool:
        await self._ensure_connection()
        result = await self._redis.set(
            self._key(key),
            self._lock_token,
            nx=True,
            ex=ttl_seconds,
        )
        return result is not None

    async def release(self, key: str) -> None:
        await self._ensure_connection()
        # Only release if we own the lock (prevent releasing another worker's lock)
        lua_script = """
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('del', KEYS[1])
        else
            return 0
        end
        """
        await self._redis.eval(lua_script, 1, self._key(key), self._lock_token)

    async def extend(self, key: str, ttl_seconds: int) -> bool:
        await self._ensure_connection()
        lua_script = """
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('expire', KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        result = await self._redis.eval(
            lua_script, 1, self._key(key), self._lock_token, ttl_seconds
        )
        return bool(result)


class DistributedLock:
    """Async context manager wrapper for lock backends.

    Usage:
        async with DistributedLock(backend, "repo:owner/name", ttl=60):
            # exclusive operation
    """

    def __init__(
        self,
        backend: LockBackend,
        key: str,
        ttl_seconds: int = 30,
        retry_interval: float = 0.5,
        max_retries: int = 10,
    ):
        self._backend = backend
        self._key = key
        self._ttl = ttl_seconds
        self._retry_interval = retry_interval
        self._max_retries = max_retries

    async def __aenter__(self):
        for attempt in range(self._max_retries):
            if await self._backend.acquire(self._key, self._ttl):
                return self
            await asyncio.sleep(self._retry_interval)

        raise TimeoutError(
            f"Failed to acquire lock '{self._key}' after {self._max_retries} attempts"
        )

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._backend.release(self._key)
        return False


def create_lock_backend(settings) -> LockBackend:
    """Create a lock backend based on configuration.

    Uses Redis if QUEUE_BACKEND is "redis" and QUEUE_REDIS_URL is set,
    otherwise falls back to in-memory locks.
    """
    backend_type = getattr(settings, "QUEUE_BACKEND", "memory").lower()
    redis_url = getattr(settings, "QUEUE_REDIS_URL", "")

    if backend_type == "redis" and redis_url:
        logger.info("lock_backend_selected", backend="redis")
        return RedisLockBackend(redis_url=redis_url)

    logger.info("lock_backend_selected", backend="memory")
    return MemoryLockBackend()
