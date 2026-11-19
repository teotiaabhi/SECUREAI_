"""
In-memory LRU cache with TTL — avoids repeated DB queries
for frequently accessed data (baselines, settings).

Thread-safe via asyncio.Lock. No external dependencies.
"""

import asyncio
import time
from collections import OrderedDict
from typing import Any, Optional

from app.core.logging import get_logger

logger = get_logger("cache_service")


class AsyncLRUCache:
    """TTL-based LRU cache for async contexts.

    Args:
        maxsize: Maximum entries before eviction.
        ttl_seconds: Time-to-live per entry in seconds.
        name: Cache name for logging.
    """

    def __init__(self, maxsize: int = 256, ttl_seconds: float = 300, name: str = "default"):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self.name = name
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache. Returns None on miss or expiry."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            value, expires_at = entry
            if time.monotonic() > expires_at:
                # Entry expired — remove it
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return value

    async def set(self, key: str, value: Any) -> None:
        """Store a value in the cache with TTL."""
        async with self._lock:
            expires_at = time.monotonic() + self.ttl_seconds
            self._cache[key] = (value, expires_at)
            self._cache.move_to_end(key)

            # Evict oldest entries if over capacity
            while len(self._cache) > self.maxsize:
                evicted_key, _ = self._cache.popitem(last=False)
                logger.debug("cache_eviction", cache=self.name, key=evicted_key)

    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache (sync-safe)."""
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Flush the entire cache."""
        self._cache.clear()
        logger.info("cache_cleared", cache=self.name)

    @property
    def stats(self) -> dict:
        """Cache hit/miss statistics."""
        total = self._hits + self._misses
        return {
            "name": self.name,
            "size": len(self._cache),
            "maxsize": self.maxsize,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total * 100, 1) if total else 0.0,
        }


# ── Pre-built caches ─────────────────────────────────────────

baseline_cache = AsyncLRUCache(maxsize=100, ttl_seconds=300, name="baseline")  # 5 min TTL
settings_cache = AsyncLRUCache(maxsize=1, ttl_seconds=60, name="settings")     # 1 min TTL
