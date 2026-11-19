"""
Per-user per-endpoint rate limiter — in-memory sliding window.

No Redis required. Suitable for single-process async deployments.
Complements slowapi's global IP-based limiter with user-aware,
endpoint-specific rate limiting.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Tuple

from fastapi import HTTPException

import logging

logger = logging.getLogger("middleware.rate_limiter")

# (max_requests, window_seconds) per endpoint group
ENDPOINT_LIMITS: Dict[str, Tuple[int, int]] = {
    "/auth/": (10, 60),
    "/scan/start": (5, 60),
    "/scan/upload": (3, 60),
    "/scan/status": (120, 60),
}
DEFAULT_LIMIT = (60, 60)


class PerUserRateLimiter:
    """Sliding-window rate limiter keyed by (user_id, endpoint_group)."""

    def __init__(self) -> None:
        # Key: (user_id, endpoint_group) → deque of timestamps
        self._windows: Dict[Tuple[str, str], deque] = defaultdict(deque)

    def _match_group(self, path: str) -> str:
        """Match a request path to an endpoint group."""
        for prefix in ENDPOINT_LIMITS:
            if path.startswith(prefix) or path.startswith(f"/api/v1{prefix}"):
                return prefix
        return "__default__"

    def _get_limit(self, group: str) -> Tuple[int, int]:
        return ENDPOINT_LIMITS.get(group, DEFAULT_LIMIT)

    def check(self, user_id: str, path: str) -> None:
        """Check rate limit. Raises HTTPException(429) if exceeded."""
        group = self._match_group(path)
        max_requests, window_seconds = self._get_limit(group)

        key = (user_id, group)
        now = time.monotonic()
        window = self._windows[key]

        # Prune expired entries
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= max_requests:
            retry_after = int(window[0] + window_seconds - now) + 1
            logger.warning(
                "rate_limit_exceeded user=%s group=%s count=%d limit=%d",
                user_id, group, len(window), max_requests,
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )

        window.append(now)

    def cleanup(self) -> None:
        """Remove empty windows to prevent memory leak."""
        empty_keys = [k for k, v in self._windows.items() if not v]
        for k in empty_keys:
            del self._windows[k]
