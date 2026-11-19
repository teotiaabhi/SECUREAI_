"""
Generalized circuit breaker — protects external service calls
from cascading failures.

States: CLOSED → OPEN → HALF_OPEN → CLOSED
- CLOSED: requests flow normally; failures are counted.
- OPEN: all requests are rejected immediately; waits for recovery_timeout.
- HALF_OPEN: allows a limited number of probe requests; success resets, failure re-opens.

Thread-safe via asyncio.Lock (designed for async callers).
"""

import asyncio
import time
from enum import Enum
from typing import Any, Callable, Optional

from app.core.logging import get_logger

logger = get_logger("circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    """Raised when the circuit is open and the call is rejected."""

    def __init__(self, name: str, retry_after: float):
        self.name = name
        self.retry_after = retry_after
        super().__init__(f"Circuit breaker '{name}' is open — retry after {retry_after:.0f}s")


class CircuitBreaker:
    """Async circuit breaker with half-open probing.

    Args:
        name: Human-readable name for logging.
        failure_threshold: Failures before opening (default 5).
        recovery_timeout: Seconds to wait before half-open probe (default 60).
        half_open_max_calls: Max concurrent calls in half-open state (default 1).
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        # Auto-transition OPEN → HALF_OPEN when recovery timeout elapses
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self.recovery_timeout:
                return CircuitState.HALF_OPEN
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    @property
    def is_available(self) -> bool:
        return self.state != CircuitState.OPEN

    async def execute(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute a function through the circuit breaker.

        Args:
            func: Async callable to execute.
            *args, **kwargs: Arguments forwarded to func.

        Returns:
            Result of func.

        Raises:
            CircuitBreakerOpen: If circuit is open.
            Exception: If func raises and half-open → re-open.
        """
        async with self._lock:
            current_state = self.state

            if current_state == CircuitState.OPEN:
                retry_after = self.recovery_timeout - (time.monotonic() - self._last_failure_time)
                raise CircuitBreakerOpen(self.name, max(0, retry_after))

            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitBreakerOpen(self.name, self.recovery_timeout)
                self._half_open_calls += 1

        try:
            result = await func(*args, **kwargs)
            await self._record_success()
            return result
        except Exception as e:
            await self._record_failure()
            raise

    async def _record_success(self) -> None:
        async with self._lock:
            if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
                logger.info(
                    "circuit_breaker_closed",
                    name=self.name,
                    previous_state=self._state.value,
                )
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0

    async def _record_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                # Probe failed — re-open immediately
                self._state = CircuitState.OPEN
                self._half_open_calls = 0
                logger.warning(
                    "circuit_breaker_reopened",
                    name=self.name,
                    failure_count=self._failure_count,
                )
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "circuit_breaker_opened",
                    name=self.name,
                    failure_count=self._failure_count,
                    recovery_timeout=self.recovery_timeout,
                )

    def reset(self) -> None:
        """Force-reset breaker to closed (for tests or admin actions)."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0


# ── Pre-configured instances ─────────────────────────────────

github_api_breaker = CircuitBreaker(
    name="github_api",
    failure_threshold=5,
    recovery_timeout=60,
)

ai_provider_breaker = CircuitBreaker(
    name="ai_provider",
    failure_threshold=3,
    recovery_timeout=120,
)
