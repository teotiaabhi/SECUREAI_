"""
Abuse detector — in-memory anomaly detection for scan and auth abuse.

Tracks rapid scan starts and repeated auth failures to detect
automated attacks, credential stuffing, or resource abuse.

No external dependencies (no Redis). Suitable for single-process deployment.
"""

import time
import logging
from collections import defaultdict, deque
from typing import Dict

logger = logging.getLogger("middleware.abuse_detector")

# Thresholds
SCAN_START_MAX = 10       # max scan starts per user
SCAN_START_WINDOW = 300   # within 5 minutes
AUTH_FAILURE_MAX = 5      # max auth failures per IP
AUTH_FAILURE_WINDOW = 600 # within 10 minutes


class AbuseDetector:
    """Detect rapid scan starts and repeated auth failures."""

    def __init__(self) -> None:
        self._scan_starts: Dict[str, deque] = defaultdict(deque)
        self._auth_failures: Dict[str, deque] = defaultdict(deque)

    def record_scan_start(self, user_id: str) -> None:
        """Record a scan start for a user."""
        now = time.monotonic()
        window = self._scan_starts[user_id]
        window.append(now)
        self._prune(window, now, SCAN_START_WINDOW)

    def record_auth_failure(self, ip_address: str) -> None:
        """Record an authentication failure for an IP."""
        now = time.monotonic()
        window = self._auth_failures[ip_address]
        window.append(now)
        self._prune(window, now, AUTH_FAILURE_WINDOW)

    def is_suspicious_scan_rate(self, user_id: str) -> bool:
        """Check if user has an unusually high scan start rate."""
        now = time.monotonic()
        window = self._scan_starts.get(user_id)
        if not window:
            return False
        self._prune(window, now, SCAN_START_WINDOW)
        suspicious = len(window) > SCAN_START_MAX
        if suspicious:
            logger.warning(
                "suspicious_scan_rate user=%s count=%d window=%ds",
                user_id, len(window), SCAN_START_WINDOW,
            )
        return suspicious

    def is_suspicious_auth_rate(self, ip_address: str) -> bool:
        """Check if an IP has an unusually high auth failure rate."""
        now = time.monotonic()
        window = self._auth_failures.get(ip_address)
        if not window:
            return False
        self._prune(window, now, AUTH_FAILURE_WINDOW)
        suspicious = len(window) > AUTH_FAILURE_MAX
        if suspicious:
            logger.warning(
                "suspicious_auth_rate ip=%s count=%d window=%ds",
                ip_address, len(window), AUTH_FAILURE_WINDOW,
            )
        return suspicious

    @staticmethod
    def _prune(window: deque, now: float, max_age: float) -> None:
        """Remove entries older than max_age seconds."""
        cutoff = now - max_age
        while window and window[0] < cutoff:
            window.popleft()

    def cleanup(self) -> None:
        """Remove empty tracking entries to prevent memory leak."""
        for store in (self._scan_starts, self._auth_failures):
            empty_keys = [k for k, v in store.items() if not v]
            for k in empty_keys:
                del store[k]
