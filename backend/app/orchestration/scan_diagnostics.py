"""
Scan Diagnostics — production-grade observability for freeze debugging.

Provides:
  - Phase 4:  Executor state monitoring (active/completed/pending futures)
  - Phase 6:  Event loop health check (async watchdog)
  - Phase 7:  Worker heartbeat system (periodic heartbeat in workers)
  - Phase 8:  Memory monitoring (periodic RSS/system mem logging)
  - Phase 9:  Stack dump on freeze (faulthandler thread dump)
  - Phase 10: Scan progress watchdog (stall detection + diagnostics)

All diagnostics run as background asyncio tasks or threads that are
started when a scan begins and cancelled when it finishes.
"""

import asyncio
import faulthandler
import io
import logging
import os
import sys
import threading
import time
import traceback
from typing import Dict, Optional, Set

logger = logging.getLogger("orchestration.scan_diagnostics")


# ─── Phase 6: Event Loop Health Check ────────────────────────────────

async def event_loop_watchdog(
    scan_id: str,
    interval: float = 2.0,
    warn_threshold_ms: float = 500.0,
) -> None:
    """Periodic event loop latency monitor.

    Schedules a callback every `interval` seconds and measures how long
    it actually takes to wake up.  If latency > warn_threshold_ms, the
    event loop is being blocked by CPU work.
    """
    logger.info("[scan %s][diag] Event loop watchdog started (interval=%.1fs)", scan_id, interval)
    try:
        while True:
            t0 = time.monotonic()
            await asyncio.sleep(interval)
            latency_ms = (time.monotonic() - t0 - interval) * 1000

            if latency_ms > warn_threshold_ms:
                logger.warning(
                    "[scan %s][diag] EVENT LOOP BLOCKED: latency=%.0fms (threshold=%.0fms)",
                    scan_id, latency_ms, warn_threshold_ms,
                )
            elif latency_ms > 100:
                logger.info(
                    "[scan %s][diag] event_loop_latency=%.0fms",
                    scan_id, latency_ms,
                )
    except asyncio.CancelledError:
        logger.info("[scan %s][diag] Event loop watchdog stopped", scan_id)


# ─── Phase 8: Memory Monitoring ─────────────────────────────────────

async def memory_monitor(
    scan_id: str,
    interval: float = 5.0,
) -> None:
    """Periodic memory usage logger.

    Logs process RSS and system memory every `interval` seconds.
    Detects sudden spikes (>100 MB jump between checks).
    """
    logger.info("[scan %s][diag] Memory monitor started (interval=%.0fs)", scan_id, interval)
    prev_rss = 0.0
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                import psutil
                proc = psutil.Process(os.getpid())
                rss_mb = proc.memory_info().rss / (1024 * 1024)
                sys_mem = psutil.virtual_memory()
                sys_pct = sys_mem.percent
                sys_avail_mb = sys_mem.available / (1024 * 1024)
            except ImportError:
                rss_mb = 0.0
                sys_pct = 0.0
                sys_avail_mb = 0.0

            spike = ""
            if prev_rss > 0 and (rss_mb - prev_rss) > 100:
                spike = f" SPIKE +{rss_mb - prev_rss:.0f}MB"

            logger.info(
                "[scan %s][diag] memory: rss=%.0fMB sys=%.1f%% avail=%.0fMB%s",
                scan_id, rss_mb, sys_pct, sys_avail_mb, spike,
            )
            prev_rss = rss_mb
    except asyncio.CancelledError:
        logger.info("[scan %s][diag] Memory monitor stopped", scan_id)


# ─── Phase 9: Stack Dump on Freeze ──────────────────────────────────

def dump_all_thread_stacks(scan_id: str) -> str:
    """Capture stack traces of ALL threads using faulthandler + threading.

    Returns the combined stack dump as a string.
    """
    buf = io.StringIO()
    buf.write(f"\n{'='*72}\n")
    buf.write(f"[scan {scan_id}][diag] STACK DUMP — all threads\n")
    buf.write(f"{'='*72}\n\n")

    # Method 1: threading + sys._current_frames()
    frames = sys._current_frames()
    for thread_id, frame in frames.items():
        thread_name = "unknown"
        for t in threading.enumerate():
            if t.ident == thread_id:
                thread_name = t.name
                break
        buf.write(f"--- Thread {thread_id} ({thread_name}) ---\n")
        traceback.print_stack(frame, file=buf)
        buf.write("\n")

    # Method 2: faulthandler (writes to stderr, but also capture)
    buf.write("--- faulthandler.dump_traceback() ---\n")
    faulthandler_buf = io.StringIO()
    try:
        # faulthandler only writes to real file descriptors, not StringIO
        # So we capture what we can from threading above
        faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
        buf.write("(dumped to stderr)\n")
    except Exception as exc:
        buf.write(f"(faulthandler failed: {exc})\n")

    buf.write(f"{'='*72}\n")
    return buf.getvalue()


# ─── Phase 10: Scan Progress Watchdog ────────────────────────────────

class ScanProgressWatchdog:
    """Monitors scan progress and triggers diagnostics on stall.

    Tracks the last time progress was made (file completed).
    If no progress for `stall_threshold_s` seconds, dumps diagnostics.

    Also provides Phase 4 executor state logging via `update_executor_state()`.
    """

    def __init__(
        self,
        scan_id: str,
        stall_threshold_s: float = 10.0,
    ):
        self.scan_id = scan_id
        self.stall_threshold_s = stall_threshold_s

        # Progress tracking
        self._last_progress_time: float = time.monotonic()
        self._last_file: str = ""
        self._files_completed: int = 0
        self._files_total: int = 0

        # Phase 4: executor state
        self._active_futures: int = 0
        self._completed_futures: int = 0
        self._pending_tasks: int = 0

        # Diagnostics state
        self._stall_dumps: int = 0
        self._max_dumps: int = 3  # Don't spam logs with dumps

    def file_started(self, file_name: str, file_idx: int, total: int) -> None:
        """Called when a file begins scanning."""
        self._last_file = file_name
        self._files_total = total
        logger.info(
            "[scan %s][diag] scanning file %d/%d: %s",
            self.scan_id, file_idx, total, file_name,
        )

    def file_completed(self, file_name: str, elapsed_ms: float, findings: int) -> None:
        """Called when a file finishes scanning."""
        self._last_progress_time = time.monotonic()
        self._files_completed += 1
        self._completed_futures += 1
        logger.info(
            "[scan %s][diag] finished file %s (%.0fms, %d findings, %d/%d done)",
            self.scan_id, file_name, elapsed_ms, findings,
            self._files_completed, self._files_total,
        )

    def file_failed(self, file_name: str, error: str, elapsed_ms: float) -> None:
        """Called when a file scan fails or times out."""
        self._last_progress_time = time.monotonic()
        self._files_completed += 1
        logger.warning(
            "[scan %s][diag] file FAILED %s after %.0fms: %s (%d/%d done)",
            self.scan_id, file_name, elapsed_ms, error,
            self._files_completed, self._files_total,
        )

    def update_executor_state(
        self,
        active: int,
        completed: int,
        pending: int,
    ) -> None:
        """Phase 4: Update and log executor state."""
        self._active_futures = active
        self._completed_futures = completed
        self._pending_tasks = pending
        logger.info(
            "[scan %s][diag] executor_state: active=%d completed=%d pending=%d",
            self.scan_id, active, completed, pending,
        )

    def seconds_since_progress(self) -> float:
        """How long since last progress was made."""
        return time.monotonic() - self._last_progress_time

    def check_stall(self) -> bool:
        """Check if scan has stalled. Returns True if stall detected.

        Triggers diagnostics dump on first detection.
        """
        stall_s = self.seconds_since_progress()
        if stall_s < self.stall_threshold_s:
            return False

        logger.error(
            "[scan %s][diag] PROGRESS STALL DETECTED: no progress for %.1fs "
            "(last_file=%s, completed=%d/%d, active_futures=%d, pending=%d)",
            self.scan_id, stall_s, self._last_file,
            self._files_completed, self._files_total,
            self._active_futures, self._pending_tasks,
        )

        if self._stall_dumps < self._max_dumps:
            self._stall_dumps += 1
            dump = dump_all_thread_stacks(self.scan_id)
            logger.error(dump)

        return True


async def progress_watchdog_loop(
    watchdog: ScanProgressWatchdog,
    interval: float = 3.0,
) -> None:
    """Background task that periodically checks for stalls.

    Runs every `interval` seconds.  If a stall is detected, logs full
    diagnostics including thread stack dumps.
    """
    logger.info(
        "[scan %s][diag] Progress watchdog started (stall_threshold=%.0fs)",
        watchdog.scan_id, watchdog.stall_threshold_s,
    )
    try:
        while True:
            await asyncio.sleep(interval)
            watchdog.check_stall()
    except asyncio.CancelledError:
        logger.info("[scan %s][diag] Progress watchdog stopped", watchdog.scan_id)


# ─── Phase 7: Worker Heartbeat ───────────────────────────────────────

# Worker heartbeat runs inside each worker process (not async).
# Called from worker.py as a daemon thread.

_heartbeat_stop = threading.Event()


def _worker_heartbeat_thread(interval: float = 5.0) -> None:
    """Daemon thread in worker process that logs heartbeats.

    Runs until _heartbeat_stop is set or process exits.
    """
    pid = os.getpid()
    logger.info("[worker pid=%d] heartbeat thread started", pid)
    while not _heartbeat_stop.wait(timeout=interval):
        try:
            import psutil
            rss = psutil.Process(pid).memory_info().rss / (1024 * 1024)
        except Exception:
            rss = 0.0
        logger.info("[worker pid=%d] heartbeat alive rss=%.0fMB", pid, rss)
    logger.info("[worker pid=%d] heartbeat thread stopped", pid)


def start_worker_heartbeat(interval: float = 5.0) -> None:
    """Start the heartbeat daemon thread in the current worker process."""
    _heartbeat_stop.clear()
    t = threading.Thread(
        target=_worker_heartbeat_thread,
        args=(interval,),
        daemon=True,
        name="worker-heartbeat",
    )
    t.start()


def stop_worker_heartbeat() -> None:
    """Signal heartbeat thread to stop."""
    _heartbeat_stop.set()


# ─── Diagnostics Manager ────────────────────────────────────────────

class ScanDiagnostics:
    """Manages all diagnostic background tasks for a single scan.

    Usage:
        diag = ScanDiagnostics(scan_id)
        diag.start()          # starts all background monitors
        ...                   # scan runs
        diag.stop()           # cancels all monitors

    Provides the watchdog for file-level progress tracking.
    """

    def __init__(self, scan_id: str, stall_threshold_s: float = 10.0):
        self.scan_id = scan_id
        self.watchdog = ScanProgressWatchdog(scan_id, stall_threshold_s)
        self._tasks: list = []
        self._started = False

    def start(self) -> None:
        """Start all diagnostic background tasks."""
        if self._started:
            return
        self._started = True

        loop = asyncio.get_event_loop()

        # Phase 6: event loop watchdog
        self._tasks.append(
            loop.create_task(
                event_loop_watchdog(self.scan_id),
                name=f"diag-eventloop-{self.scan_id[:8]}",
            )
        )

        # Phase 8: memory monitor
        self._tasks.append(
            loop.create_task(
                memory_monitor(self.scan_id),
                name=f"diag-memory-{self.scan_id[:8]}",
            )
        )

        logger.info(
            "[scan %s][diag] All diagnostics started (%d background tasks)",
            self.scan_id, len(self._tasks),
        )

    def stop(self) -> None:
        """Cancel all diagnostic background tasks."""
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        self._started = False
        logger.info("[scan %s][diag] All diagnostics stopped", self.scan_id)
