"""
ParallelScanController — worker-pool architecture with per-file
timeout, worker crash recovery, progress persistence, memory
backpressure, and stability guarantees.

Architecture:
    Main API
      ↓
    Scan Orchestrator
      ↓
    ParallelScanController
      ↓
    Worker Pool (ProcessPoolExecutor / in-process thread pool)

Each worker scans one file.  If a worker freezes for >PER_FILE_TIMEOUT
seconds the future is abandoned, the file is skipped, and scanning
continues with the remaining files.

Progress is stored in an in-memory dict (ScanProgress) keyed by scan_id
so the status endpoint can read it without performing any scan work.

Stability features:
  - Phase 2:  as_completed() pattern to collect finished futures immediately
  - Phase 6:  Worker health tracking (active/failed/restarted counters)
  - Phase 7:  Backpressure — limits in-flight futures to avoid queue bloat
  - Phase 9:  Hard memory abort at MEMORY_HARD_LIMIT_MB (default 1500 MB)
  - Phase 10: Progress increment in finally blocks — always advances
"""

import asyncio
import collections
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from typing import AsyncIterator, Callable, Deque, Dict, List, Optional, Tuple

from app.core.config import get_settings

logger = logging.getLogger("orchestration.parallel_controller")


# ─── In-memory progress store (Phase 5) ─────────────────────────────

_scan_progress: Dict[str, dict] = {}


def get_scan_progress(scan_id: str) -> Optional[dict]:
    """Read scan progress from the in-memory store.

    Called by the status endpoint — never performs scan work.
    """
    return _scan_progress.get(scan_id)


def set_scan_progress(scan_id: str, data: dict) -> None:
    """Update scan progress in the in-memory store."""
    _scan_progress[scan_id] = data


def clear_scan_progress(scan_id: str) -> None:
    """Remove finished scan from progress store."""
    _scan_progress.pop(scan_id, None)


class ScanCancelledError(Exception):
    """Raised when a scan is cancelled during processing."""
    pass


class MemoryLimitExceeded(Exception):
    """Raised when process RSS exceeds the hard memory limit."""
    pass


# ─── Phase 9: Memory helpers ────────────────────────────────────────

# Hard limit in MB — if the *main* process exceeds this, abort the scan.
MEMORY_HARD_LIMIT_MB: int = 1500


def _get_process_rss_mb() -> float:
    """Get current process RSS in MB."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


# ─── Phase 3: Work queue task ────────────────────────────────────────

@dataclass
class _FileTask:
    """A single file-scan unit of work in the task queue."""
    file_name: str
    content: str
    language: str
    batch_idx: int
    submit_time: float = 0.0
    attempt: int = 1


# ─── Phase 7: File size constant ─────────────────────────────────────

MAX_SCAN_FILE_SIZE: int = 1_048_576  # 1 MB


# ─── Phase 12: Binary detection ──────────────────────────────────────

def _is_likely_binary(content: str, sample_size: int = 8192) -> bool:
    """Quick heuristic: null bytes in first 8 KB indicate binary content."""
    return '\x00' in content[:sample_size]


class ParallelScanController:
    """Work-queue-based parallel scan controller.

    Architecture (Phase 3):
        FileTaskQueue → Sliding-window submission → WorkerPool → ResultCollector

    Workers pull tasks dynamically.  As each finishes, the next file is
    submitted immediately (sliding window), preventing worker starvation.

    Phases: 1 (submit+wait), 2 (isolation), 3 (work queue),
    4 (adaptive scaling), 6 (per-file timeout), 7 (file size guard),
    8 (progress tracking), 9 (memory abort), 10 (crash recovery),
    11 (structured logs), 12 (binary/size pre-filtering).
    """

    def __init__(
        self,
        per_file_timeout: int = 10,
        memory_threshold: float = 85.0,
        max_inflight: int = 20,
    ):
        settings = get_settings()
        self._per_file_timeout = min(per_file_timeout, settings.ENGINE_PER_FILE_TIMEOUT)

        self._memory_threshold = memory_threshold
        if memory_threshold == 85.0:
            try:
                self._memory_threshold = settings.MEMORY_PRESSURE_THRESHOLD
            except Exception:
                pass

        self._max_inflight = max_inflight

        # Health counters (reset per scan_batches call)
        self._active_workers = 0
        self._failed_workers = 0
        self._timeouts_total = 0
        self._pool_restarts = 0

    # ── Phase 4: Adaptive worker count ───────────────────────────────

    @staticmethod
    def _compute_worker_count(total_files: int, total_size: int) -> int:
        """Compute optimal worker count based on CPU, memory, and workload."""
        cpu = os.cpu_count() or 4
        base = min(8, cpu)
        if total_files <= 10:
            base = min(2, base)
        elif total_files <= 30:
            base = min(4, base)
        try:
            import psutil
            mem_pct = psutil.virtual_memory().percent
            if mem_pct > 85:
                base = max(2, base // 2)
            elif mem_pct > 70:
                base = max(2, base - 1)
        except ImportError:
            pass
        return max(1, base)

    # ── Health snapshot ──────────────────────────────────────────────

    def _health_snapshot(self) -> dict:
        return {
            "active_workers": self._active_workers,
            "failed_workers": self._failed_workers,
            "timeouts": self._timeouts_total,
            "pool_restarts": self._pool_restarts,
        }

    def get_profiler(self):
        """Return the merged RuleProfiler after scan_batches completes."""
        return getattr(self, "_profiler", None)

    # ── Memory helpers ───────────────────────────────────────────────

    @staticmethod
    def _get_memory_pct() -> float:
        """Get system memory usage percentage."""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            return 0.0

    async def _check_memory_pressure(self, scan_id: Optional[str] = None) -> None:
        """Pause if system memory is high; abort if process RSS exceeds hard limit."""
        mem_pct = await asyncio.to_thread(self._get_memory_pct)
        rss_mb = await asyncio.to_thread(_get_process_rss_mb)

        # Phase 9: hard abort
        if rss_mb > MEMORY_HARD_LIMIT_MB:
            logger.error(
                "MEMORY HARD LIMIT exceeded: %.0f MB > %d MB — aborting scan %s",
                rss_mb, MEMORY_HARD_LIMIT_MB, scan_id or "?",
            )
            raise MemoryLimitExceeded(
                f"Process RSS {rss_mb:.0f} MB exceeds hard limit {MEMORY_HARD_LIMIT_MB} MB"
            )

        if mem_pct > self._memory_threshold:
            logger.warning(
                "Memory pressure (%.1f%%, RSS %.0f MB) — pausing 2s [scan %s]",
                mem_pct, rss_mb, scan_id or "?",
            )
            await asyncio.sleep(2)

    # ── Phase 10: guaranteed progress update helper ──────────────────

    def _update_progress(
        self,
        scan_id: Optional[str],
        *,
        total: int,
        scanned: int,
        skipped: int,
        errored: int,
        current_file: str,
        status: str = "scanning",
    ) -> None:
        if scan_id:
            set_scan_progress(scan_id, {
                "files_total": total,
                "files_scanned": scanned,
                "files_skipped": skipped,
                "files_errored": errored,
                "current_file": current_file,
                "status": status,
                **self._health_snapshot(),
            })

    # ── Phase 10: Executor factory ───────────────────────────────────

    @staticmethod
    def _create_executor(max_workers: int) -> ProcessPoolExecutor:
        """Create a fresh ProcessPoolExecutor.

        Workers load rules from disk in worker_init() — NO rule data
        is passed through initargs, eliminating heavy pickling that
        can deadlock multiprocessing pipes on Windows.
        """
        from engine.worker import worker_init
        return ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=worker_init,
        )

    # ── Main entry point ─────────────────────────────────────────────

    async def scan_batches(
        self,
        batches: list,
        cancel_event: Optional[asyncio.Event] = None,
        progress_callback: Optional[Callable] = None,
        scan_id: Optional[str] = None,
    ) -> AsyncIterator[Tuple[list, float]]:
        """Scan batches and yield (findings, progress_fraction) per batch.

        Stability features:
            - Phase 2: as_completed() for multiprocess — collect finished
              futures immediately instead of waiting sequentially.
            - Phase 6: Worker health tracking (active/failed/timeout counters).
            - Phase 7: Backpressure — limit in-flight futures.
            - Phase 9: Hard memory abort if RSS > MEMORY_HARD_LIMIT_MB.
            - Phase 10: files_completed always incremented in finally blocks.

        Args:
            batches: List of ScanBatch objects from ChunkDispatcher.
            cancel_event: asyncio.Event to signal cancellation.
            progress_callback: Optional callback(file_name) per file scanned.
            scan_id: Scan UUID string for progress tracking.

        Yields:
            Tuple of (list_of_finding_dicts, progress_fraction)
        """
        if not batches:
            return

        from engine.worker import worker_init, worker_scan_file_safe, worker_set_total, worker_get_profiler_snapshot
        from engine.rule_profiler import RuleProfiler
        from app.orchestration.scan_diagnostics import ScanProgressWatchdog

        scan_start = time.monotonic()
        self._profiler = RuleProfiler()

        # Create file-level progress watchdog (Phase 2/4/10)
        _watchdog = ScanProgressWatchdog(scan_id or "unknown")

        # Workers load rules from disk themselves in worker_init().
        # No rule serialization needed — avoids pickling ~1000 rule
        # dicts through multiprocessing pipes (deadlock on Windows).

        total_files = sum(len(b.files) for b in batches)
        files_completed = 0
        files_skipped = 0
        files_errored = 0

        # Reset health counters
        self._active_workers = 0
        self._failed_workers = 0
        self._timeouts_total = 0
        self._pool_restarts = 0

        # Phase 7: file size limit
        settings = get_settings()
        max_file_bytes = getattr(
            settings, 'ENGINE_MAX_FILE_SIZE_BYTES', MAX_SCAN_FILE_SIZE
        )

        logger.info(
            "[scan %s] scan_batches START: %d files in %d batches, "
            "per_file_timeout=%ds, max_file_bytes=%d",
            scan_id, total_files, len(batches),
            self._per_file_timeout, max_file_bytes,
        )

        self._update_progress(
            scan_id, total=total_files, scanned=0,
            skipped=0, errored=0, current_file="",
        )

        # ── Phase 3: Build task queue from all batches ───────────
        task_queue: Deque[_FileTask] = collections.deque()
        for batch_idx, batch in enumerate(batches):
            for cf in batch.files:
                file_name = cf.ingested.path or cf.ingested.filename
                content = cf.ingested.content
                language = cf.language

                # Phase 7: skip oversized files
                if len(content) > max_file_bytes:
                    files_skipped += 1
                    files_completed += 1
                    logger.warning(
                        "[scan %s] Oversized (%d bytes > %d), skip: %s",
                        scan_id, len(content), max_file_bytes, file_name,
                    )
                    continue

                # Phase 12: skip binary files
                if _is_likely_binary(content):
                    files_skipped += 1
                    files_completed += 1
                    logger.info(
                        "[scan %s] Binary file, skip: %s", scan_id, file_name,
                    )
                    continue

                task_queue.append(_FileTask(
                    file_name=file_name,
                    content=content,
                    language=language,
                    batch_idx=batch_idx,
                ))

        scannable = len(task_queue)
        logger.info(
            "[scan %s] Queue: %d scannable, %d pre-filtered",
            scan_id, scannable, files_skipped,
        )

        if not task_queue:
            self._update_progress(
                scan_id, total=total_files, scanned=files_completed,
                skipped=files_skipped, errored=files_errored,
                current_file="", status="complete",
            )
            yield [], 1.0
            return

        # Pool strategy
        total_size = sum(b.total_size for b in batches)
        use_multiprocess = scannable > 50 or total_size > 1_000_000

        # Phase 4: adaptive workers
        max_workers = self._compute_worker_count(scannable, total_size)
        yield_interval = min(50, max(5, scannable // 10))

        if not use_multiprocess:
            # ── In-process thread pool (small scans) ─────────────
            await asyncio.to_thread(worker_init)
            await asyncio.to_thread(worker_set_total, total_files)
            from engine.rule_profiler import reset_profiler
            await asyncio.to_thread(reset_profiler)

            logger.info(
                "[scan %s] Thread pool: %d files", scan_id, scannable,
            )

            accumulated: List[dict] = []
            files_since_yield = 0

            while task_queue:
                if cancel_event and cancel_event.is_set():
                    raise ScanCancelledError("Scan cancelled")

                task = task_queue.popleft()
                self._update_progress(
                    scan_id, total=total_files, scanned=files_completed,
                    skipped=files_skipped, errored=files_errored,
                    current_file=task.file_name,
                )

                # Phase 2: file-level tracing
                _file_idx = files_completed + 1
                _watchdog.file_started(task.file_name, _file_idx, total_files)

                file_start = time.monotonic()
                self._active_workers += 1
                try:
                    result = await asyncio.wait_for(
                        asyncio.to_thread(
                            worker_scan_file_safe,
                            task.content, task.file_name, task.language,
                        ),
                        timeout=self._per_file_timeout,
                    )
                    # Unpack structured result (Part 6)
                    result_status = result.get("status", "error")
                    result_findings = result.get("findings", [])
                    result_error = result.get("error")
                    result_pid = result.get("pid", 0)
                    result_elapsed = result.get("elapsed_ms", 0.0)
                    result_rules = result.get("rules_executed", 0)

                    if result_status == "ok":
                        accumulated.extend(result_findings)
                        _watchdog.file_completed(
                            task.file_name,
                            (time.monotonic() - file_start) * 1000,
                            len(result_findings),
                        )
                        logger.info(
                            "[scan %s] file %d/%d: %s — %d findings in %.0fms "
                            "(pid=%d, rules=%d)",
                            scan_id, _file_idx, total_files, task.file_name,
                            len(result_findings), result_elapsed,
                            result_pid, result_rules,
                        )
                    else:
                        # Worker returned error status
                        files_errored += 1
                        self._failed_workers += 1
                        _watchdog.file_failed(
                            task.file_name,
                            result_error or "worker error",
                            (time.monotonic() - file_start) * 1000,
                        )
                        logger.error(
                            "[scan %s] file %d/%d: %s — worker error "
                            "(pid=%d, elapsed=%.0fms): %s",
                            scan_id, _file_idx, total_files, task.file_name,
                            result_pid, result_elapsed, result_error,
                        )
                except asyncio.TimeoutError:
                    files_skipped += 1
                    self._timeouts_total += 1
                    _watchdog.file_failed(
                        task.file_name,
                        f"timeout ({self._per_file_timeout}s)",
                        (time.monotonic() - file_start) * 1000,
                    )
                    logger.warning(
                        "[scan %s] Timeout (%ds): %s after %.1fs",
                        scan_id, self._per_file_timeout, task.file_name,
                        time.monotonic() - file_start,
                    )
                except Exception as exc:
                    files_errored += 1
                    self._failed_workers += 1
                    _watchdog.file_failed(
                        task.file_name,
                        str(exc),
                        (time.monotonic() - file_start) * 1000,
                    )
                    logger.error(
                        "[scan %s] Error on %s: %s",
                        scan_id, task.file_name, exc,
                    )
                finally:
                    self._active_workers -= 1
                    files_completed += 1
                    files_since_yield += 1
                    self._update_progress(
                        scan_id, total=total_files, scanned=files_completed,
                        skipped=files_skipped, errored=files_errored,
                        current_file=task.file_name,
                    )

                if progress_callback:
                    progress_callback(task.file_name)

                if files_since_yield >= yield_interval or not task_queue:
                    frac = files_completed / total_files if total_files > 0 else 1.0
                    yield accumulated, frac
                    accumulated = []
                    files_since_yield = 0
                    await self._check_memory_pressure(scan_id)

            # Collect profiler snapshot from in-process worker
            snap = await asyncio.to_thread(worker_get_profiler_snapshot)
            self._profiler.merge_snapshot(snap)

        else:
            # ── Phase 3: Multiprocess work queue ─────────────────
            loop = asyncio.get_running_loop()

            logger.info(
                "[scan %s] Process pool: %d workers, %d files",
                scan_id, max_workers, scannable,
            )

            executor = self._create_executor(max_workers)
            accumulated: List[dict] = []
            inflight: Dict[asyncio.Future, _FileTask] = {}
            files_since_yield = 0
            consecutive_timeouts = 0
            max_consecutive = max_workers * 3

            try:
                while task_queue or inflight:
                    if cancel_event and cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled")

                    # ── Fill worker slots from queue ─────────────
                    while len(inflight) < max_workers and task_queue:
                        task = task_queue.popleft()
                        task.submit_time = time.monotonic()
                        # Phase 2: file-level tracing
                        _watchdog.file_started(
                            task.file_name,
                            files_completed + len(inflight) + 1,
                            total_files,
                        )
                        try:
                            fut = loop.run_in_executor(
                                executor,
                                worker_scan_file_safe,
                                task.content, task.file_name, task.language,
                            )
                            inflight[fut] = task
                            self._active_workers += 1
                        except BrokenProcessPool:
                            logger.error(
                                "[scan %s] Pool broken on submit — recovering",
                                scan_id,
                            )
                            task_queue.appendleft(task)
                            executor, dropped = self._recover_pool(
                                executor, inflight, task_queue,
                                max_workers, scan_id,
                            )
                            files_errored += dropped
                            files_completed += dropped
                            inflight.clear()
                            break

                    if not inflight:
                        if not task_queue:
                            break
                        continue

                    # ── Wait for any one completion ──────────────
                    try:
                        done, _ = await asyncio.wait(
                            inflight.keys(),
                            return_when=asyncio.FIRST_COMPLETED,
                            timeout=2.0,
                        )
                    except Exception as exc:
                        logger.error(
                            "[scan %s] asyncio.wait error: %s", scan_id, exc,
                        )
                        break

                    now = time.monotonic()

                    # Phase 4: executor state after each wait cycle
                    _watchdog.update_executor_state(
                        active=len(inflight),
                        completed=files_completed,
                        pending=len(task_queue),
                    )

                    # ── Collect completed futures ────────────────
                    pool_broken = False
                    for fut in (done or set()):
                        task = inflight.pop(fut)
                        self._active_workers = max(0, self._active_workers - 1)
                        elapsed_ms = (now - task.submit_time) * 1000
                        try:
                            result = fut.result()

                            # Part 6: Unpack structured worker result
                            if isinstance(result, dict):
                                result_status = result.get("status", "error")
                                result_findings = result.get("findings", [])
                                result_error = result.get("error")
                                result_pid = result.get("pid", 0)
                                result_elapsed = result.get("elapsed_ms", 0.0)
                                result_rules = result.get("rules_executed", 0)

                                if result_status == "ok":
                                    accumulated.extend(result_findings)
                                    consecutive_timeouts = 0
                                    _watchdog.file_completed(
                                        task.file_name, elapsed_ms,
                                        len(result_findings),
                                    )
                                    logger.info(
                                        "[scan %s] file %s — %d findings in "
                                        "%.0fms (pid=%d, rules=%d)",
                                        scan_id, task.file_name,
                                        len(result_findings), result_elapsed,
                                        result_pid, result_rules,
                                    )
                                else:
                                    # Worker caught error internally
                                    files_errored += 1
                                    self._failed_workers += 1
                                    consecutive_timeouts = 0
                                    _watchdog.file_failed(
                                        task.file_name,
                                        result_error or "worker error",
                                        elapsed_ms,
                                    )
                                    logger.error(
                                        "[scan %s] file %s — worker error "
                                        "(pid=%d, elapsed=%.0fms): %s",
                                        scan_id, task.file_name,
                                        result_pid, result_elapsed,
                                        result_error,
                                    )
                            elif isinstance(result, list):
                                # Backward compat: raw list of finding dicts
                                accumulated.extend(result)
                                consecutive_timeouts = 0
                                _watchdog.file_completed(
                                    task.file_name, elapsed_ms, len(result),
                                )
                            else:
                                logger.warning(
                                    "[scan %s] Unexpected result type from %s: %s",
                                    scan_id, task.file_name, type(result).__name__,
                                )

                        except BrokenProcessPool:
                            logger.error(
                                "[scan %s] Worker crash on %s — recovering "
                                "(pid unknown, elapsed=%.0fms)",
                                scan_id, task.file_name, elapsed_ms,
                            )
                            self._failed_workers += 1
                            if task.attempt < 2:
                                task.attempt += 1
                                task_queue.appendleft(task)
                            else:
                                files_errored += 1
                                files_completed += 1
                            executor, dropped = self._recover_pool(
                                executor, inflight, task_queue,
                                max_workers, scan_id,
                            )
                            files_errored += dropped
                            files_completed += dropped
                            inflight.clear()
                            pool_broken = True
                            break

                        except asyncio.CancelledError:
                            # Part 3: Handle cancelled futures gracefully
                            files_errored += 1
                            self._failed_workers += 1
                            _watchdog.file_failed(
                                task.file_name, "future cancelled", elapsed_ms,
                            )
                            logger.warning(
                                "[scan %s] Future cancelled for %s after %.0fms",
                                scan_id, task.file_name, elapsed_ms,
                            )

                        except Exception as exc:
                            files_errored += 1
                            self._failed_workers += 1
                            _watchdog.file_failed(
                                task.file_name, str(exc), elapsed_ms,
                            )
                            logger.error(
                                "[scan %s] Future exception on %s after "
                                "%.0fms: %s",
                                scan_id, task.file_name, elapsed_ms, exc,
                                exc_info=True,
                            )

                        files_completed += 1
                        files_since_yield += 1
                        self._update_progress(
                            scan_id, total=total_files,
                            scanned=files_completed,
                            skipped=files_skipped,
                            errored=files_errored,
                            current_file=task.file_name,
                        )

                    if pool_broken:
                        continue

                    # ── Phase 6: timed-out futures ───────────────
                    stale = [
                        f for f, t in inflight.items()
                        if now - t.submit_time > self._per_file_timeout
                    ]
                    for fut in stale:
                        task = inflight.pop(fut)
                        fut.cancel()
                        files_skipped += 1
                        files_completed += 1
                        files_since_yield += 1
                        self._timeouts_total += 1
                        consecutive_timeouts += 1
                        self._active_workers = max(0, self._active_workers - 1)
                        # Phase 2: timeout trace
                        _watchdog.file_failed(
                            task.file_name,
                            f"timeout ({self._per_file_timeout}s)",
                            (now - task.submit_time) * 1000,
                        )
                        logger.warning(
                            "[scan %s] Timeout (%ds): %s (#%d)",
                            scan_id, self._per_file_timeout,
                            task.file_name, self._timeouts_total,
                        )
                        self._update_progress(
                            scan_id, total=total_files,
                            scanned=files_completed,
                            skipped=files_skipped,
                            errored=files_errored,
                            current_file=task.file_name,
                        )

                    # Phase 10: pool degraded
                    if consecutive_timeouts >= max_consecutive:
                        logger.warning(
                            "[scan %s] %d consecutive timeouts — recovering",
                            scan_id, consecutive_timeouts,
                        )
                        executor, dropped = self._recover_pool(
                            executor, inflight, task_queue,
                            max_workers, scan_id,
                        )
                        files_errored += dropped
                        files_completed += dropped
                        inflight.clear()
                        consecutive_timeouts = 0

                    # ── Yield periodically ───────────────────────
                    should_yield = (
                        files_since_yield >= yield_interval
                        or (not task_queue and not inflight)
                    )
                    if should_yield and (accumulated or (not task_queue and not inflight)):
                        frac = files_completed / total_files if total_files > 0 else 1.0
                        yield accumulated, frac
                        accumulated = []
                        files_since_yield = 0
                        await self._check_memory_pressure(scan_id)
            finally:
                # Collect profiler snapshots from worker processes
                try:
                    for _ in range(max_workers):
                        snap_fut = loop.run_in_executor(
                            executor, worker_get_profiler_snapshot,
                        )
                        snap = await asyncio.wait_for(snap_fut, timeout=5.0)
                        self._profiler.merge_snapshot(snap)
                except Exception as prof_exc:
                    logger.warning(
                        "[scan %s] Profiler snapshot collection failed: %s",
                        scan_id, prof_exc,
                    )
                try:
                    executor.shutdown(wait=False, cancel_futures=True)
                except Exception:
                    pass

        # ── Final ────────────────────────────────────────────────
        elapsed = time.monotonic() - scan_start
        self._update_progress(
            scan_id, total=total_files, scanned=files_completed,
            skipped=files_skipped, errored=files_errored,
            current_file="", status="complete",
        )

        logger.info(
            "[scan %s] scan_batches DONE: %d/%d in %.1fs "
            "(skip=%d err=%d timeout=%d restarts=%d)",
            scan_id, files_completed, total_files, elapsed,
            files_skipped, files_errored, self._timeouts_total,
            self._pool_restarts,
        )

    # ── Phase 10: Pool recovery ──────────────────────────────────────

    def _recover_pool(
        self,
        old_executor: ProcessPoolExecutor,
        inflight: Dict[asyncio.Future, _FileTask],
        task_queue: Deque[_FileTask],
        max_workers: int,
        scan_id: Optional[str],
    ) -> Tuple[ProcessPoolExecutor, int]:
        """Shut down broken executor, requeue inflight, create fresh pool.

        Returns (new_executor, dropped_file_count).
        """
        self._pool_restarts += 1
        logger.warning(
            "[scan %s] Pool recovery #%d: requeueing %d tasks",
            scan_id, self._pool_restarts, len(inflight),
        )

        dropped = 0
        requeued: List[_FileTask] = []
        for fut, task in inflight.items():
            fut.cancel()
            self._active_workers = max(0, self._active_workers - 1)
            if task.attempt < 2:
                task.attempt += 1
                requeued.append(task)
            else:
                dropped += 1

        task_queue.extendleft(reversed(requeued))

        try:
            old_executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

        self._active_workers = 0
        return self._create_executor(max_workers), dropped
