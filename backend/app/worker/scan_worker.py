"""
Scan Worker — pulls tasks from queue and executes scan pipelines.

Supports two deployment modes:
- Embedded: runs as an asyncio background task inside the main FastAPI app
- Standalone: runs as a separate process via `python -m app.worker.run`

The worker is stateless — all state is in the database and queue.
"""

import asyncio
import time
import uuid as uuid_mod
from typing import Optional

from app.queue.base import QueueBackend, ScanTask
from app.queue.dead_letter import DeadLetterQueue
from app.core.logging import get_logger
from app.core.config import get_settings

logger = get_logger("worker")


class ScanWorker:
    """Scan pipeline worker that processes tasks from a queue backend.

    Pulls ScanTask objects from the queue, delegates execution to the
    scan orchestrator, and handles retries and dead-lettering.
    """

    def __init__(
        self,
        queue: QueueBackend,
        db_factory,
        worker_id: Optional[str] = None,
        dlq: Optional[DeadLetterQueue] = None,
        session_manager=None,
    ):
        self._queue = queue
        self._db_factory = db_factory
        self._worker_id = worker_id or f"worker-{uuid_mod.uuid4().hex[:8]}"
        self._dlq = dlq or DeadLetterQueue()
        self._session_manager = session_manager
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._active_count = 0
        self._processed_count = 0

        settings = get_settings()
        self._max_retries = settings.DLQ_MAX_RETRIES
        self._retry_delay = settings.DLQ_RETRY_DELAY
        self._heartbeat_interval = settings.WORKER_HEARTBEAT_INTERVAL

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def active_count(self) -> int:
        return self._active_count

    @property
    def processed_count(self) -> int:
        return self._processed_count

    async def start(self) -> None:
        """Start the worker loop and heartbeat."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info(
            "worker_started",
            worker_id=self._worker_id,
            max_retries=self._max_retries,
        )

    async def stop(self) -> None:
        """Gracefully stop the worker."""
        self._running = False

        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info(
            "worker_stopped",
            worker_id=self._worker_id,
            total_processed=self._processed_count,
        )

    async def _run_loop(self) -> None:
        """Main worker loop: dequeue and execute tasks."""
        while self._running:
            try:
                task = await self._queue.dequeue(timeout=2.0)
                if task is None:
                    continue

                self._active_count += 1
                try:
                    await self._execute(task)
                    self._processed_count += 1
                except Exception as e:
                    await self._handle_failure(task, e)
                finally:
                    self._active_count -= 1

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("worker_loop_error", error=str(e))
                await asyncio.sleep(1)

    async def _execute(self, task: ScanTask) -> None:
        """Execute a scan task by delegating to the orchestrator.

        In embedded mode, uses the session_manager's pipeline directly.
        The session_manager handles all state transitions, progress
        tracking, and cleanup.
        """
        logger.info(
            "task_executing",
            worker_id=self._worker_id,
            scan_id=str(task.scan_id),
            attempt=task.attempt,
        )

        start_time = time.time()

        try:
            if self._session_manager is not None:
                # Embedded mode: delegate to session manager's pipeline
                await self._session_manager.execute_scan_pipeline(
                    scan_id=task.scan_id,
                    user_id=task.user_id,
                    source_type=task.source_type,
                    repo_url=task.repo_url,
                    branch=task.branch,
                )
            else:
                # Standalone mode: import and run orchestrator directly
                from app.orchestration.scan_orchestrator import ScanOrchestrator
                async with self._db_factory() as db:
                    orchestrator = ScanOrchestrator(db=db)
                    await orchestrator.run(scan_id=task.scan_id)

            duration = time.time() - start_time
            logger.info(
                "task_completed",
                worker_id=self._worker_id,
                scan_id=str(task.scan_id),
                duration_seconds=round(duration, 2),
            )

            # Update metrics
            try:
                from app.services.metrics import get_metrics
                metrics = get_metrics()
                metrics.inc_counter(
                    "worker_tasks_processed",
                    {"worker_id": self._worker_id, "status": "success"},
                )
            except Exception:
                pass

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "task_execution_failed",
                worker_id=self._worker_id,
                scan_id=str(task.scan_id),
                error=str(e)[:500],
                duration_seconds=round(duration, 2),
            )
            raise

    async def _handle_failure(self, task: ScanTask, error: Exception) -> None:
        """Handle a failed task: retry or dead-letter."""
        if task.attempt < self._max_retries:
            # Retry with backoff
            task.attempt += 1
            delay = self._retry_delay * task.attempt
            logger.warning(
                "task_retry_scheduled",
                scan_id=str(task.scan_id),
                attempt=task.attempt,
                delay_seconds=delay,
            )
            await asyncio.sleep(delay)
            await self._queue.enqueue(task)
        else:
            # Exhausted retries — send to DLQ
            await self._dlq.push(task, str(error)[:1000], task.attempt)

            # Update metrics
            try:
                from app.services.metrics import get_metrics
                metrics = get_metrics()
                metrics.inc_counter(
                    "worker_tasks_processed",
                    {"worker_id": self._worker_id, "status": "dead_lettered"},
                )
            except Exception:
                pass

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat for liveness monitoring."""
        while self._running:
            try:
                await asyncio.sleep(self._heartbeat_interval)
                logger.debug(
                    "worker_heartbeat",
                    worker_id=self._worker_id,
                    active=self._active_count,
                    processed=self._processed_count,
                )

                # Update heartbeat metric
                try:
                    from app.services.metrics import get_metrics
                    metrics = get_metrics()
                    metrics.set_gauge("worker_heartbeat_age", 0)
                except Exception:
                    pass

            except asyncio.CancelledError:
                break
            except Exception:
                pass
