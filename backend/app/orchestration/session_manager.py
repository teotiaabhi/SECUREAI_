"""
ScanSessionManager — state machine, priority queue, and concurrency limiter
for scan sessions.

Manages the lifecycle of scan sessions:
- Per-user concurrency limits (max 3 concurrent scans)
- Global concurrency via asyncio.Semaphore (max 20)
- Priority queue (paid users = priority 0, free = 10)
- Phase timeout enforcement
- Graceful cancellation via asyncio.Event
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Set
from uuid import UUID

from sqlalchemy import update, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.scan_session import ScanSessionRecord, ScanProgress

logger = logging.getLogger("orchestration.session_manager")

# Valid phase transitions
VALID_TRANSITIONS = {
    ScanStatus.QUEUED.value: {
        ScanStatus.CLONING.value,
        ScanStatus.EXTRACTING.value,   # zip uploads skip cloning
        ScanStatus.CLASSIFYING.value,  # paste/upload skip cloning
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.CLONING.value: {
        ScanStatus.EXTRACTING.value,
        ScanStatus.CLASSIFYING.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.EXTRACTING.value: {
        ScanStatus.CLASSIFYING.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.CLASSIFYING.value: {
        ScanStatus.SCANNING.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.SCANNING.value: {
        ScanStatus.AI_VALIDATING.value,
        ScanStatus.REPORTING.value,  # skip AI if not configured
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.AI_VALIDATING.value: {
        ScanStatus.REPORTING.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.REPORTING.value: {
        ScanStatus.COMPLETE.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
}

# Phase timeouts in seconds
PHASE_TIMEOUTS = {
    ScanStatus.CLONING.value: 120,
    ScanStatus.EXTRACTING.value: 60,
    ScanStatus.CLASSIFYING.value: 30,
    ScanStatus.SCANNING.value: 600,
    ScanStatus.AI_VALIDATING.value: 300,
    ScanStatus.REPORTING.value: 60,
}


class ConcurrencyLimitError(Exception):
    """Raised when per-user concurrency limit is reached."""
    pass


class InvalidTransitionError(Exception):
    """Raised on invalid phase transition."""
    pass


@dataclass
class ScanSession:
    """In-memory state for an active scan session."""
    scan_id: UUID
    user_id: UUID
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    current_phase: str = ScanStatus.QUEUED.value
    phase_started_at: float = field(default_factory=time.monotonic)
    task: Optional[asyncio.Task] = None


class ScanSessionManager:
    """Manages scan session lifecycle with concurrency control."""

    def __init__(
        self,
        max_per_user: int = 3,
        max_global: int = 20,
        queue_backend=None,
    ):
        self._max_per_user = max_per_user
        self._active_sessions: Dict[UUID, ScanSession] = {}
        self._user_sessions: Dict[UUID, Set[UUID]] = {}
        # Use pluggable queue backend or fallback to built-in asyncio.PriorityQueue
        self._queue_backend = queue_backend
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._global_semaphore = asyncio.Semaphore(max_global)
        self._consumer_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._db_factory = None
        self._active_count = 0

    async def start(self, db_factory=None) -> None:
        """Start the queue consumer. Call during app startup."""
        self._db_factory = db_factory
        self._consumer_task = asyncio.create_task(self._queue_consumer())
        logger.info(
            "ScanSessionManager started (max_per_user=%d, max_global=%d)",
            self._max_per_user,
            self._global_semaphore._value,
        )

    async def shutdown(self) -> None:
        """Shutdown gracefully. Cancel all in-flight scans."""
        self._shutdown_event.set()

        # Cancel all active sessions
        for session in list(self._active_sessions.values()):
            session.cancel_event.set()
            if session.task and not session.task.done():
                session.task.cancel()

        # Cancel queue consumer
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass

        # Shutdown queue backend
        if self._queue_backend is not None:
            try:
                await self._queue_backend.shutdown()
            except Exception as e:
                logger.error("Queue backend shutdown error: %s", e)

        logger.info(
            "ScanSessionManager shutdown (%d sessions cancelled)",
            len(self._active_sessions),
        )
        self._active_sessions.clear()
        self._user_sessions.clear()

    async def enqueue_scan(
        self,
        db: AsyncSession,
        scan_id: UUID,
        user_id: UUID,
        is_paid: bool = False,
        source_type: str = "paste",
        repo_url: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> dict:
        """Enqueue a scan for processing.

        Returns dict with queue_position and scan_id.
        Raises ConcurrencyLimitError if user has too many active scans.
        """
        # Check per-user concurrency
        user_scans = self._user_sessions.get(user_id, set())
        if len(user_scans) >= self._max_per_user:
            raise ConcurrencyLimitError(
                f"Maximum {self._max_per_user} concurrent scans per user"
            )

        # Create session record
        session = ScanSession(scan_id=scan_id, user_id=user_id)
        self._active_sessions[scan_id] = session

        # Track user sessions
        if user_id not in self._user_sessions:
            self._user_sessions[user_id] = set()
        self._user_sessions[user_id].add(scan_id)

        # Update scan status to QUEUED
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status=ScanStatus.QUEUED.value)
        )

        # Create session record in DB
        session_record = ScanSessionRecord(
            scan_id=scan_id,
            phase=ScanStatus.QUEUED.value,
            priority=0 if is_paid else 10,
            source_type=source_type,
            repo_url=repo_url,
            branch=branch,
        )
        db.add(session_record)

        # Create progress record
        progress_record = ScanProgress(
            scan_id=scan_id,
            phase=ScanStatus.QUEUED.value,
            percent=0.0,
        )
        db.add(progress_record)

        await db.commit()

        # Enqueue with priority (lower = higher priority)
        priority = 0 if is_paid else 10
        if self._queue_backend is not None:
            # Use pluggable queue backend
            from app.queue.base import ScanTask
            task = ScanTask(
                scan_id=scan_id,
                user_id=user_id,
                priority=priority,
                source_type=source_type,
                repo_url=repo_url,
                branch=branch,
            )
            queue_position = await self._queue_backend.enqueue(task)
        else:
            # Fallback to built-in asyncio.PriorityQueue
            queue_entry = (priority, time.monotonic(), scan_id, user_id)
            await self._queue.put(queue_entry)
            queue_position = self._queue.qsize()
        logger.info(
            "Scan %s enqueued (position=%d, priority=%d, user=%s)",
            scan_id, queue_position, priority, user_id,
        )

        return {
            "scan_id": str(scan_id),
            "queue_position": queue_position,
            "status": ScanStatus.QUEUED.value,
        }

    async def transition(
        self,
        scan_id: UUID,
        new_phase: str,
        db: AsyncSession,
        commit: bool = True,
    ) -> None:
        """Transition a scan to a new phase with validation."""
        session = self._active_sessions.get(scan_id)
        if not session:
            logger.warning("Transition attempted for unknown session: %s", scan_id)
            return

        current = session.current_phase
        valid_next = VALID_TRANSITIONS.get(current, set())

        if new_phase not in valid_next:
            raise InvalidTransitionError(
                f"Invalid transition {current} -> {new_phase} "
                f"for scan {scan_id}"
            )

        session.current_phase = new_phase
        session.phase_started_at = time.monotonic()

        # Update scan status
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status=new_phase)
        )

        # Update session record
        await db.execute(
            update(ScanSessionRecord)
            .where(ScanSessionRecord.scan_id == scan_id)
            .values(phase=new_phase)
        )

        if commit:
            await db.commit()

        logger.info("Scan %s transitioned: %s -> %s", scan_id, current, new_phase)

    async def cancel(self, scan_id: UUID, db: AsyncSession) -> bool:
        """Cancel a scan. Returns True if cancelled, False if not found."""
        session = self._active_sessions.get(scan_id)
        if not session:
            # Try to cancel directly in DB (might be queued)
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(
                    status=ScanStatus.CANCELLED.value,
                    error_message="Cancelled by user",
                )
            )
            await db.commit()
            return True

        # Set cancel event
        session.cancel_event.set()

        # Cancel task if running
        if session.task and not session.task.done():
            session.task.cancel()

        # Update DB
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                status=ScanStatus.CANCELLED.value,
                error_message="Cancelled by user",
            )
        )
        await db.execute(
            update(ScanSessionRecord)
            .where(ScanSessionRecord.scan_id == scan_id)
            .values(phase=ScanStatus.CANCELLED.value)
        )
        await db.commit()

        # Cleanup
        self._release_session(scan_id)

        logger.info("Scan %s cancelled", scan_id)
        return True

    def is_cancelled(self, scan_id: UUID) -> bool:
        """Check if a scan has been cancelled."""
        session = self._active_sessions.get(scan_id)
        if not session:
            return False
        return session.cancel_event.is_set()

    def get_cancel_event(self, scan_id: UUID) -> Optional[asyncio.Event]:
        """Get the cancel event for a scan session."""
        session = self._active_sessions.get(scan_id)
        if session:
            return session.cancel_event
        return None

    def check_phase_timeout(self, scan_id: UUID) -> bool:
        """Check if the current phase has exceeded its timeout."""
        session = self._active_sessions.get(scan_id)
        if not session:
            return False

        timeout = PHASE_TIMEOUTS.get(session.current_phase)
        if timeout is None:
            return False

        elapsed = time.monotonic() - session.phase_started_at
        return elapsed > timeout

    def _release_session(self, scan_id: UUID) -> None:
        """Release a session and update tracking."""
        session = self._active_sessions.pop(scan_id, None)
        if session:
            user_scans = self._user_sessions.get(session.user_id)
            if user_scans:
                user_scans.discard(scan_id)
                if not user_scans:
                    del self._user_sessions[session.user_id]

    async def complete_session(
        self,
        scan_id: UUID,
        db: AsyncSession,
        status: str = ScanStatus.COMPLETE.value,
        error_message: Optional[str] = None,
        commit: bool = True,
    ) -> None:
        """Mark a session as complete or failed."""
        update_values = {"status": status}
        if error_message:
            update_values["error_message"] = error_message[:1024]

        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(**update_values)
        )
        await db.execute(
            update(ScanSessionRecord)
            .where(ScanSessionRecord.scan_id == scan_id)
            .values(
                phase=status,
                completed_at=datetime.now(timezone.utc),
                error_message=error_message,
            )
        )
        if commit:
            await db.commit()

        self._release_session(scan_id)
        logger.info("Scan %s completed with status: %s", scan_id, status)

    async def _queue_consumer(self) -> None:
        """Background task that processes the scan queue."""
        logger.info("Queue consumer started")

        while not self._shutdown_event.is_set():
            try:
                scan_id = None
                user_id = None

                if self._queue_backend is not None:
                    # Use pluggable queue backend
                    task = await self._queue_backend.dequeue(timeout=5.0)
                    if task is None:
                        continue
                    scan_id = task.scan_id
                    user_id = task.user_id
                else:
                    # Fallback to built-in asyncio.PriorityQueue
                    try:
                        priority, timestamp, scan_id, user_id = await asyncio.wait_for(
                            self._queue.get(), timeout=5.0,
                        )
                    except asyncio.TimeoutError:
                        continue

                # Acquire global semaphore
                await self._global_semaphore.acquire()
                self._active_count += 1

                session = self._active_sessions.get(scan_id)
                if not session or session.cancel_event.is_set():
                    self._active_count -= 1
                    self._global_semaphore.release()
                    continue

                # Launch scan pipeline as a task
                from app.orchestration.scan_orchestrator import (
                    execute_scan_pipeline,
                )

                async def _run_and_release(sid: UUID):
                    try:
                        await execute_scan_pipeline(sid, self)
                    except Exception as exc:
                        logger.error(
                            "Scan pipeline crashed for %s: %s", sid, exc, exc_info=True,
                        )
                    finally:
                        self._active_count -= 1
                        self._global_semaphore.release()

                task = asyncio.create_task(_run_and_release(scan_id))
                session.task = task

            except asyncio.CancelledError:
                logger.info("Queue consumer cancelled")
                break
            except Exception as exc:
                logger.error("Queue consumer error: %s", exc)
                await asyncio.sleep(1)

        logger.info("Queue consumer stopped")
