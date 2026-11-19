"""
CleanupService — temp directory cleanup, stale scan recovery, data retention.

Safety: never deletes outside SCAN_TEMP_DIR.
Runs periodically via asyncio.create_task in app lifespan.
"""

import asyncio
import logging
import os
import shutil
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import update, select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.scan_session import ScanSessionRecord, ScanProgress, ScanFile
from app.models.chunk import ScanChunk

logger = logging.getLogger("orchestration.cleanup")

# Terminal states that don't need recovery
TERMINAL_STATES = {
    ScanStatus.COMPLETE.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELLED.value,
}


class CleanupService:
    """Manages cleanup of temporary files, stale scans, and old data."""

    def __init__(
        self,
        temp_dir: str = "",
        data_retention_days: int = 90,
        stale_timeout: int = 3600,
        cleanup_interval_hours: int = 6,
    ):
        self._temp_dir = temp_dir
        self._retention_days = data_retention_days
        self._stale_timeout = stale_timeout
        self._interval_hours = cleanup_interval_hours

    async def remove_temp_directory(self, path: str) -> None:
        """Safely remove a temporary scan directory."""
        if not path:
            return

        # Safety: only delete within configured temp directory or system temp
        real_path = os.path.realpath(path)
        safe_prefixes = []
        if self._temp_dir:
            safe_prefixes.append(os.path.realpath(self._temp_dir))
        import tempfile
        safe_prefixes.append(os.path.realpath(tempfile.gettempdir()))

        is_safe = any(real_path.startswith(p + os.sep) for p in safe_prefixes)
        if not is_safe:
            logger.warning(
                "Refused to delete directory outside safe prefix: %s", path
            )
            return

        if os.path.isdir(path):
            await asyncio.to_thread(shutil.rmtree, path, True)
            logger.info("Removed temp directory: %s", path)

    async def purge_old_scans(self, db: AsyncSession) -> int:
        """Delete scans older than retention period. Returns count deleted."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)

        # Find old scans in terminal states
        stmt = select(Scan.id).where(
            Scan.created_at < cutoff,
            Scan.status.in_(list(TERMINAL_STATES)),
        )
        result = await db.execute(stmt)
        old_ids = [row[0] for row in result.all()]

        if not old_ids:
            return 0

        # Cascade delete handles vulnerabilities, chunks, sessions, progress, files
        for scan_id in old_ids:
            stmt = delete(Scan).where(Scan.id == scan_id)
            await db.execute(stmt)

        await db.commit()
        logger.info("Purged %d old scans (older than %d days)", len(old_ids), self._retention_days)
        return len(old_ids)

    async def clear_processed_chunks(self, db: AsyncSession, scan_id) -> int:
        """Null out chunk content after processing to save storage."""
        stmt = (
            update(ScanChunk)
            .where(ScanChunk.scan_id == scan_id)
            .values(chunk_content=None)
        )
        result = await db.execute(stmt)
        await db.commit()
        count = result.rowcount or 0
        if count > 0:
            logger.info("Cleared %d processed chunks for scan %s", count, scan_id)
        return count

    async def recover_stale_scans(self, db: AsyncSession) -> int:
        """Mark scans stuck in non-terminal state for >1h as FAILED."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._stale_timeout)

        stmt = (
            update(Scan)
            .where(
                Scan.created_at < cutoff,
                ~Scan.status.in_(list(TERMINAL_STATES)),
            )
            .values(
                status=ScanStatus.FAILED.value,
                error_message="Scan timed out (stale scan recovery)",
            )
        )
        result = await db.execute(stmt)
        await db.commit()
        count = result.rowcount or 0
        if count > 0:
            logger.info("Recovered %d stale scans", count)
        return count

    async def recover_stuck_scans_on_startup(self, db: AsyncSession) -> int:
        """Mark any non-terminal scans as FAILED on startup (crash recovery)."""
        from app.models.scan import Scan, ScanStatus
        from sqlalchemy import select

        non_terminal = [
            ScanStatus.PENDING.value, ScanStatus.QUEUED.value,
            ScanStatus.SCANNING.value, ScanStatus.ANALYZING.value,
            ScanStatus.CLONING.value, ScanStatus.EXTRACTING.value,
            ScanStatus.CLASSIFYING.value, ScanStatus.AI_REASONING.value,
            ScanStatus.AI_VALIDATING.value, ScanStatus.UPLOADING.value,
            ScanStatus.GENERATING_REPORT.value, ScanStatus.REPORTING.value,
        ]
        result = await db.execute(
            select(Scan).where(Scan.status.in_(non_terminal))
        )
        stuck = result.scalars().all()
        count = 0
        for scan in stuck:
            scan.status = ScanStatus.FAILED.value
            scan.error_message = "Server restarted — scan interrupted"
            count += 1
        if count:
            await db.commit()
        logger.info("startup_recovery completed=%d", count)
        return count

    async def detect_orphan_sessions(self, db: AsyncSession) -> int:
        """Delete ScanSessionRecords whose scan_id has no matching Scan."""
        from app.models.scan_session import ScanSessionRecord
        from app.models.scan import Scan
        from sqlalchemy import select

        result = await db.execute(
            select(ScanSessionRecord).where(
                ~ScanSessionRecord.scan_id.in_(select(Scan.id))
            )
        )
        orphans = result.scalars().all()
        count = 0
        for orphan in orphans:
            await db.delete(orphan)
            count += 1
        if count:
            await db.commit()
        logger.info("orphan_sessions_cleaned=%d", count)
        return count

    async def cleanup_orphaned_temp_dirs(self) -> int:
        """Remove temp directories older than 2 hours."""
        if not self._temp_dir or not os.path.isdir(self._temp_dir):
            return 0

        cutoff = time.time() - 7200  # 2 hours
        cleaned = 0

        try:
            entries = await asyncio.to_thread(os.listdir, self._temp_dir)
            for entry in entries[:1000]:
                if not entry.startswith("scan-"):
                    continue
                full_path = os.path.join(self._temp_dir, entry)
                if not os.path.isdir(full_path):
                    continue
                try:
                    mtime = os.path.getmtime(full_path)
                    if mtime < cutoff:
                        await asyncio.to_thread(shutil.rmtree, full_path, True)
                        cleaned += 1
                except OSError:
                    pass
        except OSError as exc:
            logger.warning("Failed to list temp dir: %s", exc)

        if cleaned > 0:
            logger.info("Cleaned %d orphaned temp directories", cleaned)
        return cleaned

    async def run_periodic_cleanup(self, db_factory) -> None:
        """Run all cleanup tasks periodically.

        Args:
            db_factory: Callable that returns an async context manager for DB sessions.
        """
        interval = self._interval_hours * 3600
        logger.info(
            "Periodic cleanup started (interval: %dh)", self._interval_hours
        )

        while True:
            try:
                await asyncio.sleep(interval)
                logger.info("Running periodic cleanup cycle")

                async with db_factory() as db:
                    await self.recover_stale_scans(db)
                    await self.purge_old_scans(db)
                    await self.detect_orphan_sessions(db)

                await self.cleanup_orphaned_temp_dirs()

                logger.info("Periodic cleanup cycle complete")
            except asyncio.CancelledError:
                logger.info("Periodic cleanup cancelled")
                break
            except Exception as exc:
                logger.error("Periodic cleanup error: %s", exc)
                # Continue loop even on error
                await asyncio.sleep(60)
