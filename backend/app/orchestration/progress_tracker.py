"""
ScanProgressTracker — DB-persisted real-time scan progress.

Survives server restarts by persisting to the scan_progress table.
Provides ETA estimation via weighted moving average.
"""

import logging
import time
from collections import deque
from typing import Dict, Optional
from uuid import UUID

from sqlalchemy import update, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_session import ScanProgress

logger = logging.getLogger("orchestration.progress_tracker")


class ScanProgressTracker:
    """Tracks and persists scan progress to the database."""

    def __init__(self, scan_id: UUID):
        self._scan_id = scan_id
        self._rate_samples: deque = deque(maxlen=5)
        self._last_update_time: Optional[float] = None
        self._last_files_scanned: int = 0

    def _estimate_eta(self, files_scanned: int, total_files: int) -> float:
        """Estimate time remaining using weighted moving average of processing rate."""
        now = time.monotonic()

        if self._last_update_time is not None and files_scanned > self._last_files_scanned:
            elapsed = now - self._last_update_time
            files_delta = files_scanned - self._last_files_scanned
            if elapsed > 0:
                rate = files_delta / elapsed  # files per second
                self._rate_samples.append(rate)

        self._last_update_time = now
        self._last_files_scanned = files_scanned

        if not self._rate_samples or files_scanned >= total_files:
            return 0.0

        # Weighted average: recent samples weighted more heavily
        weights = list(range(1, len(self._rate_samples) + 1))
        total_weight = sum(weights)
        avg_rate = sum(r * w for r, w in zip(self._rate_samples, weights)) / total_weight

        remaining_files = total_files - files_scanned
        if avg_rate > 0:
            return round(remaining_files / avg_rate, 1)
        return 0.0

    async def update(
        self,
        db: AsyncSession,
        phase: str,
        percent: float,
        current_file: str = "",
        live_vuln_count: int = 0,
        files_scanned: int = 0,
        total_files: int = 0,
        eta_seconds: Optional[float] = None,
        commit: bool = True,
    ) -> None:
        """Update scan progress in the database."""
        # Clamp percent
        percent = round(max(0.0, min(100.0, percent)), 1)

        # Auto-estimate ETA if not provided
        if eta_seconds is None and total_files > 0:
            eta_seconds = self._estimate_eta(files_scanned, total_files)
        elif eta_seconds is None:
            eta_seconds = 0.0

        stmt = (
            update(ScanProgress)
            .where(ScanProgress.scan_id == self._scan_id)
            .values(
                phase=phase,
                percent=percent,
                current_file=current_file[:512] if current_file else "",
                live_vuln_count=live_vuln_count,
                files_scanned=files_scanned,
                total_files=total_files,
                eta_seconds=eta_seconds,
            )
        )
        await db.execute(stmt)
        if commit:
            await db.commit()

    @staticmethod
    async def get_progress(db: AsyncSession, scan_id: UUID) -> Dict:
        """Get current progress for a scan."""
        stmt = select(ScanProgress).where(ScanProgress.scan_id == scan_id)
        result = await db.execute(stmt)
        progress = result.scalar_one_or_none()

        if progress is None:
            return {
                "phase": "unknown",
                "percent": 0.0,
                "current_file": "",
                "live_vuln_count": 0,
                "files_scanned": 0,
                "total_files": 0,
                "eta_seconds": 0.0,
            }

        return {
            "phase": progress.phase,
            "percent": progress.percent,
            "current_file": progress.current_file,
            "live_vuln_count": progress.live_vuln_count,
            "files_scanned": progress.files_scanned,
            "total_files": progress.total_files,
            "eta_seconds": progress.eta_seconds,
        }
