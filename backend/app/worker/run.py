"""
Standalone worker CLI entrypoint.

Usage:
    python -m app.worker.run

Runs a ScanWorker process that pulls scan tasks from the configured
queue backend (memory or Redis) and executes them independently
of the main FastAPI API server.

Handles SIGTERM and SIGINT for graceful shutdown.
"""

import asyncio
import signal
import sys
import os

# Ensure the backend directory is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


async def main():
    from app.core.config import get_settings
    from app.core.logging import setup_logging, get_logger
    from app.db.session import async_session_factory
    from app.queue.factory import create_queue_backend
    from app.worker.scan_worker import ScanWorker

    settings = get_settings()
    setup_logging(debug=settings.DEBUG)
    logger = get_logger("worker.run")

    logger.info("standalone_worker_starting", worker_mode="standalone")

    # Create queue backend
    queue = create_queue_backend(settings)

    # Create worker
    worker_id = settings.WORKER_ID or None
    worker = ScanWorker(
        queue=queue,
        db_factory=async_session_factory,
        worker_id=worker_id,
    )

    # Signal handling for graceful shutdown
    shutdown_event = asyncio.Event()

    def _signal_handler(sig, frame):
        logger.info("shutdown_signal_received", signal=sig)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Start worker
    await worker.start()
    logger.info("standalone_worker_ready", worker_id=worker.worker_id)

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Graceful shutdown
    logger.info("standalone_worker_shutting_down")
    await worker.stop()
    await queue.shutdown()
    logger.info("standalone_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
