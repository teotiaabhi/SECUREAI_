"""
Queue backend factory — selects backend based on configuration.

Usage:
    from app.queue.factory import create_queue_backend
    backend = create_queue_backend(settings)
"""

from app.queue.base import QueueBackend
from app.core.logging import get_logger

logger = get_logger("queue.factory")


def create_queue_backend(settings) -> QueueBackend:
    """Create a queue backend based on configuration.

    Args:
        settings: Application settings with QUEUE_BACKEND and QUEUE_REDIS_URL.

    Returns:
        QueueBackend instance (MemoryQueueBackend or RedisQueueBackend).
    """
    backend_type = getattr(settings, "QUEUE_BACKEND", "memory").lower()

    if backend_type == "redis":
        redis_url = getattr(settings, "QUEUE_REDIS_URL", "")
        if not redis_url:
            logger.warning(
                "redis_url_empty",
                message="QUEUE_REDIS_URL not set, falling back to memory backend",
            )
            backend_type = "memory"
        else:
            from app.queue.redis_backend import RedisQueueBackend
            logger.info("queue_backend_selected", backend="redis")
            return RedisQueueBackend(redis_url=redis_url)

    from app.queue.memory_backend import MemoryQueueBackend
    logger.info("queue_backend_selected", backend="memory")
    return MemoryQueueBackend()
