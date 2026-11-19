"""
Prometheus-compatible metrics endpoint.

Serves metrics in Prometheus text exposition format at /metrics.
No authentication required (standard for metrics endpoints).
Excluded from OpenAPI schema.
"""

from fastapi import APIRouter, Response

from app.services.metrics import get_metrics

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint.

    Returns all application metrics in Prometheus text exposition format.
    """
    metrics = get_metrics()
    content = metrics.format_prometheus()
    return Response(
        content=content,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
