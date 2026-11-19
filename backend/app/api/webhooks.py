"""
Webhook API Routes — thin HTTP adapter for GitHub webhooks.

All security logic (signature verification, replay protection, event
routing) lives in app.services.github_webhook.  This route file only
maps HTTP requests to the service entrypoint and translates structured
exceptions to HTTP responses.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.github_webhook import (
    process_webhook,
    WebhookResult,
    InvalidSignatureError,
    ReplayAttackDetected,
    UnsupportedEventError,
    RepositoryNotFoundError,
)
from app.core.logging import get_logger

logger = get_logger("api_webhooks")
router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@router.post("/github")
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """GitHub webhook receiver.

    Delegates all processing to the webhook service layer.
    Maps service exceptions to appropriate HTTP status codes.
    """
    # Extract raw body + GitHub headers
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    event_type = request.headers.get("X-GitHub-Event", "")
    delivery_id = request.headers.get("X-GitHub-Delivery", "")

    # Resolve session manager from app state
    session_manager = getattr(request.app.state, "session_manager", None)
    if session_manager is None:
        raise HTTPException(
            status_code=503,
            detail="Scan service not available — server starting up",
        )

    # Delegate to service layer, map exceptions to HTTP responses
    try:
        result: WebhookResult = await process_webhook(
            db=db,
            body=body,
            event_type=event_type,
            delivery_id=delivery_id,
            signature=signature,
            session_manager=session_manager,
        )
    except InvalidSignatureError:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    except ReplayAttackDetected as exc:
        return {"status": "already_processed", "delivery_id": exc.delivery_id}
    except UnsupportedEventError as exc:
        return {"status": "ignored", "event": exc.event_type}
    except RepositoryNotFoundError:
        return {"status": "ignored", "reason": "repository not connected"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Commit DB changes on success
    await db.commit()

    # Build HTTP response from structured result
    response = {
        "status": "accepted" if result.accepted else "ignored",
        "event": result.event_type,
    }
    if result.scan_id:
        response["scan_id"] = str(result.scan_id)
    if result.scan_enqueued:
        response["scan_enqueued"] = True
    if result.detail:
        response.update(result.detail)

    return response
