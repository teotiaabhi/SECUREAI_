"""
GitHub Webhook Service — secure webhook processing layer.

Single entrypoint: process_webhook() handles signature verification,
two-layer replay protection, event dispatch, and scan enqueuing via
the orchestration layer.

Structured exceptions allow the API route to remain a thin HTTP adapter.
"""

import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from uuid import UUID
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cicd import Repository, Commit, ScanMode, WebhookDelivery
from app.models.scan import Scan, ScanStatus
from app.core.logging import get_logger
from app.core.config import get_settings
from app.services.metrics import get_metrics

logger = get_logger("github_webhook")


# ── Structured Exceptions ───────────────────────────────────

class WebhookError(Exception):
    """Base exception for webhook processing errors."""


class InvalidSignatureError(WebhookError):
    """HMAC-SHA256 signature verification failed."""

    def __init__(self, github_repo_id: Optional[int] = None):
        self.github_repo_id = github_repo_id
        super().__init__("Invalid webhook signature")


class ReplayAttackDetected(WebhookError):
    """Delivery ID has already been processed (replay attempt)."""

    def __init__(self, delivery_id: str):
        self.delivery_id = delivery_id
        super().__init__(f"Replay detected: {delivery_id}")


class UnsupportedEventError(WebhookError):
    """GitHub event type is not handled by this service."""

    def __init__(self, event_type: str):
        self.event_type = event_type
        super().__init__(f"Unsupported event: {event_type}")


class RepositoryNotFoundError(WebhookError):
    """No active repository record matches the webhook's repo ID."""

    def __init__(self, github_repo_id: int):
        self.github_repo_id = github_repo_id
        super().__init__(f"Repository not found: {github_repo_id}")


# ── Return Contract ─────────────────────────────────────────

@dataclass
class WebhookResult:
    """Structured result from process_webhook()."""
    accepted: bool
    event_type: str
    repository_id: Optional[UUID] = None
    scan_enqueued: bool = False
    scan_id: Optional[UUID] = None
    detail: dict = field(default_factory=dict)


# ── Replay Protection (two-layer) ───────────────────────────

_processed_deliveries: OrderedDict = OrderedDict()
_MAX_DELIVERIES = 10_000


async def _check_replay(delivery_id: str, db: AsyncSession) -> bool:
    """Two-layer replay check: in-memory LRU + DB persistence.

    Returns True if this delivery has already been processed.
    """
    if not delivery_id:
        return False

    # Layer 1: in-memory (hot path)
    if delivery_id in _processed_deliveries:
        return True

    # Layer 2: DB (cold path / post-restart)
    result = await db.execute(
        select(WebhookDelivery.id).where(
            WebhookDelivery.delivery_id == delivery_id
        )
    )
    if result.scalar_one_or_none() is not None:
        _processed_deliveries[delivery_id] = True
        while len(_processed_deliveries) > _MAX_DELIVERIES:
            _processed_deliveries.popitem(last=False)
        return True

    return False


async def _record_delivery(
    delivery_id: str,
    event_type: str,
    repo_id: UUID,
    db: AsyncSession,
) -> None:
    """Persist delivery ID to both memory cache and DB."""
    if not delivery_id:
        return

    _processed_deliveries[delivery_id] = True
    while len(_processed_deliveries) > _MAX_DELIVERIES:
        _processed_deliveries.popitem(last=False)

    record = WebhookDelivery(
        delivery_id=delivery_id,
        event_type=event_type,
        repository_id=repo_id,
    )
    db.add(record)
    await db.flush()


# ── Signature Verification ──────────────────────────────────

def verify_webhook_signature(
    payload_body: bytes, signature: str, secret: str
) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature.

    Uses constant-time comparison to prevent timing attacks.
    """
    if not signature or not secret:
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def generate_webhook_secret() -> str:
    """Generate a cryptographically secure webhook secret."""
    return secrets.token_hex(32)


# ── Repository Lookup ───────────────────────────────────────

async def lookup_repository(
    db: AsyncSession, github_repo_id: int
) -> Optional[Repository]:
    """Look up an active Repository by GitHub's numeric repo ID."""
    result = await db.execute(
        select(Repository).where(
            Repository.github_repo_id == github_repo_id,
            Repository.is_active.is_(True),
        )
    )
    return result.scalar_one_or_none()


# ── Idempotent Scan Guard ───────────────────────────────────

_ACTIVE_STATUSES = {
    ScanStatus.PENDING.value,
    ScanStatus.QUEUED.value,
    ScanStatus.CLONING.value,
    ScanStatus.EXTRACTING.value,
    ScanStatus.CLASSIFYING.value,
    ScanStatus.SCANNING.value,
    ScanStatus.AI_VALIDATING.value,
    ScanStatus.REPORTING.value,
}


async def _check_active_scan_exists(
    db: AsyncSession,
    repository_id: UUID,
    head_commit_sha: str,
    pr_number: Optional[int] = None,
) -> Optional[Scan]:
    """Check for duplicate active scan (same commit + PR combination).

    Prevents double-enqueue on webhook retries or rapid synchronize events.
    """
    conditions = [
        Scan.repository_id == repository_id,
        Scan.head_commit_sha == head_commit_sha,
        Scan.status.in_(_ACTIVE_STATUSES),
    ]
    if pr_number is not None:
        conditions.append(Scan.pr_number == pr_number)

    result = await db.execute(
        select(Scan).where(and_(*conditions)).limit(1)
    )
    return result.scalar_one_or_none()


# ── Event Handlers ──────────────────────────────────────────

async def _handle_push(
    db: AsyncSession,
    payload: dict,
    repo: Repository,
    session_manager,
) -> WebhookResult:
    """Push to default branch → full baseline scan."""
    ref = payload.get("ref", "")
    branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref

    if branch != repo.default_branch:
        logger.info(
            "push_ignored_non_default_branch",
            repo=repo.full_name, branch=branch,
            default_branch=repo.default_branch,
        )
        return WebhookResult(
            accepted=False, event_type="push",
            repository_id=repo.id,
            detail={"reason": "non_default_branch", "branch": branch},
        )

    head_commit = payload.get("head_commit") or {}
    head_sha = head_commit.get("id", "") or payload.get("after", "")

    if not head_sha or head_sha == "0" * 40:
        logger.info("push_ignored_no_commit", repo=repo.full_name)
        return WebhookResult(
            accepted=False, event_type="push",
            repository_id=repo.id,
            detail={"reason": "no_commit"},
        )

    head_sha = head_sha[:40]

    # Idempotency guard
    existing = await _check_active_scan_exists(db, repo.id, head_sha)
    if existing:
        logger.info(
            "push_scan_deduplicated", repo=repo.full_name,
            commit=head_sha[:8], existing_scan_id=str(existing.id),
        )
        return WebhookResult(
            accepted=True, event_type="push",
            repository_id=repo.id, scan_enqueued=False,
            scan_id=existing.id,
            detail={"status": "already_running", "commit": head_sha[:8]},
        )

    # Create Commit record
    commit = Commit(
        repository_id=repo.id,
        sha=head_sha,
        message=(head_commit.get("message", "") or "")[:512],
        author=(head_commit.get("author", {}).get("username", "") or "")[:255],
        branch=branch[:255],
    )
    db.add(commit)

    # Create Scan record, enqueue via orchestration entrypoint
    scan = Scan(
        user_id=repo.user_id,
        repo_name=repo.full_name,
        status=ScanStatus.PENDING,
        scan_mode=ScanMode.FULL.value,
        repository_id=repo.id,
        head_commit_sha=head_sha,
        config={
            "depth": "standard",
            "categories": {},
            "ai_reasoning": True,
            "webhook_triggered": True,
        },
    )
    db.add(scan)
    await db.flush()

    commit.scan_id = scan.id
    await db.flush()

    await session_manager.enqueue_scan(
        db=db,
        scan_id=scan.id,
        user_id=repo.user_id,
        is_paid=False,
        source_type="github",
        repo_url=f"https://github.com/{repo.full_name}",
        branch=branch,
    )

    logger.info(
        "push_scan_enqueued", repo=repo.full_name,
        scan_id=str(scan.id), commit=head_sha[:8],
    )

    return WebhookResult(
        accepted=True, event_type="push",
        repository_id=repo.id, scan_enqueued=True,
        scan_id=scan.id,
        detail={"scan_mode": "full", "commit": head_sha[:8]},
    )


async def _handle_pull_request(
    db: AsyncSession,
    payload: dict,
    repo: Repository,
    session_manager,
) -> WebhookResult:
    """PR opened/synchronized/reopened → diff scan."""
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        logger.info("pr_ignored_action", repo=repo.full_name, action=action)
        return WebhookResult(
            accepted=False, event_type="pull_request",
            repository_id=repo.id,
            detail={"reason": "ignored_action", "action": action},
        )

    pr = payload.get("pull_request") or {}
    pr_number = payload.get("number") or pr.get("number")
    if not pr_number:
        logger.info("pr_ignored_no_number", repo=repo.full_name)
        return WebhookResult(
            accepted=False, event_type="pull_request",
            repository_id=repo.id,
            detail={"reason": "no_pr_number"},
        )

    base_sha = (pr.get("base") or {}).get("sha", "")
    head_sha = (pr.get("head") or {}).get("sha", "")
    head_branch = (pr.get("head") or {}).get("ref", "")

    if not head_sha:
        logger.info("pr_ignored_no_head_sha", repo=repo.full_name)
        return WebhookResult(
            accepted=False, event_type="pull_request",
            repository_id=repo.id,
            detail={"reason": "no_head_sha"},
        )

    head_sha = head_sha[:40]

    # Idempotency guard
    existing = await _check_active_scan_exists(
        db, repo.id, head_sha, pr_number=pr_number,
    )
    if existing:
        logger.info(
            "pr_scan_deduplicated", repo=repo.full_name,
            pr_number=pr_number, head_sha=head_sha[:8],
            existing_scan_id=str(existing.id),
        )
        return WebhookResult(
            accepted=True, event_type="pull_request",
            repository_id=repo.id, scan_enqueued=False,
            scan_id=existing.id,
            detail={
                "status": "already_running",
                "pr_number": pr_number,
                "head_commit": head_sha[:8],
            },
        )

    # Create Commit record
    commit = Commit(
        repository_id=repo.id,
        sha=head_sha,
        message=(pr.get("title", "") or "")[:512],
        author=((pr.get("user") or {}).get("login", "") or "")[:255],
        branch=head_branch[:255],
        pr_number=pr_number,
    )
    db.add(commit)

    # Create Scan record, enqueue via orchestration entrypoint
    scan = Scan(
        user_id=repo.user_id,
        repo_name=repo.full_name,
        status=ScanStatus.PENDING,
        scan_mode=ScanMode.DIFF.value,
        repository_id=repo.id,
        base_commit_sha=base_sha[:40] if base_sha else None,
        head_commit_sha=head_sha,
        pr_number=pr_number,
        config={
            "depth": "standard",
            "categories": {},
            "ai_reasoning": True,
            "webhook_triggered": True,
            "pr_number": pr_number,
        },
    )
    db.add(scan)
    await db.flush()

    commit.scan_id = scan.id
    await db.flush()

    await session_manager.enqueue_scan(
        db=db,
        scan_id=scan.id,
        user_id=repo.user_id,
        is_paid=False,
        source_type="github",
        repo_url=f"https://github.com/{repo.full_name}",
        branch=head_branch,
    )

    logger.info(
        "pr_scan_enqueued", repo=repo.full_name,
        scan_id=str(scan.id), pr_number=pr_number,
        head_sha=head_sha[:8],
    )

    return WebhookResult(
        accepted=True, event_type="pull_request",
        repository_id=repo.id, scan_enqueued=True,
        scan_id=scan.id,
        detail={
            "scan_mode": "diff",
            "pr_number": pr_number,
            "head_commit": head_sha[:8],
        },
    )


# ── Main Entrypoint ─────────────────────────────────────────

_SUPPORTED_EVENTS = {"push", "pull_request"}


async def process_webhook(
    *,
    db: AsyncSession,
    body: bytes,
    event_type: str,
    delivery_id: str,
    signature: str,
    session_manager,
) -> WebhookResult:
    """Unified webhook entrypoint — verifies, routes, and enqueues.

    Args:
        db: Async database session.
        body: Raw request body bytes (for signature verification).
        event_type: Value of X-GitHub-Event header.
        delivery_id: Value of X-GitHub-Delivery header (for replay protection).
        signature: Value of X-Hub-Signature-256 header.
        session_manager: ScanSessionManager instance.

    Returns:
        WebhookResult with structured fields.

    Raises:
        InvalidSignatureError: HMAC verification failed.
        ReplayAttackDetected: Delivery ID already processed.
        UnsupportedEventError: Event type not in supported set.
        RepositoryNotFoundError: No active repo matches payload.
    """
    settings = get_settings()
    metrics = get_metrics()
    _wh_start = time.monotonic()

    # 1. Validate event type
    if not event_type:
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise UnsupportedEventError("")

    # 2. Replay protection
    if await _check_replay(delivery_id, db):
        logger.info("webhook_replay_rejected", delivery_id=delivery_id)
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise ReplayAttackDetected(delivery_id)

    # 3. Parse payload
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("Invalid JSON payload")

    # 4. Handle ping (no repo needed)
    if event_type == "ping":
        logger.info("webhook_ping_received", delivery_id=delivery_id)
        return WebhookResult(
            accepted=True, event_type="ping",
            detail={"status": "pong"},
        )

    # 5. Reject unsupported events early
    if event_type not in _SUPPORTED_EVENTS:
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise UnsupportedEventError(event_type)

    # 6. Identify repository
    repo_data = payload.get("repository") or {}
    github_repo_id = repo_data.get("id")
    if not github_repo_id:
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise RepositoryNotFoundError(0)

    repo = await lookup_repository(db, github_repo_id)

    # 7. Verify signature (per-repo secret → global fallback)
    secret = (repo.webhook_secret if repo else None) or settings.GITHUB_APP_WEBHOOK_SECRET
    if not secret:
        logger.warning(
            "webhook_no_secret",
            github_repo_id=github_repo_id, event=event_type,
        )
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise InvalidSignatureError(github_repo_id)

    if not verify_webhook_signature(body, signature, secret):
        logger.warning(
            "webhook_signature_invalid",
            github_repo_id=github_repo_id, event=event_type,
            delivery_id=delivery_id,
        )
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise InvalidSignatureError(github_repo_id)

    # 8. Repo must exist and be active
    if not repo:
        metrics.webhook_events_total.inc({"event_type": event_type, "status": "rejected"})
        raise RepositoryNotFoundError(github_repo_id)

    # 9. Record delivery (memory + DB) — after all validation passes
    await _record_delivery(delivery_id, event_type, repo.id, db)

    # 10. Dispatch to handler
    if event_type == "push":
        result = await _handle_push(db, payload, repo, session_manager)
    else:
        result = await _handle_pull_request(db, payload, repo, session_manager)

    metrics.webhook_events_total.inc({"event_type": event_type, "status": "accepted"})
    metrics.webhook_processing_seconds.observe(time.monotonic() - _wh_start, {"event_type": event_type})

    return result
