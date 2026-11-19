"""
CI/CD Integration schemas — request/response DTOs for repositories,
webhooks, delta reports, baselines, and vulnerability timelines.

Pure schema layer: no DB/ORM imports. All models are Pydantic BaseModel.
"""

from pydantic import BaseModel, Field
from typing import Dict, Optional, List
from uuid import UUID
from datetime import datetime
from enum import Enum


# ── Enums ─────────────────────────────────────────────────

class ScanModeSchema(str, Enum):
    """Schema-layer mirror of ScanMode DB enum."""
    FULL = "full"
    DIFF = "diff"
    FILE_ONLY = "file_only"


# ── Request Models ────────────────────────────────────────

class RepositoryConnectRequest(BaseModel):
    """Connect a GitHub repository for CI/CD scanning."""
    repo_full_name: str = Field(..., description="GitHub repo full name, e.g. 'owner/repo'")
    default_branch: str = "main"


class ManualTriggerRequest(BaseModel):
    """Manually trigger a scan for a connected repository."""
    scan_mode: ScanModeSchema = Field(ScanModeSchema.FULL, description="full | diff | file_only")
    branch: Optional[str] = None
    base_commit: Optional[str] = Field(None, max_length=40)
    head_commit: Optional[str] = Field(None, max_length=40)


# ── Webhook Payload Models ────────────────────────────────
# Lightweight extraction of only the fields we need from GitHub.
# Full payloads are large; we do NOT over-validate them.

class GitHubWebhookHeaders(BaseModel):
    """Extracted GitHub webhook headers."""
    event_type: str = Field(..., description="X-GitHub-Event header value")
    delivery_id: str = Field("", description="X-GitHub-Delivery header value")
    signature: str = Field("", description="X-Hub-Signature-256 header value")


class WebhookRepository(BaseModel):
    """Minimal repository info extracted from webhook payload."""
    id: int = Field(..., description="GitHub's numeric repository ID")
    full_name: str = ""
    default_branch: str = "main"


class PushEventPayload(BaseModel):
    """Fields extracted from a GitHub push webhook event."""
    ref: str = ""
    before: str = Field("", max_length=40)
    after: str = Field("", max_length=40)
    repository: Optional[WebhookRepository] = None
    head_commit: Optional[Dict] = None
    installation: Optional[Dict] = None


class PullRequestEventPayload(BaseModel):
    """Fields extracted from a GitHub pull_request webhook event."""
    action: str = ""
    number: Optional[int] = None
    repository: Optional[WebhookRepository] = None
    pull_request: Optional[Dict] = None
    installation: Optional[Dict] = None

    @property
    def base_sha(self) -> str:
        pr = self.pull_request or {}
        return (pr.get("base") or {}).get("sha", "")

    @property
    def head_sha(self) -> str:
        pr = self.pull_request or {}
        return (pr.get("head") or {}).get("sha", "")

    @property
    def head_branch(self) -> str:
        pr = self.pull_request or {}
        return (pr.get("head") or {}).get("ref", "")

    @property
    def pr_number(self) -> Optional[int]:
        if self.number:
            return self.number
        pr = self.pull_request or {}
        return pr.get("number")


# ── Response Models ───────────────────────────────────────

class RepositoryResponse(BaseModel):
    """Public repository info returned by list/detail endpoints."""
    id: UUID
    full_name: str
    github_repo_id: int
    default_branch: str
    is_active: bool
    installed_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class RepositoryDetailResponse(RepositoryResponse):
    """Extended response when connecting a repo (includes secret)."""
    webhook_url: str
    webhook_secret: str


# ── Delta / Diff Report Models ────────────────────────────

class DeltaFinding(BaseModel):
    """A single finding within a delta report."""
    file_name: str
    vulnerability_type: str
    severity: str
    confidence: float = 0.0
    line_reference: Optional[int] = None
    detection_id: str
    status: str  # "new" | "fixed" | "unchanged"


class DeltaSummary(BaseModel):
    """Aggregate counts for a delta report."""
    new_count: int = 0
    fixed_count: int = 0
    unchanged_count: int = 0
    severity_breakdown: Dict[str, int] = {}


class DeltaReportResponse(BaseModel):
    """Full vulnerability delta report for a diff scan."""
    scan_id: UUID
    baseline_scan_id: Optional[UUID] = None
    new_findings: List[DeltaFinding] = []
    fixed_findings: List[DeltaFinding] = []
    unchanged_findings: List[DeltaFinding] = []
    regression_detected: bool = False
    summary: DeltaSummary = DeltaSummary()


# ── Baseline Models ───────────────────────────────────────

class BaselineResponse(BaseModel):
    """Current baseline summary for a repository."""
    scan_id: Optional[UUID] = None
    commit_sha: str
    finding_count: int
    severity_counts: Dict[str, int] = {}
    created_at: Optional[datetime] = None


# ── Timeline Models ───────────────────────────────────────

class TimelineEntry(BaseModel):
    """Single point in a repository's vulnerability timeline."""
    scan_id: UUID
    commit_sha: str = ""
    scan_mode: str = "full"
    security_score: float = 0.0
    risk_score: float = 0.0
    total_findings: int = 0
    new_findings: int = 0
    fixed_findings: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}


class TimelineResponse(BaseModel):
    """Vulnerability trend over time for a repository."""
    repository: str
    entries: List[TimelineEntry] = []
