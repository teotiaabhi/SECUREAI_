from pydantic import BaseModel, Field
from typing import Any, Dict, Optional, List
from uuid import UUID
from datetime import datetime
from enum import Enum


class ScanDepth(str, Enum):
    BASIC = "basic"
    STANDARD = "standard"
    DEEP = "deep"


class ScanCategoryConfig(BaseModel):
    backend: bool = True
    frontend: bool = True
    api: bool = True
    config: bool = True
    dependencies: bool = True


class ScanConfigRequest(BaseModel):
    depth: ScanDepth = ScanDepth.STANDARD
    categories: ScanCategoryConfig = ScanCategoryConfig()
    ai_reasoning: bool = True
    exploit_examples: bool = True
    secure_rewrite: bool = True


class CodePasteInput(BaseModel):
    code: str = Field(..., max_length=500_000)
    language: str = "auto"
    filename: str = "paste.txt"


class GitHubRepoInput(BaseModel):
    repo_full_name: str  # e.g. "user/repo"
    branch: str = "main"


class ScanStartRequest(BaseModel):
    source_type: str = Field(..., description="paste | upload | github")
    config: ScanConfigRequest = ScanConfigRequest()
    code_paste: Optional[CodePasteInput] = None
    github_repo: Optional[GitHubRepoInput] = None
    repo_name: str = "uploaded-code"
    branch: Optional[str] = None
    tag: Optional[str] = None
    commit: Optional[str] = None


class ScanStatusResponse(BaseModel):
    id: UUID
    status: str
    phase: str = ""
    progress_percent: float = 0.0
    current_file: str = ""
    files_scanned: int = 0
    total_files: int = 0
    chunks_processed: int = 0
    total_chunks: int = 0
    estimated_time_remaining: float = 0.0
    live_vuln_count: int = 0
    queue_position: int = 0


class ScanResultResponse(BaseModel):
    id: UUID
    repo_name: str
    status: str
    total_files: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    security_score: float
    confidence_score: float
    grade: str
    duration: float
    created_at: datetime
    vulnerabilities: List["VulnerabilityResponse"] = []

    model_config = {"from_attributes": True}


class ScanHistoryItem(BaseModel):
    id: UUID
    repo_name: str
    status: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_score: float
    grade: str
    duration: float
    created_at: datetime

    model_config = {"from_attributes": True}


class VulnerabilityResponse(BaseModel):
    id: UUID
    file_name: str = ""
    vulnerability_type: str = ""
    severity: str = "info"
    confidence: Optional[float] = 0.0
    line_reference: Optional[int] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    exploit_example: Optional[str] = None
    owasp_mapping: Optional[str] = None
    category: Optional[str] = None
    status: str = "open"
    code_snippet: Optional[dict] = None

    model_config = {"from_attributes": True}


class ScanReportResponse(BaseModel):
    """Structured scan report with analytics."""
    security_score: float
    confidence_score: float
    grade: str
    total_files: int
    total_findings: int
    severity_counts: Dict[str, int] = {}
    owasp_distribution: Dict[str, int] = {}
    cwe_distribution: Dict[str, int] = {}
    category_distribution: Dict[str, int] = {}
    file_risk_ranking: List[Dict[str, Any]] = []
    executive_summary: str = ""
    posture_summary: str = ""


class ScanCompareResponse(BaseModel):
    """Comparison between two scan reports."""
    score_delta: float
    grade_change: str
    vuln_delta: Dict[str, int] = {}
    total_delta: int = 0
    trend: str = "stable"
