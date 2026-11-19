"""
Delta Engine — vulnerability delta computation between scans and baselines.

Compares current scan findings against a repository's baseline to classify
each finding as NEW, FIXED, or UNCHANGED. Detects regressions (new critical/high).

Pure computation layer:
  - compute_delta() is stateless — no DB reads or writes
  - store_delta() persists a pre-computed delta to the DB (called by orchestrator)

No orchestration logic. No GitHub calls. No baseline management.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cicd import BaselineFinding, VulnerabilityDelta
from app.models.vulnerability import Vulnerability
from app.services.baseline_service import compute_detection_id
from app.core.logging import get_logger

logger = get_logger("delta_engine")

# Severities that trigger regression flag
_REGRESSION_SEVERITIES = frozenset({"critical", "high"})


# ── Structured Result ───────────────────────────────────────

@dataclass
class DeltaFinding:
    """A single finding within a delta report."""
    file_name: str
    vulnerability_type: str
    severity: str
    confidence: float
    line_reference: Optional[int]
    detection_id: str
    status: str  # "new" | "fixed" | "unchanged"


@dataclass
class DeltaResult:
    """Structured result from compute_delta()."""
    new_findings: List[DeltaFinding] = field(default_factory=list)
    fixed_findings: List[DeltaFinding] = field(default_factory=list)
    unchanged_findings: List[DeltaFinding] = field(default_factory=list)
    regression_detected: bool = False
    severity_summary: Dict[str, int] = field(default_factory=dict)

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def unchanged_count(self) -> int:
        return len(self.unchanged_findings)

    def __getitem__(self, key: str):
        """Dict-style access for backward compatibility with orchestrator."""
        return self.to_dict()[key]

    def get(self, key: str, default=None):
        """Dict-style .get() for backward compatibility."""
        return self.to_dict().get(key, default)

    def to_dict(self) -> dict:
        """Serialize to dict for JSON storage / API responses."""
        def _serialize(f: DeltaFinding) -> dict:
            return {
                "file_name": f.file_name,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "line_reference": f.line_reference,
                "detection_id": f.detection_id,
                "status": f.status,
            }

        return {
            "new_findings": [_serialize(f) for f in self.new_findings],
            "fixed_findings": [_serialize(f) for f in self.fixed_findings],
            "unchanged_findings": [_serialize(f) for f in self.unchanged_findings],
            "new_count": self.new_count,
            "fixed_count": self.fixed_count,
            "unchanged_count": self.unchanged_count,
            "regression_detected": self.regression_detected,
            "severity_summary": self.severity_summary,
        }


# ── Core Delta Computation ──────────────────────────────────

def compute_delta(
    current_vulnerabilities: List[Vulnerability],
    baseline_findings: List[BaselineFinding],
) -> DeltaResult:
    """Compare current scan findings against baseline findings.

    Uses detection_id (deterministic SHA-256 fingerprint) to match findings
    across scans. Set operations determine which are new, fixed, or unchanged.

    This function is pure computation — no DB reads, no DB writes.

    Args:
        current_vulnerabilities: Vulnerability ORM objects from the current scan.
        baseline_findings: Active BaselineFinding ORM objects from the repo baseline.

    Returns:
        DeltaResult with new/fixed/unchanged findings and regression flag.
    """
    # Build current finding map: detection_id -> (Vulnerability, detection_id)
    current_map: Dict[str, dict] = {}
    for vuln in current_vulnerabilities:
        det_id = compute_detection_id(
            file_path=vuln.file_name,
            rule_id=vuln.vulnerability_type,
            line_reference=vuln.line_reference or 0,
            severity=vuln.severity,
        )
        if det_id not in current_map:
            current_map[det_id] = {
                "file_name": vuln.file_name,
                "vulnerability_type": vuln.vulnerability_type,
                "severity": vuln.severity,
                "confidence": vuln.confidence or 0.0,
                "line_reference": vuln.line_reference,
            }

    # Build baseline map: detection_id -> BaselineFinding metadata
    baseline_map: Dict[str, dict] = {}
    for bf in baseline_findings:
        baseline_map[bf.detection_id] = {
            "file_name": bf.file_name,
            "vulnerability_type": bf.vulnerability_type,
            "severity": bf.severity,
            "line_reference": bf.line_reference,
        }

    current_ids = set(current_map.keys())
    baseline_ids = set(baseline_map.keys())

    # Set operations
    new_ids = current_ids - baseline_ids
    fixed_ids = baseline_ids - current_ids
    unchanged_ids = current_ids & baseline_ids

    # Build structured finding lists
    new_findings = [
        DeltaFinding(
            file_name=current_map[did]["file_name"],
            vulnerability_type=current_map[did]["vulnerability_type"],
            severity=current_map[did]["severity"],
            confidence=current_map[did]["confidence"],
            line_reference=current_map[did]["line_reference"],
            detection_id=did,
            status="new",
        )
        for did in new_ids
    ]

    fixed_findings = [
        DeltaFinding(
            file_name=baseline_map[did]["file_name"],
            vulnerability_type=baseline_map[did]["vulnerability_type"],
            severity=baseline_map[did]["severity"],
            confidence=0.0,
            line_reference=baseline_map[did]["line_reference"],
            detection_id=did,
            status="fixed",
        )
        for did in fixed_ids
    ]

    unchanged_findings = [
        DeltaFinding(
            file_name=current_map[did]["file_name"],
            vulnerability_type=current_map[did]["vulnerability_type"],
            severity=current_map[did]["severity"],
            confidence=current_map[did]["confidence"],
            line_reference=current_map[did]["line_reference"],
            detection_id=did,
            status="unchanged",
        )
        for did in unchanged_ids
    ]

    # Severity summary for new findings
    severity_summary: Dict[str, int] = {}
    for f in new_findings:
        severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1

    # Regression detection: any new critical or high
    regression_detected = any(
        f.severity in _REGRESSION_SEVERITIES for f in new_findings
    )

    result = DeltaResult(
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        unchanged_findings=unchanged_findings,
        regression_detected=regression_detected,
        severity_summary=severity_summary,
    )

    logger.info(
        "delta_computed",
        new=result.new_count,
        fixed=result.fixed_count,
        unchanged=result.unchanged_count,
        regression=regression_detected,
    )

    return result


# ── Persistence (called by orchestrator) ────────────────────

async def store_delta(
    db: AsyncSession,
    scan_id: UUID,
    baseline_scan_id: Optional[UUID],
    delta: DeltaResult,
) -> VulnerabilityDelta:
    """Persist a computed delta result to the database.

    Args:
        db: Async database session.
        scan_id: UUID of the scan that produced these findings.
        baseline_scan_id: UUID of the baseline scan (if known).
        delta: DeltaResult from compute_delta().

    Returns:
        The created VulnerabilityDelta ORM object.
    """
    delta_dict = delta.to_dict()

    vuln_delta = VulnerabilityDelta(
        scan_id=scan_id,
        baseline_scan_id=baseline_scan_id,
        new_count=delta.new_count,
        fixed_count=delta.fixed_count,
        unchanged_count=delta.unchanged_count,
        regression_detected=delta.regression_detected,
        delta_detail={
            "new_findings": delta_dict["new_findings"],
            "fixed_findings": delta_dict["fixed_findings"],
            "severity_summary": delta_dict["severity_summary"],
        },
    )
    db.add(vuln_delta)
    await db.flush()

    logger.info(
        "delta_stored",
        scan_id=str(scan_id),
        new=delta.new_count,
        fixed=delta.fixed_count,
    )

    return vuln_delta
