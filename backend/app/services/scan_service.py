"""
Scan Service — Orchestrates the full scan pipeline.
"""

import asyncio
import time
import uuid
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.models.chunk import ScanChunk
from app.services.ingestion import IngestedFile, ingest_paste, ingest_github
from app.scanner.chunk_engine import chunk_files
from engine import scan_files
from app.scanner.aggregator import aggregate_findings
from app.scanner.risk_engine import assess_risk
from app.ai.router import analyze_chunks
from app.ai.confidence_engine import merge_rule_and_ai_findings
from app.core.logging import get_logger

logger = get_logger("scan_service")

# In-memory progress tracking (would use Redis in production)
_scan_progress: dict = {}


def get_scan_progress(scan_id: str) -> dict:
    return _scan_progress.get(scan_id, {})


def update_scan_progress(scan_id: str, **kwargs):
    if scan_id not in _scan_progress:
        _scan_progress[scan_id] = {}
    _scan_progress[scan_id].update(kwargs)


def cancel_scan(scan_id: str):
    update_scan_progress(scan_id, cancelled=True)


async def run_scan(
    db: AsyncSession,
    scan: Scan,
    files: List[IngestedFile],
    depth: str = "standard",
    use_ai: bool = True,
) -> Scan:
    """Execute the full scan pipeline."""
    scan_id = str(scan.id)
    start_time = time.time()

    try:
        # Phase 1: Uploading / Ingestion
        update_scan_progress(scan_id, phase="uploading", percent=5, current_file="", live_vulns=0)
        scan.status = ScanStatus.UPLOADING
        scan.total_files = len(files)
        await db.flush()

        # Filter out files with errors
        valid_files = [f for f in files if not f.errors]
        if not valid_files:
            scan.status = ScanStatus.FAILED
            scan.error_message = "No valid files to scan"
            await db.flush()
            return scan

        # Phase 2: Chunking & Analysis
        update_scan_progress(scan_id, phase="analyzing", percent=15)
        scan.status = ScanStatus.ANALYZING
        await db.flush()

        chunks = chunk_files(valid_files)
        total_chunks = len(chunks)
        update_scan_progress(scan_id, total_chunks=total_chunks)

        # Store chunks in DB
        for chunk in chunks:
            db_chunk = ScanChunk(
                scan_id=scan.id,
                file_name=chunk.file_name,
                chunk_index=chunk.chunk_index,
                token_size=chunk.token_estimate,
                chunk_content=None,  # Don't store raw code
                flagged_by_rule=None,
            )
            db.add(db_chunk)
        await db.flush()

        # Rule engine scan — new YAML-based engine replaces hardcoded rules
        rule_findings = scan_files(valid_files)
        update_scan_progress(scan_id, percent=40, live_vulns=len(rule_findings))

        # Phase 3: AI Analysis (if enabled)
        ai_findings = []
        if use_ai and depth != "basic":
            update_scan_progress(scan_id, phase="ai_reasoning", percent=50)
            scan.status = ScanStatus.AI_REASONING
            await db.flush()

            try:
                ai_findings = await analyze_chunks(chunks, depth)
            except Exception as e:
                logger.error("ai_analysis_failed", error=str(e))
                # Continue with rule-only results

            update_scan_progress(scan_id, percent=75)

        # Check if cancelled
        if _scan_progress.get(scan_id, {}).get("cancelled"):
            scan.status = ScanStatus.CANCELLED
            await db.flush()
            return scan

        # Phase 4: Merge, aggregate, assess risk
        update_scan_progress(scan_id, phase="generating_report", percent=85)
        scan.status = ScanStatus.GENERATING_REPORT
        await db.flush()

        # Merge rule and AI findings
        merged = merge_rule_and_ai_findings(rule_findings, ai_findings)

        # Risk assessment
        risk = assess_risk(
            aggregate_findings(rule_findings),
            len(valid_files),
        )

        # Store vulnerabilities
        for finding in merged:
            vuln = Vulnerability(
                scan_id=scan.id,
                file_name=finding["file_name"],
                vulnerability_type=finding["vulnerability_type"],
                severity=finding["severity"],
                confidence=finding["confidence"],
                line_reference=finding.get("line_reference"),
                impact=finding.get("impact", ""),
                remediation=finding.get("remediation", ""),
                exploit_example=finding.get("exploit_example", ""),
                owasp_mapping=finding.get("owasp_mapping", ""),
                category=finding.get("category", ""),
                status="open",
            )
            db.add(vuln)

        # Update scan record
        dist = risk["severity_distribution"]
        scan.total_vulnerabilities = len(merged)
        scan.critical_count = dist.get("critical", 0)
        scan.high_count = dist.get("high", 0)
        scan.medium_count = dist.get("medium", 0)
        scan.low_count = dist.get("low", 0)
        scan.info_count = dist.get("info", 0)
        scan.security_score = risk["security_score"]
        scan.confidence_score = sum(f["confidence"] for f in merged) / max(len(merged), 1)
        scan.grade = risk["grade"]
        scan.duration = round(time.time() - start_time, 1)
        scan.status = ScanStatus.COMPLETE

        await db.flush()
        update_scan_progress(scan_id, phase="complete", percent=100, live_vulns=len(merged))

        logger.info(
            "scan_complete",
            scan_id=scan_id,
            files=len(valid_files),
            vulns=len(merged),
            score=risk["security_score"],
            grade=risk["grade"],
            duration=scan.duration,
        )
        return scan

    except Exception as e:
        logger.error("scan_failed", scan_id=scan_id, error=str(e))
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)[:1024]
        scan.duration = round(time.time() - start_time, 1)
        await db.flush()
        return scan
