"""
File Viewer API — Serves source file content for vulnerability context viewing.

Security:
  - Multi-tenant isolation: only scan owner can access file content
  - Path traversal prevention via filename validation
  - Content returned as plain text (never HTML-rendered)
  - File size capped to prevent memory abuse
"""

import os
import re
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.auth.jwt_handler import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.chunk import ScanChunk
from app.core.logging import get_logger

logger = get_logger("api_file_viewer")
router = APIRouter(prefix="/scans", tags=["File Viewer"])

# Maximum file content size to serve (2 MB)
MAX_CONTENT_SIZE = 2 * 1024 * 1024

# Path traversal patterns
_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]|[/\\]\.\.")


def _sanitize_filename(name: str) -> str:
    """Strip path traversal attempts and normalize separators."""
    if _PATH_TRAVERSAL_RE.search(name):
        raise HTTPException(status_code=400, detail="Invalid file name")
    # Normalize backslashes to forward slashes
    return name.replace("\\", "/")


@router.get("/{scan_id}/file")
async def get_file_for_vulnerability(
    scan_id: UUID,
    file_name: str = Query(..., description="Name of the file to view"),
    detection_id: Optional[str] = Query(None, description="Vulnerability detection ID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve source file content with vulnerability highlight context.

    Multi-tenant: verifies scan belongs to the authenticated user.
    Returns file content from scan chunks (paste/upload) or reconstructed
    from scan artifacts.

    Response shape:
    {
        "file_name": "auth.py",
        "content": "...full file content...",
        "highlight_line": 42,
        "context_start": 37,
        "context_end": 47,
        "total_lines": 120,
        "vulnerability": {
            "id": "...",
            "severity": "critical",
            "confidence": 0.91,
            "type": "SQL Injection",
            "detection_id": "...",
            "impact": "...",
            "remediation": "...",
            "owasp_mapping": "...",
            "category": "..."
        }
    }
    """
    # ── 1. Validate scan ownership (multi-tenant isolation) ─────
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # ── 2. Sanitize file name ──────────────────────────────────
    safe_name = _sanitize_filename(file_name)

    # ── 3. Find the vulnerability ──────────────────────────────
    vuln_query = select(Vulnerability).where(
        Vulnerability.scan_id == scan_id,
        Vulnerability.file_name == safe_name,
    )
    if detection_id:
        vuln_query = vuln_query.where(Vulnerability.id == detection_id)

    vuln_result = await db.execute(vuln_query)
    vuln = vuln_result.scalar_one_or_none()

    if not vuln:
        # Try partial match on filename (basename match)
        basename = os.path.basename(safe_name)
        vuln_result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.scan_id == scan_id,
                Vulnerability.file_name.ilike(f"%{basename}"),
            )
        )
        vuln = vuln_result.scalars().first()

    if not vuln:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found for the specified file",
        )

    # ── 4. Retrieve file content ───────────────────────────────
    content = await _get_file_content(db, scan_id, safe_name, scan)

    if content is None:
        raise HTTPException(
            status_code=404,
            detail="Source file content not available. "
                   "File content is only retained for paste and upload scans.",
        )

    # Size guard
    if len(content.encode("utf-8", errors="ignore")) > MAX_CONTENT_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File too large to display in viewer",
        )

    # ── 5. Compute highlight context ───────────────────────────
    lines = content.split("\n")
    total_lines = len(lines)
    highlight_line = vuln.line_reference or 1
    highlight_line = max(1, min(highlight_line, total_lines))
    context_start = max(1, highlight_line - 5)
    context_end = min(total_lines, highlight_line + 5)

    # ── 6. Build response ──────────────────────────────────────
    return {
        "file_name": safe_name,
        "content": content,
        "highlight_line": highlight_line,
        "context_start": context_start,
        "context_end": context_end,
        "total_lines": total_lines,
        "vulnerability": {
            "id": str(vuln.id),
            "severity": vuln.severity,
            "confidence": vuln.confidence or 0.0,
            "type": vuln.vulnerability_type,
            "detection_id": str(vuln.id),
            "impact": vuln.impact or "",
            "remediation": vuln.remediation or "",
            "owasp_mapping": vuln.owasp_mapping or "",
            "category": vuln.category or "",
        },
    }


async def _get_file_content(
    db: AsyncSession,
    scan_id: UUID,
    file_name: str,
    scan: Scan,
) -> Optional[str]:
    """Retrieve file content from scan chunks or scan artifacts.

    Checks multiple sources:
    1. ScanChunk table (paste/upload scans store content here)
    2. Vulnerability code_snippet field (fallback for partial content)
    """
    # ── Source 1: ScanChunk (full file content) ────────────────
    basename = os.path.basename(file_name)

    # Try exact match first, then basename match
    for match_expr in [
        ScanChunk.file_name == file_name,
        ScanChunk.file_name.ilike(f"%{basename}"),
    ]:
        result = await db.execute(
            select(ScanChunk)
            .where(ScanChunk.scan_id == scan_id, match_expr)
            .order_by(ScanChunk.chunk_index)
        )
        chunks = result.scalars().all()
        if chunks:
            # Reconstruct full file from ordered chunks
            parts = [c.chunk_content for c in chunks if c.chunk_content]
            if parts:
                return "\n".join(parts) if len(parts) > 1 else parts[0]

    # ── Source 2: Vulnerability code_snippet (partial) ─────────
    vuln_result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.scan_id == scan_id,
            Vulnerability.file_name == file_name,
        )
    )
    vuln = vuln_result.scalar_one_or_none()
    if vuln and vuln.code_snippet:
        snippet = vuln.code_snippet
        if isinstance(snippet, dict):
            return snippet.get("content", snippet.get("code", ""))
        if isinstance(snippet, str):
            return snippet

    return None
