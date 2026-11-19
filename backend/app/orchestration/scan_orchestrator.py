"""
Scan Orchestrator — master pipeline coordinator.

Ties all orchestration components together into a single
execute_scan_pipeline() function that runs the full scan lifecycle:

QUEUED -> CLONING/EXTRACTING -> CLASSIFYING -> SCANNING ->
AI_VALIDATING -> REPORTING -> COMPLETE

Supports two scan modes:
  - FULL: clone entire repo, scan all files, update baseline
  - DIFF: fetch only changed files via GitHub API, scan those,
          compute delta against baseline, post PR comment

Checks cancel_event between phases. Catches all exceptions and
marks the scan FAILED with an error message.
"""

import asyncio
import logging
import os
import tempfile
import time
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import update, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.scan_session import ScanSessionRecord, ScanFile
from app.models.vulnerability import Vulnerability
from app.services.metrics import get_metrics

logger = logging.getLogger("orchestration.scan_orchestrator")


def should_run_ai_validation(settings, findings: list) -> bool:
    """Return whether the optional AI validation phase should run."""
    return bool(
        getattr(settings, "AI_VALIDATION_ENABLED", False)
        and (settings.PPLX_API_KEY or settings.HF_API_TOKEN)
        and findings
    )


async def execute_scan_pipeline(
    scan_id: UUID,
    session_manager,
) -> None:
    """Execute the full scan pipeline for a given scan, with an overall timeout.

    This is the master coordinator that orchestrates:
    1. Ingestion (clone/extract/paste or diff fetch)
    2. File classification
    3. Batch scanning with progress tracking
    4. AI validation of high-severity findings
    5. Report generation and DB persistence
    5b. CI/CD post-processing (delta, baseline, PR comment)

    Args:
        scan_id: UUID of the scan to process.
        session_manager: ScanSessionManager instance for state transitions.
    """
    from app.core.config import get_settings
    settings = get_settings()
    try:
        await asyncio.wait_for(
            _execute_pipeline_inner(scan_id, session_manager),
            timeout=settings.WORKER_TASK_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.error("scan_pipeline_timeout scan_id=%s", scan_id)
        try:
            from app.db.session import async_session_factory
            async with async_session_factory() as db:
                await session_manager.complete_session(
                    scan_id, db,
                    status=ScanStatus.FAILED.value,
                    error_message="Scan timed out (pipeline timeout)",
                )
        except Exception as inner_exc:
            logger.error(
                "Failed to mark scan %s as failed after timeout: %s", scan_id, inner_exc
            )


async def _execute_pipeline_inner(
    scan_id: UUID,
    session_manager,
) -> None:
    """Inner implementation of the scan pipeline."""
    from app.db.session import async_session_factory
    from app.orchestration.progress_tracker import ScanProgressTracker
    from app.orchestration.cleanup_service import CleanupService
    from app.orchestration.report_aggregator import ReportAggregator
    from app.orchestration.chunk_dispatcher import ChunkDispatcher
    from app.orchestration.parallel_controller import ParallelScanController, ScanCancelledError, MemoryLimitExceeded
    from app.orchestration.ai_validation_queue import AIValidationQueue
    from app.orchestration.scan_diagnostics import ScanDiagnostics
    from app.services.ingestion_v2 import RepoIngestionService
    from app.core.config import get_settings
    from engine.models import EngineFinding

    settings = get_settings()
    cancel_event = session_manager.get_cancel_event(scan_id)
    progress = ScanProgressTracker(scan_id)
    cleanup = CleanupService(temp_dir=settings.SCAN_TEMP_DIR)
    diag = ScanDiagnostics(str(scan_id))
    temp_dir = None
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.active_scans.inc()

    try:
        async with async_session_factory() as db:
            # Load scan record (eager-load user for token resolution)
            from sqlalchemy.orm import joinedload
            result = await db.execute(
                select(Scan).options(joinedload(Scan.user)).where(Scan.id == scan_id)
            )
            scan = result.unique().scalar_one_or_none()
            if not scan:
                logger.error("Scan %s not found", scan_id)
                return

            # Load session record
            result = await db.execute(
                select(ScanSessionRecord)
                .where(ScanSessionRecord.scan_id == scan_id)
            )
            session_record = result.scalar_one_or_none()

            source_type = session_record.source_type if session_record else "paste"
            repo_url = session_record.repo_url if session_record else None
            branch = session_record.branch if session_record else None

            # Resolve GitHub token upfront while user is loaded
            github_token_resolved = _resolve_github_token(scan)

            # Record scan started metric
            scan_mode = scan.scan_mode or "full"
            user_tier = "free"
            try:
                if scan.user:
                    tier_val = getattr(scan.user, "tier", "free")
                    user_tier = tier_val.value if hasattr(tier_val, "value") else str(tier_val)
            except Exception:
                pass
            metrics.scans_started_total.inc({
                "scan_mode": scan_mode,
                "source_type": source_type,
                "tier": user_tier,
            })

            # Create per-user isolated temp directory
            temp_dir = os.path.join(
                settings.SCAN_TEMP_DIR or tempfile.gettempdir(),
                str(scan.user_id),
                str(scan_id),
            )
            os.makedirs(temp_dir, exist_ok=True)

            # Start diagnostics background tasks (Phase 6/8/10)
            diag.start()

            # ── Phase 1: INGESTION ────────────────────────────────
            _phase1_start = time.monotonic()
            logger.info(
                "[scan %s] Phase START: ingestion (%.1fs elapsed)",
                scan_id, _phase1_start - start_time,
            )
            ingestion = RepoIngestionService()
            files = []

            # ── DIFF MODE: fetch only changed files ──────────────
            if scan_mode == "diff" and source_type == "github" and repo_url:
                files, scan_mode = await _handle_diff_ingestion(
                    scan=scan,
                    scan_id=scan_id,
                    db=db,
                    session_manager=session_manager,
                    progress=progress,
                    cancel_event=cancel_event,
                    settings=settings,
                    repo_url=repo_url,
                )

                if _is_cancelled(cancel_event):
                    return

            # ── FULL MODE: git clone ─────────────────────────────
            if scan_mode != "diff" and source_type == "github" and repo_url:
                # ── Pre-analysis (advisory — never blocks clone) ─
                logger.info(
                    "[scan %s] starting precheck  repo_url=%s",
                    scan_id, repo_url,
                )
                await progress.update(
                    db, ScanStatus.CLONING.value, 2.0,
                    current_file="Pre-analyzing repository...",
                )
                try:
                    from app.orchestration.repo_pre_analyzer import (
                        precheck_repository, parse_github_url,
                    )
                    _owner, _repo_name = parse_github_url(repo_url)
                    github_token = github_token_resolved
                    precheck = await precheck_repository(
                        _owner, _repo_name,
                        token=github_token,
                        max_size_mb=settings.GIT_CLONE_MAX_SIZE_MB,
                        max_files=settings.MAX_FILES_PER_SCAN_LARGE,
                    )
                    if precheck.warnings:
                        for w in precheck.warnings:
                            logger.warning(
                                "[scan %s] [PRECHECK] %s", scan_id, w,
                            )
                    else:
                        logger.info(
                            "[scan %s] [PRECHECK] passed: %.1fMB, ~%d files, "
                            "languages=%s, large_files=%s",
                            scan_id, precheck.size_mb, precheck.estimated_files,
                            list(precheck.languages.keys())[:5],
                            precheck.has_large_files,
                        )
                except Exception:
                    # Precheck is optional — full stack trace + continue
                    logger.exception(
                        "[scan %s] [PRECHECK] precheck failed for "
                        "repo_url=%s — continuing with clone",
                        scan_id, repo_url,
                    )
                logger.info("[scan %s] precheck completed", scan_id)

                # ── Clone ────────────────────────────────────────
                logger.info(
                    "[scan %s] starting clone  repo_url=%s  branch=%s",
                    scan_id, repo_url, branch,
                )
                await session_manager.transition(
                    scan_id, ScanStatus.CLONING.value, db
                )
                await progress.update(
                    db, ScanStatus.CLONING.value, 5.0,
                    current_file="Cloning repository...",
                )

                if _is_cancelled(cancel_event):
                    return

                # Use pre-resolved GitHub token
                github_token = github_token_resolved
                tag = (scan.config or {}).get("tag")
                commit = (scan.config or {}).get("commit")

                try:
                    files, temp_dir = await ingestion.ingest_git_clone(
                        repo_url=repo_url,
                        branch=branch,
                        github_token=github_token,
                        tag=tag,
                        commit=commit,
                        cancel_event=cancel_event,
                    )
                except Exception:
                    logger.exception(
                        "[scan %s] clone failed  stage=clone  "
                        "repo_url=%s  branch=%s",
                        scan_id, repo_url, branch,
                    )
                    raise  # fatal — cannot continue without files
                logger.info(
                    "[scan %s] clone completed  files=%d  temp_dir=%s",
                    scan_id, len(files), temp_dir,
                )

                # ── Post-clone sub-stages ────────────────────────
                if temp_dir:
                    # Post-clone filtering
                    logger.info(
                        "[scan %s] starting post-clone filtering  "
                        "temp_dir=%s", scan_id, temp_dir,
                    )
                    try:
                        await ingestion.post_clone_filter(temp_dir)
                    except Exception:
                        logger.exception(
                            "[scan %s] post-clone filtering failed  "
                            "stage=post_clone_filter  repo_url=%s",
                            scan_id, repo_url,
                        )
                    logger.info(
                        "[scan %s] post-clone filtering completed",
                        scan_id,
                    )

                    # Size guard
                    logger.info(
                        "[scan %s] starting size guard  temp_dir=%s",
                        scan_id, temp_dir,
                    )
                    try:
                        await ingestion.check_extracted_size(temp_dir)
                    except Exception:
                        logger.exception(
                            "[scan %s] size guard failed  "
                            "stage=size_guard  repo_url=%s",
                            scan_id, repo_url,
                        )
                        raise  # fatal — repo too large
                    logger.info(
                        "[scan %s] size guard completed", scan_id,
                    )

                    # Monorepo detection (informational)
                    logger.info(
                        "[scan %s] starting monorepo detection",
                        scan_id,
                    )
                    try:
                        ingestion.detect_monorepo(temp_dir)
                    except Exception:
                        logger.exception(
                            "[scan %s] monorepo detection failed  "
                            "stage=monorepo_detection  repo_url=%s",
                            scan_id, repo_url,
                        )
                    logger.info(
                        "[scan %s] monorepo detection completed",
                        scan_id,
                    )

                # Update session with clone info
                if session_record and temp_dir:
                    await db.execute(
                        update(ScanSessionRecord)
                        .where(ScanSessionRecord.scan_id == scan_id)
                        .values(temp_dir=temp_dir)
                    )
                    await db.commit()

            elif source_type == "zip":
                # ZIP extraction
                logger.info(
                    "[scan %s] starting zip extraction", scan_id,
                )
                await session_manager.transition(
                    scan_id, ScanStatus.EXTRACTING.value, db
                )
                await progress.update(
                    db, ScanStatus.EXTRACTING.value, 5.0,
                    current_file="Extracting archive...",
                )

                if _is_cancelled(cancel_event):
                    return

                zip_path = (scan.config or {}).get("zip_path", "")
                if zip_path:
                    try:
                        files, temp_dir = await ingestion.ingest_zip_secure(
                            zip_path=zip_path,
                            cancel_event=cancel_event,
                        )
                    except Exception:
                        logger.exception(
                            "[scan %s] zip extraction failed  "
                            "stage=zip_extraction  zip_path=%s",
                            scan_id, zip_path,
                        )
                        raise  # fatal — cannot continue without files
                    logger.info(
                        "[scan %s] zip extraction completed  files=%d",
                        scan_id, len(files),
                    )

                    # Post-extraction: filter dirs + size guard
                    if temp_dir:
                        logger.info(
                            "[scan %s] starting post-extraction filtering",
                            scan_id,
                        )
                        try:
                            await ingestion.post_clone_filter(temp_dir)
                        except Exception:
                            logger.exception(
                                "[scan %s] post-extraction filtering "
                                "failed  stage=post_clone_filter",
                                scan_id,
                            )
                        logger.info(
                            "[scan %s] post-extraction filtering "
                            "completed", scan_id,
                        )

                        logger.info(
                            "[scan %s] starting size guard (zip)",
                            scan_id,
                        )
                        try:
                            await ingestion.check_extracted_size(temp_dir)
                        except Exception:
                            logger.exception(
                                "[scan %s] size guard failed  "
                                "stage=size_guard  zip_path=%s",
                                scan_id, zip_path,
                            )
                            raise  # fatal — extracted archive too large
                        logger.info(
                            "[scan %s] size guard (zip) completed",
                            scan_id,
                        )

            else:
                # Paste/upload — files already in scan chunks
                # Load from existing chunks
                from app.models.chunk import ScanChunk
                result = await db.execute(
                    select(ScanChunk).where(ScanChunk.scan_id == scan_id)
                )
                chunks = result.scalars().all()

                from app.services.ingestion import IngestedFile

                paste_language = (scan.config or {}).get("paste_language", "")
                paste_extension_map = {
                    "python": ".py", "javascript": ".js", "typescript": ".ts",
                    "java": ".java", "go": ".go", "rust": ".rs", "ruby": ".rb",
                    "php": ".php", "csharp": ".cs", "cpp": ".cpp", "c": ".c",
                    "swift": ".swift", "kotlin": ".kt", "sql": ".sql",
                    "shell": ".sh", "yaml": ".yaml", "json": ".json",
                    "html": ".html", "css": ".css",
                }

                for chunk in chunks:
                    if chunk.chunk_content:
                        fname = chunk.file_name or "unknown"
                        ext = os.path.splitext(fname)[1].lower()
                        if source_type == "paste":
                            ext = paste_extension_map.get(
                                str(paste_language).lower(), ext
                            )
                        files.append(IngestedFile(
                            filename=os.path.basename(fname),
                            path=fname,
                            extension=ext,
                            content=chunk.chunk_content,
                            size=len(chunk.chunk_content.encode(
                                "utf-8", errors="ignore"
                            )),
                        ))

            if _is_cancelled(cancel_event):
                return

            if not files:
                await session_manager.complete_session(
                    scan_id, db,
                    status=ScanStatus.FAILED.value,
                    error_message="No files to scan",
                )
                return

            # ── Phase 1 END ──────────────────────────────────────
            logger.info(
                "[scan %s] Phase END: ingestion (duration: %.1fs, files=%d)",
                scan_id, time.monotonic() - _phase1_start, len(files),
            )

            # ── Phase 2: CLASSIFICATION ───────────────────────────
            _phase2_start = time.monotonic()
            logger.info(
                "[scan %s] Phase START: classification (%d files, %.1fs elapsed)",
                scan_id, len(files), _phase2_start - start_time,
            )
            await session_manager.transition(
                scan_id, ScanStatus.CLASSIFYING.value, db, commit=False
            )
            await progress.update(
                db, ScanStatus.CLASSIFYING.value, 15.0,
                current_file="Classifying files...",
                total_files=len(files),
                commit=False,
            )

            if _is_cancelled(cancel_event):
                return

            logger.info(
                "[scan %s] starting classification  files=%d",
                scan_id, len(files),
            )
            try:
                classified = await asyncio.to_thread(
                    ingestion.classify_and_filter, files
                )
            except Exception:
                logger.exception(
                    "[scan %s] classification failed  "
                    "stage=classification  files=%d  repo_url=%s",
                    scan_id, len(files), repo_url,
                )
                raise
            logger.info(
                "[scan %s] classification completed  classified=%d",
                scan_id, len(classified),
            )

            # Persist ScanFile records
            for cf in classified:
                scan_file = ScanFile(
                    scan_id=scan_id,
                    file_path=cf.ingested.path,
                    file_name=cf.ingested.filename,
                    language=cf.language,
                    size_bytes=cf.ingested.size,
                    priority=cf.priority,
                    category=cf.category,
                    status="pending",
                )
                db.add(scan_file)
            await db.commit()

            # Update scan total_files
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(total_files=len(classified))
            )
            await db.commit()

            if not classified:
                await session_manager.complete_session(
                    scan_id, db,
                    status=ScanStatus.FAILED.value,
                    error_message="No scannable files after classification",
                )
                return

            # ── Phase 2 END ──────────────────────────────────────
            logger.info(
                "[scan %s] Phase END: classification (duration: %.1fs, classified=%d)",
                scan_id, time.monotonic() - _phase2_start, len(classified),
            )

            # ── Phase 3: SCANNING ─────────────────────────────────
            _phase3_start = time.monotonic()
            logger.info(
                "[scan %s] Phase START: scanning (%d classified files, %.1fs elapsed)",
                scan_id, len(classified), _phase3_start - start_time,
            )
            await session_manager.transition(
                scan_id, ScanStatus.SCANNING.value, db
            )
            await progress.update(
                db, ScanStatus.SCANNING.value, 20.0,
                current_file="Starting scan...",
                total_files=len(classified),
            )

            logger.info(
                "Scan %s: entering SCANNING phase — %d files, %d batches",
                scan_id, len(classified),
                0,  # updated after batching
            )

            if _is_cancelled(cancel_event):
                return

            # Create batches
            dispatcher = ChunkDispatcher(
                batch_max_size_mb=settings.BATCH_MAX_SIZE_MB,
                batch_max_files=settings.BATCH_MAX_FILES,
            )
            batches = await asyncio.to_thread(
                dispatcher.create_batches, classified
            )

            logger.info(
                "Scan %s: created %d batches for %d files (per_file_timeout=%ds)",
                scan_id, len(batches), len(classified),
                settings.ENGINE_PER_FILE_TIMEOUT,
            )

            # Scan batches in parallel
            controller = ParallelScanController(
                per_file_timeout=settings.ENGINE_PER_FILE_TIMEOUT,
            )

            all_finding_dicts = []
            files_scanned = 0
            scan_phase_start = time.monotonic()

            try:
                async for batch_findings, progress_fraction in controller.scan_batches(
                    batches, cancel_event, scan_id=str(scan_id)
                ):
                    all_finding_dicts.extend(batch_findings)
                    files_scanned = int(progress_fraction * len(classified))

                    logger.info(
                        "Scan %s: progress %.0f%% — %d/%d files, %d findings so far (%.1fs elapsed)",
                        scan_id, progress_fraction * 100, files_scanned,
                        len(classified), len(all_finding_dicts),
                        time.monotonic() - scan_phase_start,
                    )

                    await progress.update(
                        db, ScanStatus.SCANNING.value,
                        20.0 + (progress_fraction * 50.0),  # 20% to 70%
                        live_vuln_count=len(all_finding_dicts),
                        files_scanned=files_scanned,
                        total_files=len(classified),
                    )

                    if _is_cancelled(cancel_event):
                        return
            except ScanCancelledError:
                logger.info("Scan %s cancelled during scanning phase", scan_id)
                return
            except MemoryLimitExceeded:
                raise  # Let outer handler mark scan FAILED
            except Exception as scan_exc:
                # Part 10: scanning failures must not crash the pipeline
                logger.error(
                    "Scan %s: scanning phase failed after %d findings "
                    "from %d files: %s",
                    scan_id, len(all_finding_dicts), files_scanned,
                    scan_exc, exc_info=True,
                )
                # Continue with whatever findings we have so far

            # Reconstruct EngineFinding objects (CPU-bound for large result sets)
            def _reconstruct_findings(dicts):
                out = []
                for d in dicts:
                    try:
                        out.append(EngineFinding.from_dict(d))
                    except Exception:
                        pass
                return out

            findings = await asyncio.to_thread(
                _reconstruct_findings, all_finding_dicts
            )

            # Apply deduplication and severity normalization
            from engine.deduplication import deduplicate_findings
            from engine.severity import apply_severity_normalization
            from engine.rule_intelligence import apply_rule_intelligence
            from engine.rule_loader import get_rule_index as _get_rule_index

            # Rule Intelligence enrichment (post-detection, pre-dedup)
            # Wrap CPU-bound sync calls in to_thread to keep the event
            # loop responsive (prevents ECONNRESET on status polls).
            _ri_rule_index = await asyncio.to_thread(_get_rule_index)
            findings = await asyncio.to_thread(
                apply_rule_intelligence, findings, _ri_rule_index
            )

            findings = await asyncio.to_thread(deduplicate_findings, findings)
            findings = await asyncio.to_thread(
                apply_severity_normalization, findings
            )

            # Convert to RuleFinding for the aggregator
            from engine.pipeline import _findings_to_rule_findings
            rule_findings = await asyncio.to_thread(
                _findings_to_rule_findings, findings
            )

            logger.info(
                "Scan %s: %d findings from %d files",
                scan_id, len(rule_findings), len(classified),
            )

            # ── Phase 3 END ──────────────────────────────────────
            logger.info(
                "[scan %s] Phase END: scanning (duration: %.1fs, findings=%d)",
                scan_id, time.monotonic() - _phase3_start, len(rule_findings),
            )

            # ── Rule Profiler: generate heatmap + optimization report ──
            _scan_profiler = controller.get_profiler()
            if _scan_profiler:
                from engine.rule_profiler import generate_full_report as _gen_prof_report
                _prof_report = await asyncio.to_thread(
                    _gen_prof_report,
                    _scan_profiler,
                    scan_duration_s=time.monotonic() - start_time,
                    files_scanned=len(classified),
                )
                if _prof_report:
                    logger.info(
                        "[scan %s] Rule profiler report:%s",
                        scan_id, _prof_report,
                    )

            # ── Phase 4: AI VALIDATION ────────────────────────────
            _phase4_start = time.monotonic()
            logger.info(
                "[scan %s] Phase START: ai_validation (%d findings, %.1fs elapsed)",
                scan_id, len(rule_findings),
                _phase4_start - start_time,
            )
            ai_findings = [f for f in findings if f.requires_ai_validation]
            ai_validation_requested = should_run_ai_validation(settings, ai_findings)

            if ai_validation_requested:
                await session_manager.transition(
                    scan_id, ScanStatus.AI_VALIDATING.value, db
                )
                await progress.update(
                    db, ScanStatus.AI_VALIDATING.value, 72.0,
                    current_file="AI validation...",
                    live_vuln_count=len(rule_findings),
                    files_scanned=len(classified),
                    total_files=len(classified),
                )

                if _is_cancelled(cancel_event):
                    return

                ai_queue = AIValidationQueue(
                    max_concurrent=settings.AI_MAX_CONCURRENT_VALIDATIONS,
                    max_tokens=settings.AI_MAX_TOKENS_PER_SCAN,
                )

                findings = await ai_queue.validate_findings(
                    findings,
                    cancel_event=cancel_event,
                    progress_callback=lambda done, total: None,
                )

                # Re-convert after AI adjustments
                rule_findings = await asyncio.to_thread(
                    _findings_to_rule_findings, findings
                )

            # ── Phase 4 END ──────────────────────────────────────
            logger.info(
                "[scan %s] Phase END: ai_validation (duration: %.1fs)",
                scan_id, time.monotonic() - _phase4_start,
            )

            # ── Phase 5: REPORTING ────────────────────────────────
            _phase5_start = time.monotonic()
            logger.info(
                "[scan %s] Phase START: reporting (%d findings, %.1fs elapsed)",
                scan_id, len(rule_findings), _phase5_start - start_time,
            )
            if source_type != "github" or not repo_url:
                # For non-git sources, transition from SCANNING to REPORTING
                # (skipping AI_VALIDATING if not done above)
                current_phase = (
                    ScanStatus.AI_VALIDATING.value
                    if ai_validation_requested
                    else ScanStatus.SCANNING.value
                )
            await session_manager.transition(
                scan_id, ScanStatus.REPORTING.value, db, commit=False
            )
            await progress.update(
                db, ScanStatus.REPORTING.value, 85.0,
                current_file="Generating report...",
                live_vuln_count=len(rule_findings),
                files_scanned=len(classified),
                total_files=len(classified),
                commit=False,
            )

            if _is_cancelled(cancel_event):
                return

            # Generate report (CPU-bound — run in thread)
            aggregator = ReportAggregator()
            report = await asyncio.to_thread(
                aggregator.generate_report, rule_findings, len(classified)
            )

            # Bulk insert vulnerabilities
            for vuln_data in report.vulnerabilities:
                # Build code_snippet JSON if raw snippet text is available
                snippet_raw = vuln_data.get("code_snippet", "")
                snippet_json = {"content": snippet_raw} if snippet_raw else None

                vuln = Vulnerability(
                    scan_id=scan_id,
                    vulnerability_type=vuln_data.get("vulnerability_type", ""),
                    severity=vuln_data.get("severity", "info"),
                    confidence=vuln_data.get("confidence", 0),
                    line_reference=vuln_data.get("line", 0),
                    file_name=vuln_data.get("file_name", ""),
                    impact=vuln_data.get("impact", "") or vuln_data.get("description", ""),
                    remediation=vuln_data.get("remediation", "") or None,
                    exploit_example=None,  # Populated by AI validation if enabled
                    owasp_mapping=vuln_data.get("owasp", ""),
                    category=vuln_data.get("category", ""),
                    code_snippet=snippet_json,
                )
                db.add(vuln)

            # Update scan record with metrics
            duration = time.monotonic() - start_time
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(
                    total_vulnerabilities=report.total_findings,
                    critical_count=report.severity_counts.get("critical", 0),
                    high_count=report.severity_counts.get("high", 0),
                    medium_count=report.severity_counts.get("medium", 0),
                    low_count=report.severity_counts.get("low", 0),
                    info_count=report.severity_counts.get("info", 0),
                    security_score=report.security_score,
                    confidence_score=report.confidence_score,
                    grade=report.grade,
                    duration=round(duration, 2),
                    report_data=report.to_dict(),
                )
            )
            await db.commit()

            # ── Phase 5b: POST-SCAN CI/CD (delta + baseline) ─────
            if scan.repository_id:
                delta_summary = await _handle_post_scan_cicd(
                    scan=scan,
                    scan_id=scan_id,
                    scan_mode=scan_mode,
                    db=db,
                    settings=settings,
                )

                # Enrich report_data with delta summary if available
                if delta_summary:
                    report_dict = report.to_dict()
                    report_dict["delta_summary"] = delta_summary
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == scan_id)
                        .values(report_data=report_dict)
                    )
                    await db.commit()

            # ── Phase 5 END ──────────────────────────────────────
            logger.info(
                "[scan %s] Phase END: reporting (duration: %.1fs)",
                scan_id, time.monotonic() - _phase5_start,
            )

            # ── Phase 6: COMPLETE ─────────────────────────────────
            logger.info(
                "[scan %s] Phase START: completion (score=%.1f grade=%s findings=%d, %.1fs elapsed)",
                scan_id, report.security_score, report.grade,
                report.total_findings, time.monotonic() - start_time,
            )
            await progress.update(
                db, ScanStatus.COMPLETE.value, 100.0,
                live_vuln_count=report.total_findings,
                files_scanned=len(classified),
                total_files=len(classified),
                eta_seconds=0.0,
            )

            await session_manager.complete_session(
                scan_id, db,
                status=ScanStatus.COMPLETE.value,
            )

            # Clean up in-memory progress for this scan
            from app.orchestration.parallel_controller import clear_scan_progress
            clear_scan_progress(str(scan_id))

            # ── Token deduction: record AI tokens used ─────────
            # Use the same formula as cost_estimator to keep estimate ≈ actual
            from app.services.cost_estimator import (
                BASE_TOKENS_PER_FILE, BYTES_PER_TOKEN,
                LANGUAGE_WEIGHTS, MODE_MULTIPLIERS,
            )
            total_size_bytes = sum(
                getattr(cf.ingested, "size", 0) for cf in classified
            )
            scan_languages = [cf.language for cf in classified]
            if scan_languages:
                lang_weights = [
                    LANGUAGE_WEIGHTS.get(l.lower(), 1.0)
                    for l in scan_languages
                ]
                avg_lang_weight = sum(lang_weights) / len(lang_weights)
            else:
                avg_lang_weight = 1.0
            content_tokens = total_size_bytes / BYTES_PER_TOKEN
            raw_tokens = (len(classified) * BASE_TOKENS_PER_FILE) + content_tokens
            mode_mult = MODE_MULTIPLIERS.get(scan_mode, 1.0)
            base_tokens = int(raw_tokens * avg_lang_weight * mode_mult)

            ai_tokens_consumed = (
                ai_queue._tokens_used
                if ai_validation_requested
                else 0
            )
            total_tokens = ai_tokens_consumed + base_tokens

            try:
                from app.services.usage_aggregator import record_scan_completion
                await record_scan_completion(
                    db, scan.user_id, total_tokens, scan_mode,
                    storage_bytes=total_size_bytes,
                )
                await db.commit()
                logger.info(
                    "Token deduction for scan %s: ai=%d base=%d total=%d",
                    scan_id, ai_tokens_consumed, base_tokens, total_tokens,
                )
            except Exception as tok_exc:
                logger.error(
                    "Failed to record token usage for scan %s: %s",
                    scan_id, tok_exc,
                )

            # ── Metrics: record completion ─────────────────────
            duration = time.monotonic() - start_time
            metrics.scans_completed_total.inc({
                "scan_mode": scan_mode, "status": "complete",
            })
            metrics.scan_duration_seconds.observe(duration, {
                "scan_mode": scan_mode,
            })
            for sev in ("critical", "high", "medium", "low", "info"):
                count = report.severity_counts.get(sev, 0)
                if count > 0:
                    metrics.vulnerabilities_found_total.inc(
                        {"severity": sev}, value=count,
                    )

            logger.info(
                "Scan %s complete: score=%.1f, grade=%s, "
                "findings=%d, files=%d, duration=%.1fs",
                scan_id, report.security_score, report.grade,
                report.total_findings, len(classified), duration,
            )
            logger.info(
                "[scan %s] Phase END: completion (total_pipeline_duration: %.1fs)",
                scan_id, duration,
            )

    except asyncio.CancelledError:
        logger.info("Scan %s cancelled (task cancelled)", scan_id)
        metrics.scans_completed_total.inc({
            "scan_mode": "unknown", "status": "cancelled",
        })
        try:
            async with async_session_factory() as db:
                await session_manager.complete_session(
                    scan_id, db,
                    status=ScanStatus.CANCELLED.value,
                    error_message="Cancelled",
                )
        except Exception:
            pass

    except Exception as exc:
        # MemoryLimitExceeded and ScanCancelledError fall through here
        from app.orchestration.parallel_controller import MemoryLimitExceeded, ScanCancelledError as _ScanCancelled
        if isinstance(exc, _ScanCancelled):
            logger.info("Scan %s cancelled by controller", scan_id)
            metrics.scans_completed_total.inc({
                "scan_mode": "unknown", "status": "cancelled",
            })
            fail_status = ScanStatus.CANCELLED.value
            fail_msg = "Scan cancelled"
        elif isinstance(exc, MemoryLimitExceeded):
            logger.error(
                "[scan %s] ABORTED — memory hard limit exceeded: %s", scan_id, exc,
            )
            metrics.scans_completed_total.inc({
                "scan_mode": "unknown", "status": "failed",
            })
            fail_status = ScanStatus.FAILED.value
            fail_msg = str(exc)[:1024]
        else:
            logger.exception(
                "[scan %s] pipeline failed  repo_url=%s  error=%s",
                scan_id, locals().get("repo_url", "N/A"), exc,
            )
            metrics.scans_completed_total.inc({
                "scan_mode": "unknown", "status": "failed",
            })
            fail_status = ScanStatus.FAILED.value
            fail_msg = str(exc)[:1024]
        try:
            async with async_session_factory() as db:
                await session_manager.complete_session(
                    scan_id, db,
                    status=fail_status,
                    error_message=fail_msg,
                )
        except Exception as inner_exc:
            logger.error(
                "Failed to mark scan %s as failed: %s", scan_id, inner_exc
            )

    finally:
        # Stop diagnostics background tasks
        diag.stop()
        # Decrement active scans gauge
        metrics.active_scans.dec()
        # Cleanup temp directory
        if temp_dir:
            await cleanup.remove_temp_directory(temp_dir)


# ── Diff Ingestion Helper ──────────────────────────────────

async def _handle_diff_ingestion(
    *,
    scan: Scan,
    scan_id: UUID,
    db: AsyncSession,
    session_manager,
    progress,
    cancel_event,
    settings,
    repo_url: str,
) -> Tuple[list, str]:
    """Handle diff-mode file ingestion using detect_changed_files().

    Fetches only the files that changed between two commits (PR or
    compare), downloads their content, and builds IngestedFile objects.

    If diff detection fails or the diff is too large, falls back to
    full scan mode transparently.

    Args:
        scan: Scan ORM object.
        scan_id: Scan UUID.
        db: Async database session.
        session_manager: For state transitions.
        progress: ScanProgressTracker instance.
        cancel_event: Cancellation event.
        settings: App settings.
        repo_url: GitHub repository URL.

    Returns:
        (files, scan_mode) — scan_mode may be "full" if fallback triggered.
    """
    from app.services.diff_detector import (
        detect_changed_files, fetch_file_at_ref, DiffDetectionError,
    )
    from app.services.ingestion import IngestedFile

    await session_manager.transition(
        scan_id, ScanStatus.CLONING.value, db
    )
    await progress.update(
        db, ScanStatus.CLONING.value, 5.0,
        current_file="Fetching changed files...",
    )

    if _is_cancelled(cancel_event):
        return [], "diff"

    # Resolve GitHub token
    github_token = _resolve_github_token(scan)
    if not github_token:
        await session_manager.complete_session(
            scan_id, db,
            status=ScanStatus.FAILED.value,
            error_message="No GitHub token for diff scan",
        )
        return [], "diff"

    repo_full_name = repo_url.replace("https://github.com/", "")

    # Attempt diff detection — fallback to full on failure
    try:
        diff_result = await detect_changed_files(
            token=github_token,
            repo_full_name=repo_full_name,
            base_sha=scan.base_commit_sha or "",
            head_sha=scan.head_commit_sha or "",
            pr_number=scan.pr_number,
        )
    except DiffDetectionError as exc:
        logger.warning(
            "Diff detection failed for scan %s, falling back to full: %s",
            scan_id, exc,
        )
        if settings.DIFF_SCAN_FALLBACK_ENABLED:
            await db.execute(
                update(Scan).where(Scan.id == scan_id)
                .values(scan_mode="full")
            )
            await db.commit()
            return [], "full"
        else:
            await session_manager.complete_session(
                scan_id, db,
                status=ScanStatus.FAILED.value,
                error_message=f"Diff detection failed: {exc}",
            )
            return [], "diff"

    # Check if diff is too large → fallback to full scan
    if diff_result.fallback_to_full:
        logger.info(
            "Diff scan fallback to full: %d changed files exceed threshold",
            diff_result.total_changed,
        )
        if settings.DIFF_SCAN_FALLBACK_ENABLED:
            await db.execute(
                update(Scan).where(Scan.id == scan_id)
                .values(scan_mode="full")
            )
            await db.commit()
            return [], "full"
        else:
            await session_manager.complete_session(
                scan_id, db,
                status=ScanStatus.FAILED.value,
                error_message=f"Too many changed files ({diff_result.total_changed}), "
                              f"fallback disabled",
            )
            return [], "diff"

    if _is_cancelled(cancel_event):
        return [], "diff"

    # Fetch file contents at head ref
    files = []
    ref = scan.head_commit_sha or "HEAD"

    for fname in diff_result.changed_files:
        content = await fetch_file_at_ref(
            github_token, repo_full_name, fname, ref
        )
        if content:
            ext = os.path.splitext(fname)[1].lower()
            files.append(IngestedFile(
                filename=os.path.basename(fname),
                path=fname,
                extension=ext,
                content=content,
                size=len(content.encode("utf-8", errors="ignore")),
            ))

    logger.info(
        "Diff scan %s: %d changed, %d scannable, %d fetched",
        scan_id, diff_result.total_changed,
        len(diff_result.changed_files), len(files),
    )

    return files, "diff"


# ── Post-Scan CI/CD Helper ─────────────────────────────────

async def _handle_post_scan_cicd(
    *,
    scan: Scan,
    scan_id: UUID,
    scan_mode: str,
    db: AsyncSession,
    settings,
) -> Optional[dict]:
    """Handle post-scan CI/CD: delta computation, baseline update, PR comment.

    For DIFF scans:
      1. Load active baseline
      2. Compute delta (new/fixed/unchanged)
      3. Persist delta to DB
      4. Update baseline with current findings
      5. Prune old baselines
      6. Post PR comment (if applicable)

    For FULL scans:
      1. Update baseline with current findings
      2. Prune old baselines

    Returns:
        Delta summary dict for diff scans, None for full scans.
        Never raises — CI/CD errors are logged but do not fail the scan.
    """
    try:
        from app.services.baseline_service import (
            store_baseline, get_active_baseline, prune_old_baselines,
        )
        from app.services.delta_engine import compute_delta, store_delta
        from app.services.pr_comment_service import post_pr_comment

        # Reload vulnerabilities for this scan
        vuln_result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.scan_id == scan_id
            )
        )
        scan_vulns = list(vuln_result.scalars().all())

        if scan_mode == "diff":
            # ── 1. Load baseline ──────────────────────────────
            baseline_findings = await get_active_baseline(
                db, scan.repository_id
            )

            # ── 2. Compute delta ──────────────────────────────
            delta = compute_delta(scan_vulns, baseline_findings)

            # ── 3. Persist delta ──────────────────────────────
            baseline_scan_id = None
            if baseline_findings:
                baseline_scan_id = baseline_findings[0].scan_id

            await store_delta(
                db, scan_id, baseline_scan_id, delta
            )
            await db.commit()

            # ── 4. Update baseline ────────────────────────────
            commit_sha = scan.head_commit_sha or ""
            await store_baseline(
                db, scan.repository_id, scan_id,
                scan_vulns, commit_sha,
            )

            # ── 5. Prune old baselines ────────────────────────
            await prune_old_baselines(db, scan.repository_id)
            await db.commit()

            # ── 6. PR comment ─────────────────────────────────
            if scan.pr_number and settings.PR_COMMENT_ENABLED:
                gh_token = _resolve_github_token(scan)
                if gh_token:
                    try:
                        await post_pr_comment(
                            token=gh_token,
                            repo_full_name=scan.repo_name,
                            pr_number=scan.pr_number,
                            delta=delta,
                        )
                    except Exception as pr_exc:
                        # PR comment failure must not break the scan
                        logger.warning(
                            "PR comment failed for scan %s: %s",
                            scan_id, pr_exc,
                        )

            logger.info(
                "Scan %s delta: new=%d fixed=%d unchanged=%d "
                "regression=%s",
                scan_id, delta.new_count,
                delta.fixed_count, delta.unchanged_count,
                delta.regression_detected,
            )

            return {
                "new_count": delta.new_count,
                "fixed_count": delta.fixed_count,
                "unchanged_count": delta.unchanged_count,
                "regression_detected": delta.regression_detected,
                "severity_summary": delta.severity_summary,
            }

        else:
            # ── FULL SCAN → UPDATE BASELINE ──────────────────
            commit_sha = scan.head_commit_sha or ""
            await store_baseline(
                db, scan.repository_id, scan_id,
                scan_vulns, commit_sha,
            )
            await prune_old_baselines(db, scan.repository_id)
            await db.commit()

            logger.info(
                "Baseline updated for repo %s, scan %s, "
                "%d findings",
                scan.repository_id, scan_id, len(scan_vulns),
            )

            return None

    except Exception as cicd_exc:
        # CI/CD post-processing errors should not fail the scan
        logger.error(
            "CI/CD post-processing failed for scan %s: %s",
            scan_id, cicd_exc, exc_info=True,
        )
        return None


# ── Utilities ───────────────────────────────────────────────

def _resolve_github_token(scan: Scan) -> Optional[str]:
    """Resolve a GitHub token from scan config or user's encrypted token.

    Checks scan.config["github_token"] first, then falls back to
    the user's stored encrypted token.

    Returns:
        GitHub access token string, or None if unavailable.
    """
    token = (scan.config or {}).get("github_token")
    if token:
        return token

    if scan.user:
        enc = getattr(scan.user, "github_token_encrypted", None)
        if enc:
            try:
                from app.core.security import decrypt_token
                return decrypt_token(enc)
            except Exception:
                pass

    return None


def _is_cancelled(cancel_event: Optional[asyncio.Event]) -> bool:
    """Check if the cancel event is set."""
    return cancel_event is not None and cancel_event.is_set()
