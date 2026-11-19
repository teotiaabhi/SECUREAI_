"""
Pipeline orchestrator — the single entry point binding all engine components.

scan_files() replaces scan_all_chunks() in the scan service pipeline.
Returns List[RuleFinding] for drop-in backward compatibility.
"""

import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from typing import Callable, List, Optional

from engine.models import EngineRule, EngineFinding
from engine.rule_loader import get_rule_index
from engine.file_classifier import classify_language, should_skip_file, resolve_db_category
from engine.worker import worker_init, worker_scan_file, worker_set_total
from engine.deduplication import deduplicate_findings
from engine.severity import (
    apply_severity_normalization,
    compute_severity_distribution,
    compute_repository_risk_metrics,
)
from engine.rule_intelligence import apply_rule_intelligence
from engine.clustering import cluster_findings
from engine.confidence_calibration import calibrate_confidence
from engine.confidence_scorer import apply_confidence_rescoring
from engine.exploit_chains import detect_exploit_chains, generate_chain_summary
from engine.logic_detectors import apply_logic_detectors
from engine.dataflow_analysis import apply_dataflow_analysis
from engine.false_positive_control import apply_false_positive_control
from engine.exploit_graph import apply_exploit_graph
from engine.remediation_engine import apply_remediation
from engine.developer_learning import generate_batch_explanations
from engine.result_accuracy import apply_result_accuracy_pipeline
from engine.finding_aggregation import strict_deduplicate

logger = logging.getLogger("engine.pipeline")

# Lazy-initialized executor (reused across scans)
_executor: Optional[ProcessPoolExecutor] = None
_executor_hash: Optional[str] = None


def _get_worker_count() -> int:
    """Determine number of worker processes."""
    try:
        from app.core.config import get_settings
        count = get_settings().ENGINE_WORKER_COUNT
        if count > 0:
            return count
    except Exception:
        pass
    return min(os.cpu_count() or 4, 8)


def _serialize_rules(rules: List[EngineRule]) -> List[dict]:
    """Serialize EngineRule objects to dicts for pickling to workers."""
    result = []
    for rule in rules:
        d = {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "description": rule.description,
            "language": rule.language,
            "category": rule.category,
            "db_category": rule.db_category,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "cwe": rule.cwe,
            "owasp": rule.owasp,
            "tags": rule.tags,
            "pattern_strings": rule.pattern_strings,
            "anti_patterns": rule.anti_patterns,
            "severity_weight": rule.severity_weight,
            "exploitability_score": rule.exploitability_score,
            "requires_ai_validation": rule.requires_ai_validation,
            "impact": rule.impact,
            "remediation": rule.remediation,
            "related_rules": rule.related_rules,
            "detection_layer": rule.detection_layer,
            "attack_surface_type": rule.attack_surface_type,
            "privilege_context_flags": rule.privilege_context_flags,
            "multi_function_chain_patterns": rule.multi_function_chain_patterns,
            "probable_taint_paths": rule.probable_taint_paths,
            "business_logic_indicator": rule.business_logic_indicator,
            "vulnerability_family": rule.vulnerability_family,
            "preconditions": rule.preconditions,
        }
        result.append(d)
    return result


def _get_executor() -> ProcessPoolExecutor:
    """Get or create the ProcessPoolExecutor.

    Workers load rules from disk in worker_init() — no rule data is
    passed through initargs, eliminating heavy pickling overhead.
    """
    global _executor, _executor_hash

    # Reuse existing executor if alive
    if _executor is not None:
        return _executor

    worker_count = _get_worker_count()
    logger.info(
        "Creating ProcessPoolExecutor with %d workers.", worker_count
    )

    _executor = ProcessPoolExecutor(
        max_workers=worker_count,
        initializer=worker_init,
    )
    _executor_hash = "active"
    return _executor


def _findings_to_rule_findings(findings: List[EngineFinding]) -> list:
    """Convert EngineFinding objects to RuleFinding objects for backward
    compatibility with the existing aggregator and merge pipeline.

    Uses lazy import to avoid circular dependency.
    """
    from app.scanner.rule_engine import RuleFinding

    result = []
    for f in findings:
        rf = RuleFinding(
            rule_id=f.rule_id,
            vulnerability_type=f.vulnerability_type,
            severity=f.severity,
            confidence=f.confidence,
            line=f.line,
            file_name=f.file_name,
            description=f.description,
            category=f.category,
            owasp=f.owasp,
            matched_pattern=f.matched_pattern,
        )
        # Attach developer explanation if present
        if hasattr(f, "developer_explanation"):
            rf.developer_explanation = f.developer_explanation
        result.append(rf)
    return result


def _enrich_developer_explanations(findings: List[EngineFinding]) -> None:
    """Attach developer-friendly explanations to each finding in-place.

    Adds a `developer_explanation` attribute with structured learning
    content covering CWE details, real-world exploit scenarios,
    secure remediation guidance, and OWASP references.
    """
    if not findings:
        return

    try:
        # Convert findings to dicts for the learning module
        finding_dicts = []
        for f in findings:
            finding_dicts.append({
                "rule_id": f.rule_id,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
                "owasp": getattr(f, "owasp", ""),
                "description": f.description,
                "cwe": getattr(f, "cwe", ""),
                "detection_layer": getattr(f, "detection_layer", ""),
            })

        explanations = generate_batch_explanations(finding_dicts)

        for f, explanation in zip(findings, explanations):
            if explanation:
                f.developer_explanation = {
                    "summary": explanation.get("vulnerability_type", ""),
                    "why_dangerous": explanation.get("why_this_is_dangerous", ""),
                    "real_world_scenario": explanation.get("real_world_exploit", ""),
                    "secure_fix": explanation.get("secure_fix", ""),
                    "cwe_reference": explanation.get("references", []),
                    "owasp_reference": explanation.get("references", []),
                    "severity_guidance": explanation.get("severity_guidance", ""),
                    "detection_layer_info": explanation.get("detection_layer_info", ""),
                    "secure_code_example": explanation.get("secure_code_example", ""),
                    "common_mistakes": explanation.get("common_mistakes", []),
                    "attacker_scenario": explanation.get("attacker_abuse_scenario", ""),
                }
    except Exception as exc:
        logger.warning("Developer explanation enrichment failed: %s", exc)


def scan_files(
    files: list,
    progress_callback: Optional[Callable] = None,
) -> list:
    """Main entry point: scan all files and return RuleFinding list.

    Drop-in replacement for scan_all_chunks() in scan_service.py.
    Accepts List[IngestedFile] (from app.services.ingestion).
    Returns List[RuleFinding] for backward compatibility.

    Pipeline:
    1. Load rule index (LRU cached)
    2. Serialize rules for worker pickling
    3. Classify each file (language, skip check)
    4. Submit to ProcessPoolExecutor (parallel per file)
    5. Collect + reconstruct EngineFinding objects
    5b. Rule Intelligence enrichment
    5c. Logic detectors
    5d. Dataflow analysis (taint tracking)
    5e. False positive control
    5f. Vulnerability clustering
    5g. Confidence auto-calibration
    6. Deduplication pipeline
    6b. Exploit-chain detection
    7. Severity normalization
    7b. Repository risk metrics
    7c. Developer learning explanations
    8. Convert to RuleFinding format
    """
    start_time = time.monotonic()

    # 1. Load rules
    rule_index = get_rule_index()
    total_rules = len(rule_index.all_rules)
    logger.info(
        "Engine starting: %d files, %d rules across %d languages.",
        len(files),
        total_rules,
        len(rule_index.languages),
    )

    if total_rules == 0:
        logger.error("No rules loaded. Returning empty results.")
        return []

    # 2. Workers load rules from disk (no serialization needed)
    # _serialize_rules() is no longer used for worker initialization.
    # Workers call get_rule_index() internally during worker_init().

    # 3. Classify files
    scan_jobs = []  # (content, file_name, language)
    skipped = 0

    for f in files:
        file_name = getattr(f, "filename", "") or getattr(f, "path", "")
        content = getattr(f, "content", "")
        extension = getattr(f, "extension", "")

        if not content or not file_name:
            skipped += 1
            continue

        if should_skip_file(file_name):
            skipped += 1
            continue

        language = classify_language(file_name)
        if language is None:
            skipped += 1
            continue

        scan_jobs.append((content, file_name, language))

    logger.info(
        "Classified %d files for scanning, %d skipped.", len(scan_jobs), skipped
    )

    if not scan_jobs:
        return []

    # 4. Parallel scanning
    all_finding_dicts: List[dict] = []
    total_content_size = sum(len(j[0]) for j in scan_jobs)

    # Use in-process scanning for small projects to avoid ProcessPool overhead
    # (each worker must compile ~2000 regex patterns on Windows/spawn)
    use_multiprocess = len(scan_jobs) > 50 or total_content_size > 1_000_000

    if not use_multiprocess:
        # In-process: compile rules once in main process
        worker_init()
        worker_set_total(len(scan_jobs))
        for content, file_name, language in scan_jobs:
            result_dicts = worker_scan_file(content, file_name, language)
            all_finding_dicts.extend(result_dicts)
            if progress_callback:
                progress_callback(file_name)
    else:
        executor = _get_executor()
        futures = {}
        for content, file_name, language in scan_jobs:
            fut = executor.submit(worker_scan_file, content, file_name, language)
            futures[fut] = file_name

        for fut in as_completed(futures):
            file_name = futures[fut]
            try:
                result_dicts = fut.result(timeout=60)
                all_finding_dicts.extend(result_dicts)
            except Exception as exc:
                logger.error("Scan failed for %s: %s", file_name, exc)

            if progress_callback:
                progress_callback(file_name)

    # 5. Reconstruct EngineFinding objects
    findings = []
    for d in all_finding_dicts:
        try:
            findings.append(EngineFinding.from_dict(d))
        except Exception as exc:
            logger.error("Failed to reconstruct finding: %s", exc)

    logger.info("Raw findings before dedup: %d", len(findings))

    # 5b. Rule Intelligence enrichment
    # Pass original file contents for full-fidelity line-level analysis.
    # scan_jobs holds (content, file_name, language) from classification.
    file_contents = {fname: content for content, fname, _lang in scan_jobs}
    findings = apply_rule_intelligence(findings, rule_index, file_contents)

    # 5c. Logic detectors (async race, timing, supply chain, build scripts, framework context)
    findings = apply_logic_detectors(findings, file_contents)

    # 5d. Dataflow analysis (lightweight taint tracking: source → variable → sink)
    findings = apply_dataflow_analysis(findings, file_contents)

    # 5e. False positive control (framework context, sanitization, test files, safe patterns)
    findings = apply_false_positive_control(findings, file_contents)

    # 5e2. Advanced confidence rescoring (input source analysis, safe pattern suppression)
    apply_confidence_rescoring(findings, file_contents)

    # 5f. Vulnerability clustering (groups nearby same-family findings)
    findings = cluster_findings(findings)

    # 5g. Confidence auto-calibration (context signals + corroboration)
    findings = calibrate_confidence(findings)

    # 6. Deduplication
    findings = deduplicate_findings(findings)

    # 6a. Result accuracy: strict deduplication + confidence recalibration
    findings = strict_deduplicate(findings)

    # 6b. Exploit-chain detection (synthetic chain findings added)
    findings = detect_exploit_chains(findings)

    # 6c. Exploit graph engine (graph-based attack path discovery)
    findings = apply_exploit_graph(findings, file_contents)

    # 7. Severity normalization
    findings = apply_severity_normalization(findings)

    # 7b. Repository risk metrics (LOC-based density scoring)
    risk_metrics = compute_repository_risk_metrics(
        findings, file_contents, total_files=len(scan_jobs),
    )

    # 7c. Remediation engine (secure code fix generation)
    findings = apply_remediation(findings, file_contents)

    # 7d. Result accuracy: confidence recalibration (PART 8)
    from engine.result_accuracy import apply_confidence_recalibration
    apply_confidence_recalibration(findings, file_contents)

    del file_contents  # Free memory

    # 7d. Developer learning explanations
    _enrich_developer_explanations(findings)

    # 8. Convert to RuleFinding
    rule_findings = _findings_to_rule_findings(findings)

    elapsed = (time.monotonic() - start_time) * 1000
    dist = compute_severity_distribution(findings)

    logger.info(
        "Engine complete: %d findings in %.0f ms "
        "(critical=%d, high=%d, medium=%d, low=%d, risk_density=%.6f).",
        len(rule_findings),
        elapsed,
        dist["critical"],
        dist["high"],
        dist["medium"],
        dist["low"],
        risk_metrics.get("risk_density", 0.0),
    )

    return rule_findings


async def scan_files_with_ai_validation(
    files: list,
    progress_callback: Optional[Callable] = None,
) -> list:
    """Extended scan with optional AI validation.

    1. Run base rule scanning via scan_files()
    2. For findings with requires_ai_validation, run async AI validation
    3. Adjust confidence based on AI feedback
    4. Return updated RuleFinding list
    """
    import asyncio
    from engine.ai_validation import batch_validate_findings

    # Base scan (synchronous, using ProcessPool)
    start_time = time.monotonic()

    rule_index = get_rule_index()

    # Workers load rules from disk — no serialization needed

    # Classify
    scan_jobs = []
    for f in files:
        file_name = getattr(f, "filename", "") or getattr(f, "path", "")
        content = getattr(f, "content", "")
        if not content or not file_name:
            continue
        if should_skip_file(file_name):
            continue
        language = classify_language(file_name)
        if language is None:
            continue
        scan_jobs.append((content, file_name, language))

    if not scan_jobs:
        return []

    # Parallel scan
    all_finding_dicts: List[dict] = []
    if len(scan_jobs) <= 3:
        worker_init()
        for content, file_name, language in scan_jobs:
            all_finding_dicts.extend(worker_scan_file(content, file_name, language))
    else:
        executor = _get_executor()
        futures = {}
        for content, file_name, language in scan_jobs:
            fut = executor.submit(worker_scan_file, content, file_name, language)
            futures[fut] = file_name
        for fut in as_completed(futures):
            try:
                all_finding_dicts.extend(fut.result(timeout=60))
            except Exception as exc:
                logger.error("Scan error: %s", exc)

    # Reconstruct + full pipeline: intelligence → logic → dataflow → FP control
    #   → clustering → calibration → dedup → chains → normalize
    findings = [EngineFinding.from_dict(d) for d in all_finding_dicts if d]
    file_contents_ai = {fname: content for content, fname, _lang in scan_jobs}
    findings = apply_rule_intelligence(findings, rule_index, file_contents_ai)
    findings = apply_logic_detectors(findings, file_contents_ai)
    findings = apply_dataflow_analysis(findings, file_contents_ai)
    findings = apply_false_positive_control(findings, file_contents_ai)
    findings = cluster_findings(findings)
    findings = calibrate_confidence(findings)
    findings = deduplicate_findings(findings)
    findings = detect_exploit_chains(findings)
    findings = apply_exploit_graph(findings, file_contents_ai)
    findings = apply_severity_normalization(findings)
    findings = apply_remediation(findings, file_contents_ai)
    del file_contents_ai

    # Developer learning enrichment
    _enrich_developer_explanations(findings)

    # AI validation (async)
    findings = await batch_validate_findings(findings)

    # Convert to RuleFinding
    rule_findings = _findings_to_rule_findings(findings)

    elapsed = (time.monotonic() - start_time) * 1000
    logger.info(
        "Engine (with AI) complete: %d findings in %.0f ms.", len(rule_findings), elapsed
    )

    return rule_findings
