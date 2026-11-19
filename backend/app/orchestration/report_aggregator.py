"""
ReportAggregator — structured scan report generation and comparison.

Uses existing risk_engine and aggregator modules. Produces a comprehensive
ScanReport dataclass with OWASP/CWE distributions, file risk rankings,
executive summary, and scan comparison diffs.
"""

import logging
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

logger = logging.getLogger("orchestration.report_aggregator")

SEVERITY_WEIGHTS = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}


@dataclass
class ScanReport:
    """Structured scan report for storage in scan.report_data."""

    vulnerabilities: List[Dict] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    security_score: float = 100.0
    confidence_score: float = 0.0
    grade: str = "A"
    owasp_distribution: Dict[str, int] = field(default_factory=dict)
    cwe_distribution: Dict[str, int] = field(default_factory=dict)
    category_distribution: Dict[str, int] = field(default_factory=dict)
    file_risk_ranking: List[Dict] = field(default_factory=list)
    executive_summary: str = ""
    posture_summary: str = ""
    total_files: int = 0
    total_findings: int = 0
    # Rule Intelligence layer outputs
    intelligence_summary: Dict = field(default_factory=dict)
    # Advanced analysis outputs
    repository_loc: int = 0
    risk_density: float = 0.0
    normalized_security_score: float = 100.0
    findings_per_kloc: float = 0.0
    chain_summary: Dict = field(default_factory=dict)
    clustering_summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


class ReportAggregator:
    """Generates structured scan reports and comparisons."""

    def generate_report(
        self,
        findings: list,
        total_files: int,
    ) -> ScanReport:
        """Generate a comprehensive scan report from findings.

        Args:
            findings: List of RuleFinding objects from the scan pipeline.
            total_files: Total number of files scanned.

        Returns:
            ScanReport with all computed metrics.
        """
        from app.scanner.risk_engine import (
            calculate_security_score,
            calculate_grade,
            calculate_severity_distribution,
            generate_posture_summary,
        )
        from app.scanner.aggregator import aggregate_findings

        # Aggregate findings (dedup, noise removal, sorting)
        aggregated = aggregate_findings(findings)

        # Severity counts
        sev_dist = calculate_severity_distribution(aggregated)

        # Security score and grade
        score = calculate_security_score(aggregated, total_files)
        grade = calculate_grade(score)
        posture = generate_posture_summary(score, grade, sev_dist)

        # Average confidence
        if aggregated:
            avg_confidence = sum(f.confidence for f in aggregated) / len(aggregated)
        else:
            avg_confidence = 100.0

        # OWASP distribution
        owasp_counter = Counter()
        for f in aggregated:
            owasp = getattr(f, "owasp", None) or "Uncategorized"
            owasp_counter[owasp] += 1

        # CWE distribution
        cwe_counter = Counter()
        for f in aggregated:
            rule_id = getattr(f, "rule_id", "")
            # Try to extract CWE from rule_id or description
            cwe = self._extract_cwe(f)
            if cwe:
                cwe_counter[cwe] += 1

        # Category distribution
        cat_counter = Counter()
        for f in aggregated:
            cat = getattr(f, "category", "unknown") or "unknown"
            cat_counter[cat] += 1

        # File risk ranking (top 20)
        file_risks: Dict[str, Dict] = {}
        for f in aggregated:
            fname = getattr(f, "file_name", "unknown")
            if fname not in file_risks:
                file_risks[fname] = {
                    "file": fname,
                    "risk_score": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total": 0,
                }
            sev = getattr(f, "severity", "info").lower()
            weight = SEVERITY_WEIGHTS.get(sev, 0)
            file_risks[fname]["risk_score"] += weight
            if sev in file_risks[fname]:
                file_risks[fname][sev] += 1
            file_risks[fname]["total"] += 1

        ranked_files = sorted(
            file_risks.values(),
            key=lambda x: x["risk_score"],
            reverse=True,
        )[:20]

        # Vulnerability dicts for DB insert
        vuln_dicts = []
        for f in aggregated:
            vuln_dicts.append({
                "rule_id": getattr(f, "rule_id", ""),
                "vulnerability_type": getattr(f, "vulnerability_type", ""),
                "severity": getattr(f, "severity", "info"),
                "confidence": getattr(f, "confidence", 0),
                "line": getattr(f, "line", 0),
                "file_name": getattr(f, "file_name", ""),
                "description": getattr(f, "description", ""),
                "category": getattr(f, "category", ""),
                "owasp": getattr(f, "owasp", ""),
                "matched_pattern": getattr(f, "matched_pattern", ""),
                "remediation": getattr(f, "remediation", ""),
                "impact": getattr(f, "impact", ""),
                "code_snippet": getattr(f, "code_snippet", ""),
            })

        # Executive summary
        summary = self._generate_executive_summary(
            total_files, len(aggregated), sev_dist, score, grade
        )

        # Rule Intelligence summary (if intelligence layer was applied)
        intel_summary = {}
        try:
            from engine.rule_intelligence import generate_intelligence_summary
            intel_summary = generate_intelligence_summary(aggregated)
        except Exception:
            pass

        # Exploit-chain summary
        chain_summary = {}
        try:
            from engine.exploit_chains import generate_chain_summary
            chain_summary = generate_chain_summary(aggregated)
        except Exception:
            pass

        # Clustering summary
        clustering_summary = self._compute_clustering_summary(aggregated)

        # Repository risk metrics
        risk_metrics = {}
        try:
            from engine.severity import compute_repository_risk_metrics
            risk_metrics = compute_repository_risk_metrics(
                aggregated, total_files=total_files,
            )
        except Exception:
            pass

        report = ScanReport(
            vulnerabilities=vuln_dicts,
            severity_counts=sev_dist,
            security_score=score,
            confidence_score=round(avg_confidence, 1),
            grade=grade,
            owasp_distribution=dict(owasp_counter),
            cwe_distribution=dict(cwe_counter),
            category_distribution=dict(cat_counter),
            file_risk_ranking=ranked_files,
            executive_summary=summary,
            posture_summary=posture,
            total_files=total_files,
            total_findings=len(aggregated),
            intelligence_summary=intel_summary,
            repository_loc=risk_metrics.get("repository_loc", 0),
            risk_density=risk_metrics.get("risk_density", 0.0),
            normalized_security_score=risk_metrics.get(
                "normalized_security_score", 100.0,
            ),
            findings_per_kloc=risk_metrics.get("findings_per_kloc", 0.0),
            chain_summary=chain_summary,
            clustering_summary=clustering_summary,
        )

        logger.info(
            "Report generated: score=%.1f, grade=%s, findings=%d",
            score, grade, len(aggregated),
        )
        return report

    @staticmethod
    def _extract_cwe(finding) -> Optional[str]:
        """Try to extract CWE from a finding."""
        # Check direct attribute
        cwe = getattr(finding, "cwe", None)
        if cwe:
            return str(cwe)
        # Try description
        desc = getattr(finding, "description", "")
        if "CWE-" in desc:
            import re
            match = re.search(r"CWE-\d+", desc)
            if match:
                return match.group()
        return None

    @staticmethod
    def _compute_clustering_summary(aggregated) -> Dict:
        """Build clustering summary from findings with evidence_count > 1."""
        clustered_count = 0
        total_evidence = 0
        max_evidence = 0
        for f in aggregated:
            ec = getattr(f, "evidence_count", 1) or 1
            if ec > 1:
                clustered_count += 1
                total_evidence += ec
                max_evidence = max(max_evidence, ec)

        return {
            "clustered_findings": clustered_count,
            "total_evidence_items": total_evidence,
            "max_cluster_size": max_evidence,
            "noise_reduction_ratio": round(
                1.0 - (len(aggregated) / (len(aggregated) + total_evidence))
                if total_evidence > 0 else 0.0,
                3,
            ),
        }

    @staticmethod
    def _generate_executive_summary(
        total_files: int,
        total_findings: int,
        sev_dist: Dict[str, int],
        score: float,
        grade: str,
    ) -> str:
        """Generate a human-readable executive summary."""
        if total_findings == 0:
            return (
                f"Security scan of {total_files} files completed with no vulnerabilities "
                f"detected. Security score: {score}/100 (Grade {grade})."
            )

        critical = sev_dist.get("critical", 0)
        high = sev_dist.get("high", 0)

        parts = [
            f"Security scan of {total_files} files identified {total_findings} "
            f"vulnerabilities. Security score: {score}/100 (Grade {grade})."
        ]

        if critical > 0:
            parts.append(
                f" {critical} critical vulnerabilities require immediate remediation."
            )
        if high > 0:
            parts.append(f" {high} high-severity issues should be addressed promptly.")

        top_categories = sorted(
            sev_dist.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        active_sevs = [f"{v} {k}" for k, v in top_categories if v > 0]
        if active_sevs:
            parts.append(f" Breakdown: {', '.join(active_sevs)}.")

        return "".join(parts)

    def compare_scans(
        self,
        report_a: Dict,
        report_b: Dict,
    ) -> Dict:
        """Compare two scan reports and return a diff summary.

        Args:
            report_a: Older scan report_data dict.
            report_b: Newer scan report_data dict.

        Returns:
            Dict with score_delta, grade_change, vuln_delta, trend.
        """
        score_a = report_a.get("security_score", 0)
        score_b = report_b.get("security_score", 0)
        grade_a = report_a.get("grade", "?")
        grade_b = report_b.get("grade", "?")

        sev_a = report_a.get("severity_counts", {})
        sev_b = report_b.get("severity_counts", {})

        vuln_delta = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            old = sev_a.get(sev, 0)
            new = sev_b.get(sev, 0)
            vuln_delta[sev] = new - old

        score_delta = score_b - score_a

        if score_delta > 5:
            trend = "improving"
        elif score_delta < -5:
            trend = "degrading"
        else:
            trend = "stable"

        return {
            "score_delta": round(score_delta, 1),
            "grade_change": f"{grade_a} → {grade_b}",
            "vuln_delta": vuln_delta,
            "total_delta": report_b.get("total_findings", 0) - report_a.get("total_findings", 0),
            "trend": trend,
        }
