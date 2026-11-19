"""
Engine data models — shared across all engine components.

EngineRule is frozen/picklable (uses tuples). CompiledRule lives only in workers.
EngineFinding carries enough data to populate the Vulnerability DB model.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import re


@dataclass(frozen=True)
class EngineRule:
    """Immutable YAML rule ready for serialization to worker processes.

    Uses tuples (not lists) for full pickle compatibility.
    Regex patterns are stored as (pattern_string, flags_int) pairs —
    compilation is deferred to worker processes.
    """

    rule_id: str
    title: str
    description: str
    language: str
    category: str
    db_category: str
    severity: str
    confidence: float  # 0.0–1.0
    cwe: str
    owasp: str
    tags: tuple
    pattern_strings: tuple  # tuple of (pattern_str, flags_int)
    anti_patterns: tuple  # tuple of literal strings
    severity_weight: int
    exploitability_score: str  # "High", "Medium", "Low"
    requires_ai_validation: bool
    impact: str
    remediation: str
    related_rules: tuple
    # Rule Intelligence metadata (consumed post-detection)
    detection_layer: int = 1  # 1=direct match, 2=contextual/behavioral
    attack_surface_type: str = "web"  # "web", "api", "internal", "mobile"
    privilege_context_flags: tuple = ()  # tuple of (key, value) pairs
    multi_function_chain_patterns: tuple = ()  # tuple of chain description strings
    probable_taint_paths: tuple = ()  # tuple of (source, sink, through) tuples
    business_logic_indicator: tuple = ()  # tuple of (key, value) pairs
    vulnerability_family: str = ""  # semantic grouping key (e.g. "header_privilege_escalation")
    # Context-aware preconditions (evaluated BEFORE pattern matching)
    preconditions: tuple = ()  # serialized RulePreconditions via .to_tuple()
    supports_json_files: bool = False  # explicit opt-in for scanning .json files


@dataclass
class CompiledRule:
    """EngineRule paired with compiled regex patterns.

    Lives only inside worker processes — NOT picklable due to re.Pattern.
    """

    rule: EngineRule
    compiled_patterns: List[re.Pattern]


@dataclass
class PatternMatch:
    """A single regex match within file content."""

    pattern_index: int
    start_offset: int
    end_offset: int
    line_number: int  # 1-based
    matched_text: str  # truncated to MAX_MATCH_LENGTH


@dataclass
class EngineFinding:
    """Intermediate finding before dedup and severity normalization."""

    rule_id: str
    rule_title: str
    vulnerability_type: str
    severity: str
    confidence: float  # 0–100 scale (matches existing pipeline)
    file_name: str
    line: int
    description: str
    category: str  # DB category string
    owasp: str
    cwe: str
    matched_pattern: str
    code_snippet: str  # max 800 chars
    impact: str
    remediation: str
    requires_ai_validation: bool
    severity_weight: int
    exploitability_score: str
    detection_id: str  # sha256(rule_id|file_name|line)[:16]
    ai_validated: bool = False
    ai_confidence: Optional[float] = None
    # Rule Intelligence outputs (populated by rule_intelligence layer)
    correlation_flags: list = field(default_factory=list)
    intelligence_modifiers: list = field(default_factory=list)
    adjusted_confidence: Optional[float] = None
    adjusted_severity_weight: Optional[int] = None
    # Semantic dedup outputs
    merged_rule_ids: list = field(default_factory=list)  # rule_ids merged into this finding
    vulnerability_family: str = ""  # semantic family for dedup grouping
    chain_risk_multiplier: float = 1.0  # exploit-chain diminishing return factor
    # Vulnerability clustering outputs
    evidence_count: int = 1  # how many raw detections this cluster represents
    clustered_rule_ids: list = field(default_factory=list)  # rule_ids absorbed into cluster
    # Exploit chain detection
    exploit_chain_name: str = ""  # e.g. "auth_bypass_rce", empty if not a chain finding

    def to_dict(self) -> Dict:
        """Serialize to a picklable dict for cross-process transfer."""
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_name": self.file_name,
            "line": self.line,
            "description": self.description,
            "category": self.category,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "matched_pattern": self.matched_pattern,
            "code_snippet": self.code_snippet,
            "impact": self.impact,
            "remediation": self.remediation,
            "requires_ai_validation": self.requires_ai_validation,
            "severity_weight": self.severity_weight,
            "exploitability_score": self.exploitability_score,
            "detection_id": self.detection_id,
            "ai_validated": self.ai_validated,
            "ai_confidence": self.ai_confidence,
            "correlation_flags": self.correlation_flags,
            "intelligence_modifiers": self.intelligence_modifiers,
            "adjusted_confidence": self.adjusted_confidence,
            "adjusted_severity_weight": self.adjusted_severity_weight,
            "merged_rule_ids": self.merged_rule_ids,
            "vulnerability_family": self.vulnerability_family,
            "chain_risk_multiplier": self.chain_risk_multiplier,
            "evidence_count": self.evidence_count,
            "clustered_rule_ids": self.clustered_rule_ids,
            "exploit_chain_name": self.exploit_chain_name,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "EngineFinding":
        """Reconstruct from a dict received from a worker process."""
        # Filter to known fields to handle forward/backward compat
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


# Constants
MAX_MATCH_LENGTH = 200
MAX_SNIPPET_CHARS = 800
MAX_FINDINGS_PER_FILE = 100
