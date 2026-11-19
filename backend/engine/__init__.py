"""
Static Analysis Rule Execution Engine

Production-grade scanning engine that loads 450+ YAML security rules,
uses multiprocessing for parallel file scanning, streaming for large files,
deduplication, severity normalization, and async AI validation.

Usage in scan_service.py:
    from engine import scan_files
    rule_findings = scan_files(valid_files)

For AI-enhanced scanning:
    from engine import scan_files_with_ai_validation
    rule_findings = await scan_files_with_ai_validation(valid_files)
"""

from engine.pipeline import scan_files, scan_files_with_ai_validation
from engine.rule_loader import get_rule_index
from engine.models import EngineFinding

__version__ = "1.0.0"
__all__ = [
    "scan_files",
    "scan_files_with_ai_validation",
    "get_rule_index",
    "EngineFinding",
]
