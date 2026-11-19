"""Language detection wrapper for CLI — delegates to engine.file_classifier."""

from typing import Dict, List, Optional, Set, Tuple

from engine.file_classifier import EXTENSION_TO_LANGUAGE, classify_language


def detect_language(file_path: str) -> Optional[str]:
    """Classify a file's language from its path.

    Returns language string or None if unrecognized.
    """
    return classify_language(file_path)


def get_supported_languages() -> List[str]:
    """Return sorted list of all supported language identifiers."""
    return sorted(set(EXTENSION_TO_LANGUAGE.values()))


def summarize_languages(files: List[Tuple[str, str]]) -> Dict[str, int]:
    """Count files per language from a list of (path, language) tuples."""
    counts: Dict[str, int] = {}
    for _, lang in files:
        counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items()))
