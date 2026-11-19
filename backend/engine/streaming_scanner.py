"""
Streaming scanner — regex matching with line-number tracking,
sliding-window support for large files, and backtracking protection.
"""

import logging
import re
import time
from bisect import bisect_right
from typing import List

from engine.models import PatternMatch, MAX_MATCH_LENGTH, MAX_SNIPPET_CHARS

logger = logging.getLogger("engine.streaming_scanner")

# ─── Constants ───────────────────────────────────────────────────────

STREAM_THRESHOLD = 262_144  # 256 KB — files below this are scanned whole
CHUNK_SIZE = 16_384  # 16 KB read windows
OVERLAP_SIZE = 4_096  # 4 KB overlap for cross-boundary patterns
PATTERN_TIMEOUT_MS = 200  # Skip pattern if single window > 200 ms (lowered from 500)
MAX_CONTENT_SIZE = 2_097_152  # 2 MB — skip files larger than this entirely
FILE_SCAN_TIMEOUT_MS = 5_000  # Hard timeout: skip entire file after 5 s


# ─── Line Tracking ───────────────────────────────────────────────────


def build_line_offset_table(content: str) -> List[int]:
    """Pre-compute character offsets of each line start.

    Returns list where table[i] = the character offset of line (i+1).
    Line 1 starts at offset 0, line 2 starts after the first newline, etc.
    Enables O(log n) offset-to-line conversion via binary search.
    """
    table = [0]
    idx = 0
    while True:
        idx = content.find("\n", idx)
        if idx == -1:
            break
        idx += 1
        table.append(idx)
    return table


def offset_to_line(offset: int, line_table: List[int]) -> int:
    """Convert a character offset to a 1-based line number.

    Uses binary search on the pre-computed line offset table.
    """
    return bisect_right(line_table, offset)


# ─── Whole-File Scan ─────────────────────────────────────────────────


def scan_content_whole(
    content: str,
    patterns: List[re.Pattern],
    line_table: List[int],
    file_start: float = 0.0,
) -> List[PatternMatch]:
    """Scan entire content against all patterns (for files < STREAM_THRESHOLD).

    For each pattern, uses finditer() to find all non-overlapping matches.
    Includes per-pattern wall-clock timeout for backtracking protection.
    Also checks per-file hard timeout.
    """
    matches: List[PatternMatch] = []

    for pat_idx, pattern in enumerate(patterns):
        # Check file-level hard timeout
        if file_start and (time.monotonic() - file_start) * 1000 > FILE_SCAN_TIMEOUT_MS:
            logger.warning(
                "File scan timeout (%.0f ms) reached at pattern %d/%d; stopping.",
                (time.monotonic() - file_start) * 1000, pat_idx, len(patterns),
            )
            break

        start_time = time.monotonic()
        try:
            for m in pattern.finditer(content):
                # Backtracking guard: check elapsed time every match
                elapsed_ms = (time.monotonic() - start_time) * 1000
                if elapsed_ms > PATTERN_TIMEOUT_MS:
                    logger.warning(
                        "Pattern %d timed out after %.0f ms on whole scan; skipping remainder.",
                        pat_idx,
                        elapsed_ms,
                    )
                    break

                matched_text = m.group()[:MAX_MATCH_LENGTH]
                line_num = offset_to_line(m.start(), line_table)

                matches.append(
                    PatternMatch(
                        pattern_index=pat_idx,
                        start_offset=m.start(),
                        end_offset=m.end(),
                        line_number=line_num,
                        matched_text=matched_text,
                    )
                )
        except re.error as exc:
            logger.error("Regex error on pattern %d: %s", pat_idx, exc)

    return matches


# ─── Streaming Scan (Sliding Window) ─────────────────────────────────


def scan_content_streaming(
    content: str,
    patterns: List[re.Pattern],
    line_table: List[int],
    file_start: float = 0.0,
) -> List[PatternMatch]:
    """Scan content using sliding window for files >= STREAM_THRESHOLD.

    Algorithm:
    1. Divide content into windows of CHUNK_SIZE with OVERLAP_SIZE overlap
    2. For each window, run all patterns via finditer()
    3. Convert local offsets to global offsets
    4. Deduplicate matches found in overlap regions (keep only from the
       window where the match starts in the non-overlap portion)
    5. Convert global offsets to line numbers
    Also checks per-file hard timeout.
    """
    content_len = len(content)
    step = CHUNK_SIZE - OVERLAP_SIZE
    matches: List[PatternMatch] = []
    seen_positions: set = set()  # (pattern_index, start_offset) dedup

    window_start = 0
    while window_start < content_len:
        # Check file-level hard timeout
        if file_start and (time.monotonic() - file_start) * 1000 > FILE_SCAN_TIMEOUT_MS:
            logger.warning(
                "File scan timeout (%.0f ms) reached at window offset %d; stopping.",
                (time.monotonic() - file_start) * 1000, window_start,
            )
            break

        window_end = min(window_start + CHUNK_SIZE, content_len)
        window = content[window_start:window_end]

        for pat_idx, pattern in enumerate(patterns):
            start_time = time.monotonic()
            try:
                for m in pattern.finditer(window):
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    if elapsed_ms > PATTERN_TIMEOUT_MS:
                        logger.warning(
                            "Pattern %d timed out in streaming window at offset %d; skipping.",
                            pat_idx,
                            window_start,
                        )
                        break

                    global_start = window_start + m.start()
                    global_end = window_start + m.end()

                    # Dedup: skip if this match was already found in a previous window's overlap
                    dedup_key = (pat_idx, global_start)
                    if dedup_key in seen_positions:
                        continue
                    seen_positions.add(dedup_key)

                    # Only accept matches whose start falls in the non-overlap portion
                    # (except for the last window where we accept everything)
                    non_overlap_end = window_start + step
                    if (
                        window_start > 0
                        and m.start() >= (CHUNK_SIZE - OVERLAP_SIZE)
                        and window_end < content_len
                    ):
                        # This match starts in the overlap zone and the next window
                        # will pick it up in its non-overlap zone
                        continue

                    matched_text = m.group()[:MAX_MATCH_LENGTH]
                    line_num = offset_to_line(global_start, line_table)

                    matches.append(
                        PatternMatch(
                            pattern_index=pat_idx,
                            start_offset=global_start,
                            end_offset=global_end,
                            line_number=line_num,
                            matched_text=matched_text,
                        )
                    )
            except re.error as exc:
                logger.error(
                    "Regex error on pattern %d at window %d: %s",
                    pat_idx,
                    window_start,
                    exc,
                )

        window_start += step

    return matches


# ─── Dispatcher ──────────────────────────────────────────────────────


def scan_file_content(
    content: str,
    patterns: List[re.Pattern],
) -> List[PatternMatch]:
    """Scan file content against compiled regex patterns.

    Chooses whole-file or streaming mode based on content size.
    Skips content larger than MAX_CONTENT_SIZE.
    Enforces a hard per-file timeout (FILE_SCAN_TIMEOUT_MS).
    Returns matches sorted by line number.
    """
    if not content or not patterns:
        return []

    if len(content) > MAX_CONTENT_SIZE:
        logger.warning(
            "Content size %d exceeds MAX_CONTENT_SIZE %d; skipping.",
            len(content),
            MAX_CONTENT_SIZE,
        )
        return []

    file_start = time.monotonic()
    line_table = build_line_offset_table(content)

    if len(content) < STREAM_THRESHOLD:
        matches = scan_content_whole(content, patterns, line_table, file_start)
    else:
        matches = scan_content_streaming(content, patterns, line_table, file_start)

    # Sort by line number, then by pattern index
    matches.sort(key=lambda m: (m.line_number, m.pattern_index))
    return matches


# ─── Snippet Extraction ──────────────────────────────────────────────


def extract_code_snippet(
    content: str,
    line_number: int,
    context_lines: int = 3,
    max_chars: int = MAX_SNIPPET_CHARS,
) -> str:
    """Extract surrounding code lines for a finding.

    Returns context_lines before and after the matched line,
    with line numbers prefixed. Truncated to max_chars.
    """
    lines = content.split("\n")
    total_lines = len(lines)

    start = max(0, line_number - 1 - context_lines)
    end = min(total_lines, line_number + context_lines)

    snippet_parts = []
    for i in range(start, end):
        line_num = i + 1
        marker = " >> " if line_num == line_number else "    "
        line_text = lines[i]
        if len(line_text) > 200:
            line_text = line_text[:200] + "..."
        snippet_parts.append(f"{line_num:4d}{marker}{line_text}")

    snippet = "\n".join(snippet_parts)
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars] + "\n... (truncated)"
    return snippet
