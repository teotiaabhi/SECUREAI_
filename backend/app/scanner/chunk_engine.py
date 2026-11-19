"""
Structure-aware Chunk Engine
Splits code files into semantic chunks for analysis.
"""

import re
import uuid
from typing import List
from dataclasses import dataclass
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("chunk_engine")


@dataclass
class CodeChunk:
    chunk_id: str
    file_name: str
    file_path: str
    chunk_index: int
    content: str
    token_estimate: int
    chunk_type: str  # function | class | component | route | block


BACKEND_EXTENSIONS = {".py", ".java", ".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".c"}
FRONTEND_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".tf", ".hcl", ".xml"}


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return len(text) // 4


def _split_by_pattern(content: str, patterns: List[str]) -> List[str]:
    """Split content by regex patterns, keeping each match as a chunk."""
    combined = "|".join(f"({p})" for p in patterns)
    positions = [0]
    for m in re.finditer(combined, content, re.MULTILINE):
        if m.start() > 0:
            positions.append(m.start())
    positions.append(len(content))

    chunks = []
    for i in range(len(positions) - 1):
        chunk = content[positions[i]:positions[i + 1]].strip()
        if chunk:
            chunks.append(chunk)
    return chunks


def _split_backend(content: str) -> List[str]:
    patterns = [
        r"^(?:async\s+)?def\s+\w+",        # Python functions
        r"^class\s+\w+",                     # Python classes
        r"^func\s+\w+",                      # Go functions
        r"^(?:public|private|protected)\s+", # Java/C# methods
        r"^fn\s+\w+",                        # Rust functions
        r"^def\s+\w+",                       # Ruby functions
    ]
    return _split_by_pattern(content, patterns)


def _split_frontend(content: str) -> List[str]:
    patterns = [
        r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+\w+",
        r"^(?:export\s+)?const\s+\w+\s*=\s*(?:\(|React\.)",
        r"^(?:export\s+)?class\s+\w+",
        r"^(?:export\s+)?(?:const|let|var)\s+use\w+",  # hooks
        r"^app\.\w+\(|^router\.\w+\(",                  # routes
    ]
    return _split_by_pattern(content, patterns)


def _split_by_tokens(content: str, max_tokens: int) -> List[str]:
    """Fallback: split by line groups respecting token limit."""
    lines = content.split("\n")
    chunks = []
    current: List[str] = []
    current_tokens = 0

    for line in lines:
        line_tokens = estimate_tokens(line)
        if current_tokens + line_tokens > max_tokens and current:
            chunks.append("\n".join(current))
            current = [line]
            current_tokens = line_tokens
        else:
            current.append(line)
            current_tokens += line_tokens

    if current:
        chunks.append("\n".join(current))
    return chunks


def chunk_file(file_name: str, file_path: str, content: str, extension: str) -> List[CodeChunk]:
    """Split a single file into semantic chunks."""
    settings = get_settings()
    max_tokens = settings.MAX_CHUNK_TOKENS

    # Choose splitting strategy
    if extension in BACKEND_EXTENSIONS:
        raw_chunks = _split_backend(content)
        chunk_type = "function"
    elif extension in FRONTEND_EXTENSIONS:
        raw_chunks = _split_frontend(content)
        chunk_type = "component"
    elif extension in CONFIG_EXTENSIONS:
        raw_chunks = [content]  # Config files kept whole
        chunk_type = "block"
    else:
        raw_chunks = [content]
        chunk_type = "block"

    # If splitting didn't produce meaningful chunks, use the whole content
    if len(raw_chunks) <= 1:
        raw_chunks = [content]

    # Sub-split any chunks that exceed the token limit
    final_chunks: List[str] = []
    for chunk in raw_chunks:
        if estimate_tokens(chunk) > max_tokens:
            final_chunks.extend(_split_by_tokens(chunk, max_tokens))
        else:
            final_chunks.append(chunk)

    result = []
    for i, chunk_content in enumerate(final_chunks):
        if not chunk_content.strip():
            continue
        result.append(CodeChunk(
            chunk_id=str(uuid.uuid4()),
            file_name=file_name,
            file_path=file_path,
            chunk_index=i,
            content=chunk_content,
            token_estimate=estimate_tokens(chunk_content),
            chunk_type=chunk_type,
        ))

    logger.debug("file_chunked", file=file_name, chunks=len(result))
    return result


def chunk_files(files: list) -> List[CodeChunk]:
    """Chunk all ingested files."""
    all_chunks = []
    for f in files:
        chunks = chunk_file(f.filename, f.path, f.content, f.extension)
        all_chunks.extend(chunks)
    logger.info("total_chunks_created", count=len(all_chunks))
    return all_chunks
