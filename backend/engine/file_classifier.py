"""
File classifier — maps extensions to languages, determines skip/scan decisions,
and resolves DB categories for findings.
"""

from pathlib import PurePosixPath
from typing import Optional, Set

# ─── YAML Language Family ────────────────────────────────────────────
# Languages whose files are YAML-based configuration and should be
# scanned by the dedicated yaml_scanner subsystem, NOT the generic
# code-rule engine.

YAML_LANGUAGES: Set[str] = {
    "yaml",
    "kubernetes",
    "helm",
    "github_actions",
    "gitlab_ci",
    "bitbucket_pipelines",
}

# ─── Extension → Language Mapping ────────────────────────────────────

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".erb": "ruby",
    ".php": "php",
    ".phtml": "php",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".vue": "javascript",
    ".svelte": "javascript",
    ".env": "all",
    # ── New languages ────────────────────────────────────────────────
    ".scala": "scala",
    ".sc": "scala",
    ".sbt": "scala",
    ".m": "objectivec",
    ".mm": "objectivec",
    ".html": "html",
    ".htm": "html",
    ".xhtml": "html",
    ".ejs": "html",
    ".hbs": "html",
    ".handlebars": "html",
    ".jinja": "html",
    ".jinja2": "html",
    ".njk": "html",
    ".pug": "html",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
    ".xml": "xml",
    ".xsl": "xml",
    ".xslt": "xml",
    ".xsd": "xml",
    ".svg": "xml",
    ".pom": "xml",
    ".wsdl": "xml",
    ".cbl": "cobol",
    ".cob": "cobol",
    ".cpy": "cobol",
    ".abap": "abap",
    ".cls": "apex",
    ".trigger": "apex",
    ".apex": "apex",
    ".pls": "plsql",
    ".plb": "plsql",
    ".pck": "plsql",
    ".pkb": "plsql",
    ".pks": "plsql",
    ".fnc": "plsql",
    ".prc": "plsql",
    ".trg": "plsql",
    ".tsql": "tsql",
    ".rpgle": "rpg",
    ".rpg": "rpg",
    ".sqlrpgle": "rpg",
    ".pli": "pli",
    ".pl1": "pli",
    ".vb": "vbnet",
    ".vbs": "vb6",
    ".bas": "vb6",
    ".frm": "vb6",
    ".groovy": "groovy",
    ".gvy": "groovy",
    ".gy": "groovy",
    ".gsh": "groovy",
    ".gradle": "groovy",
    # ── Infrastructure as Code ───────────────────────────────────────
    ".dockerfile": "dockerfile",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".hcl": "terraform",
    ".toml": "yaml",
    ".ini": "yaml",
    ".cfg": "yaml",
    ".conf": "yaml",
}

# ─── Skip Lists ──────────────────────────────────────────────────────

SKIP_DIRECTORIES: Set[str] = {
    "node_modules",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".git",
    ".svn",
    ".hg",
    "vendor",
    "venv",
    ".venv",
    "env",
    ".env",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "coverage",
    ".nyc_output",
    ".cache",
    "target",
    "bin",
    "obj",
    ".tox",
    ".eggs",
    "htmlcov",
    ".gradle",
    ".mvn",
    ".idea",
    ".vscode",
    ".vs",
    "bower_components",
    "jspm_packages",
    ".parcel-cache",
    ".turbo",
}

DEFAULT_IGNORE: Set[str] = {
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".git",
    "__pycache__",
    "venv",
    ".venv",
}

DEFAULT_IGNORE_FILES: Set[str] = {
    ".env",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "secureai-report.json",
}

SKIP_EXTENSIONS: Set[str] = {
    # Binary
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".pyo",
    ".class",
    ".o",
    ".obj",
    ".a",
    ".lib",
    # Images
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".webp",
    # Media
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wav",
    ".flac",
    ".ogg",
    # Documents
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    # Archives
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".bz2",
    ".xz",
    # Fonts
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    # Misc
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
    ".chunk.js",
    ".bundle.js",
    ".d.ts",
    ".snap",
    ".wasm",
}

# ─── Frontend Detection ──────────────────────────────────────────────

FRONTEND_PATH_SEGMENTS: Set[str] = {
    "components",
    "pages",
    "hooks",
    "views",
    "layouts",
    "templates",
    "static",
    "public",
    "src/app",
    "src/ui",
}

FRONTEND_EXTENSIONS: Set[str] = {".jsx", ".tsx", ".vue", ".svelte"}

# ─── Category Mapping ────────────────────────────────────────────────

CATEGORY_MAP = {
    "injection": "Backend Security",
    "auth": "Backend Security",
    "crypto": "Backend Security",
    "rce": "Backend Security",
    "deserialization": "Backend Security",
    "framework_misuse": "Backend Security",
    "path_traversal": "Backend Security",
    "xss": "Frontend Security",
    "ssrf": "API Security",
    "secrets": "Config & Infra",
    "devops": "Config & Infra",
}

# Categories whose frontend override applies
FRONTEND_OVERRIDABLE = {"injection", "auth", "framework_misuse", "xss"}


# ─── Public API ──────────────────────────────────────────────────────


def should_skip_file(file_path: str) -> bool:
    """Return True if the file should not be scanned.

    Checks: scan scope exclusions, default ignore directories/files,
    directory skip list, extension skip list, self-scan protection,
    report integrity protection.
    """
    # Delegate to scan_scope for comprehensive exclusion checks
    # (covers PART 1, 5, 6, 9 of result accuracy pipeline)
    from engine.scan_scope import should_exclude_path
    if should_exclude_path(file_path):
        return True

    path_lower = file_path.replace("\\", "/").lower()
    basename = PurePosixPath(path_lower).name

    if basename in DEFAULT_IGNORE_FILES:
        return True

    # Check directory components
    parts = path_lower.split("/")
    for part in parts:
        if part in SKIP_DIRECTORIES or part in DEFAULT_IGNORE:
            return True

    ext = _get_extension(file_path).lower()
    if ext in SKIP_EXTENSIONS:
        return True

    # Skip files with no extension (likely binaries or README)
    if not ext:
        return True

    return False


def is_frontend_context(file_path: str, extension: str) -> bool:
    """Determine if a file is in a frontend context for category override."""
    if extension.lower() in FRONTEND_EXTENSIONS:
        return True

    path_lower = file_path.replace("\\", "/").lower()
    for segment in FRONTEND_PATH_SEGMENTS:
        if f"/{segment}/" in path_lower or path_lower.startswith(f"{segment}/"):
            return True

    return False


def resolve_db_category(
    yaml_category: str, file_path: str, language: str
) -> str:
    """Map YAML category + file context to DB category string.

    Returns one of: Backend Security, Frontend Security, API Security,
    Config & Infra, Dependency Risk.
    """
    cat_lower = yaml_category.lower()
    base_category = CATEGORY_MAP.get(cat_lower, "Backend Security")

    # Frontend override for JS/TS files in frontend paths
    if (
        cat_lower in FRONTEND_OVERRIDABLE
        and language in ("javascript", "typescript")
    ):
        ext = _get_extension(file_path).lower()
        if is_frontend_context(file_path, ext):
            return "Frontend Security"

    return base_category


# ─── Helpers ─────────────────────────────────────────────────────────


def _get_extension(file_path: str) -> str:
    """Extract file extension, handling compound extensions like .min.js."""
    path_lower = file_path.lower()
    # Check compound extensions first
    for compound in (".min.js", ".min.css", ".d.ts", ".chunk.js", ".bundle.js"):
        if path_lower.endswith(compound):
            return compound

    # Handle Dockerfile (no extension)
    basename = file_path.replace("\\", "/").split("/")[-1].lower()
    if basename in ("dockerfile", "containerfile"):
        return ".dockerfile"
    if basename in ("jenkinsfile", "groovyfile"):
        return ".groovy"

    # Standard extension
    dot_pos = basename.rfind(".")
    if dot_pos > 0:
        return basename[dot_pos:]
    return ""


# ─── Filename / Path-based Language Overrides ────────────────────────

_FILENAME_LANGUAGE_MAP = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "docker-compose.yml": "dockerfile",
    "docker-compose.yaml": "dockerfile",
    ".dockerignore": "dockerfile",
    "jenkinsfile": "groovy",
    "vagrantfile": "ruby",
    "rakefile": "ruby",
    "gemfile": "ruby",
    "guardfile": "ruby",
}

# Path-segment-based CI/CD language detection
_PATH_LANGUAGE_PATTERNS = {
    ".github/workflows": "github_actions",
    ".gitlab-ci": "gitlab_ci",
    "bitbucket-pipelines": "bitbucket_pipelines",
}

_HELM_INDICATORS = {"templates/", "charts/", "chart.yaml", "values.yaml"}
_K8S_INDICATORS = {"kind:", "apiversion:", "metadata:", "spec:"}


def classify_language(file_path: str) -> Optional[str]:
    """Map a file path's extension to the YAML rule language identifier.

    Returns None for unknown or binary extensions.
    Uses extension, filename, path patterns, and shebang heuristics.
    """
    ext = _get_extension(file_path).lower()
    if ext in SKIP_EXTENSIONS:
        return None

    path_lower = file_path.replace("\\", "/").lower()
    basename = path_lower.rsplit("/", 1)[-1]

    # 1. Exact filename match
    fname_lang = _FILENAME_LANGUAGE_MAP.get(basename)
    if fname_lang:
        return fname_lang

    # 2. Path-based CI/CD detection
    for path_seg, lang in _PATH_LANGUAGE_PATTERNS.items():
        if path_seg in path_lower:
            return lang

    # 3. Helm chart detection (YAML in charts/templates dirs)
    if ext in (".yaml", ".yml", ".tpl"):
        for indicator in ("templates/", "charts/", "/helm/"):
            if indicator in path_lower:
                return "helm"
        if basename in ("chart.yaml", "chart.yml", "values.yaml", "values.yml"):
            return "helm"

    # 4. Kubernetes manifest detection
    if ext in (".yaml", ".yml") and any(
        seg in path_lower
        for seg in ("k8s/", "kubernetes/", "manifests/", "deploy/", "kustomize/")
    ):
        return "kubernetes"

    # 5. Terraform
    if ext in (".tf", ".tfvars", ".hcl"):
        return "terraform"

    # 6. Standard extension mapping
    return EXTENSION_TO_LANGUAGE.get(ext)
