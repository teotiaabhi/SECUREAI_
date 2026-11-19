"use strict";
/**
 * File Classifier — Maps file paths and VS Code languageIds to rule languages.
 *
 * Port of engine/file_classifier.py EXTENSION_TO_LANGUAGE mapping.
 * Also handles skip logic for node_modules, .git, dist, etc.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.classifyLanguage = classifyLanguage;
exports.shouldSkipFile = shouldSkipFile;
const path = __importStar(require("path"));
// ── Extension → Rule Language Mapping ────────────────────────────
const EXTENSION_TO_LANGUAGE = {
    '.py': 'python',
    '.pyw': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.mts': 'typescript',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.erb': 'ruby',
    '.php': 'php',
    '.phtml': 'php',
    '.cs': 'csharp',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.c': 'cpp',
    '.h': 'cpp',
    '.hpp': 'cpp',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.sql': 'sql',
    '.sh': 'shell',
    '.bash': 'shell',
    '.zsh': 'shell',
    '.ps1': 'shell',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.vue': 'javascript',
    '.svelte': 'javascript',
    '.env': 'all',
    '.scala': 'scala',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
    '.scss': 'css',
    '.xml': 'xml',
    '.groovy': 'groovy',
    '.gradle': 'groovy',
    '.tf': 'terraform',
    '.tfvars': 'terraform',
    '.hcl': 'terraform',
    '.toml': 'yaml',
    '.ini': 'yaml',
    '.conf': 'yaml',
};
// ── VS Code languageId → Rule Language ───────────────────────────
const VSCODE_LANG_MAP = {
    'python': 'python',
    'javascript': 'javascript',
    'javascriptreact': 'javascript',
    'typescript': 'typescript',
    'typescriptreact': 'typescript',
    'java': 'java',
    'go': 'go',
    'rust': 'rust',
    'ruby': 'ruby',
    'php': 'php',
    'csharp': 'csharp',
    'c': 'cpp',
    'cpp': 'cpp',
    'swift': 'swift',
    'kotlin': 'kotlin',
    'sql': 'sql',
    'shellscript': 'shell',
    'powershell': 'shell',
    'yaml': 'yaml',
    'json': 'json',
    'jsonc': 'json',
    'vue': 'javascript',
    'svelte': 'javascript',
    'html': 'html',
    'css': 'css',
    'scss': 'css',
    'less': 'css',
    'xml': 'xml',
    'scala': 'scala',
    'groovy': 'groovy',
    'terraform': 'terraform',
    'dockerfile': 'dockerfile',
    'plaintext': undefined,
};
// ── Skip Directories ─────────────────────────────────────────────
const SKIP_DIRECTORIES = new Set([
    'node_modules', 'dist', 'build', '.next', '__pycache__',
    '.git', '.svn', '.hg', 'vendor', 'venv', '.venv', 'env',
    '.mypy_cache', '.pytest_cache', '.ruff_cache', 'coverage',
    '.nyc_output', '.cache', 'target', 'bin', 'obj', '.tox',
    '.eggs', 'htmlcov', '.gradle', '.mvn', '.idea', '.vscode',
    '.vs', 'bower_components', '.parcel-cache', '.turbo',
]);
// ── Skip Extensions ──────────────────────────────────────────────
const SKIP_EXTENSIONS = new Set([
    '.exe', '.dll', '.so', '.dylib', '.pyc', '.class', '.o',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp',
    '.mp3', '.mp4', '.avi', '.mov', '.wav',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.lock', '.min.js', '.min.css', '.map',
    '.chunk.js', '.bundle.js', '.d.ts', '.snap', '.wasm',
]);
// ── Public API ───────────────────────────────────────────────────
/**
 * Classify a file to its rule language. Returns null if unsupported.
 * Uses both file extension and VS Code languageId for best accuracy.
 */
function classifyLanguage(filePath, vscodeLangId) {
    // 1. Try VS Code languageId first (most accurate)
    if (vscodeLangId && vscodeLangId in VSCODE_LANG_MAP) {
        const mapped = VSCODE_LANG_MAP[vscodeLangId];
        if (mapped)
            return mapped;
    }
    // 2. Fall back to extension mapping
    const ext = getExtension(filePath);
    if (ext && ext in EXTENSION_TO_LANGUAGE) {
        return EXTENSION_TO_LANGUAGE[ext];
    }
    // 3. Check special filenames
    const basename = path.basename(filePath).toLowerCase();
    if (basename === 'dockerfile' || basename === 'containerfile')
        return 'dockerfile';
    if (basename === 'jenkinsfile')
        return 'groovy';
    return null;
}
/**
 * Check if a file should be skipped (node_modules, binaries, etc.).
 */
function shouldSkipFile(filePath) {
    const normalized = filePath.replace(/\\/g, '/').toLowerCase();
    const parts = normalized.split('/');
    // Check directory components
    for (const part of parts) {
        if (SKIP_DIRECTORIES.has(part))
            return true;
    }
    // Check extension
    const ext = getExtension(filePath);
    if (ext && SKIP_EXTENSIONS.has(ext))
        return true;
    // Skip files with no extension (likely binaries/README)
    if (!ext) {
        const basename = path.basename(filePath).toLowerCase();
        if (basename !== 'dockerfile' && basename !== 'containerfile' &&
            basename !== 'jenkinsfile' && basename !== 'makefile') {
            return true;
        }
    }
    return false;
}
// ── Helpers ──────────────────────────────────────────────────────
function getExtension(filePath) {
    const basename = path.basename(filePath).toLowerCase();
    // Compound extensions
    for (const compound of ['.min.js', '.min.css', '.d.ts', '.chunk.js', '.bundle.js']) {
        if (basename.endsWith(compound))
            return compound;
    }
    const dotPos = basename.lastIndexOf('.');
    if (dotPos > 0) {
        return basename.substring(dotPos);
    }
    return null;
}
//# sourceMappingURL=fileClassifier.js.map