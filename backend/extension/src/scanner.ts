/**
 * Scanner — Core pattern matching engine for VS Code extension.
 *
 * TypeScript port of engine/detection_engine.py detect_in_file().
 * Runs compiled regex rules against file content, applies anti-pattern
 * suppression, extracts line numbers, deduplicates, and returns findings.
 */

import * as crypto from 'crypto';
import { CompiledRule } from './ruleLoader';

// ── Types ────────────────────────────────────────────────────────

export interface Finding {
    ruleId: string;
    title: string;
    description: string;
    severity: string;
    confidence: number;     // 0-100
    fileName: string;
    line: number;           // 1-based
    endLine: number;        // 1-based (end of the matched line range)
    column: number;         // 0-based start column
    endColumn: number;      // 0-based end column
    category: string;
    cwe: string;
    owasp: string;
    impact: string;
    remediation: string;
    matchedText: string;
    codeSnippet: string;
    detectionId: string;
}

// ── Constants ────────────────────────────────────────────────────

const MAX_FINDINGS_PER_FILE = 50;
const MAX_MATCH_LENGTH = 200;
const MAX_SNIPPET_CHARS = 500;
const SNIPPET_CONTEXT_LINES = 3;

// Accuracy improvement: import line prefixes
const IMPORT_PREFIXES = [
    'import ', 'from ', 'require(', 'use ', 'include ',
    'include_once ', 'require_once ', 'using ', '#include ',
];

// Comment prefixes by extension
const COMMENT_PREFIXES: Record<string, string[]> = {
    '.py': ['#'],
    '.rb': ['#'],
    '.js': ['//', '/*', '*'],
    '.jsx': ['//', '/*', '*'],
    '.ts': ['//', '/*', '*'],
    '.tsx': ['//', '/*', '*'],
    '.java': ['//', '/*', '*'],
    '.go': ['//', '/*'],
    '.rs': ['//', '/*', '*'],
    '.php': ['//', '#', '/*'],
    '.cs': ['//', '/*', '*'],
    '.kt': ['//', '/*', '*'],
    '.swift': ['//', '/*', '*'],
    '.c': ['//', '/*', '*'],
    '.cpp': ['//', '/*', '*'],
    '.sh': ['#'],
};

const IMPORT_LINE_PENALTY = 55;
const COMMENT_LINE_PENALTY = 70;
const CWE_DEDUP_PROXIMITY = 5;

// ── Main Scanner ─────────────────────────────────────────────────

/**
 * Scan a document's text against compiled rules.
 * Returns array of findings with precise line/column locations.
 */
export function scanDocument(
    content: string,
    fileName: string,
    rules: CompiledRule[],
): Finding[] {
    if (!content || rules.length === 0) return [];

    const findings: Finding[] = [];
    const seenKeys = new Set<string>();
    const contentLower = content.toLowerCase();
    const lines = content.split('\n');

    // Pre-compute string-literal lines for FP suppression
    const stringLines = buildStringLineMap(lines, fileName);

    for (const compiledRule of rules) {
        if (findings.length >= MAX_FINDINGS_PER_FILE) break;

        const { rule, compiledPatterns } = compiledRule;

        // Anti-pattern suppression: if any anti-pattern substring is found
        // in the file, skip ALL matches for this rule
        if (rule.anti_patterns.length > 0) {
            let suppressed = false;
            for (const ap of rule.anti_patterns) {
                if (contentLower.includes(ap.toLowerCase())) {
                    suppressed = true;
                    break;
                }
            }
            if (suppressed) continue;
        }

        // Run each compiled pattern against the content
        for (const pattern of compiledPatterns) {
            if (findings.length >= MAX_FINDINGS_PER_FILE) break;

            // Reset lastIndex for global/sticky patterns
            pattern.lastIndex = 0;

            // Use a non-global copy for matchAll-style iteration
            const globalPattern = new RegExp(
                pattern.source,
                pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'
            );

            let match: RegExpExecArray | null;
            let matchCount = 0;

            while ((match = globalPattern.exec(content)) !== null) {
                if (findings.length >= MAX_FINDINGS_PER_FILE) break;
                if (++matchCount > 20) break; // Safety: max 20 matches per pattern per file

                const matchedText = match[0].substring(0, MAX_MATCH_LENGTH);
                const startOffset = match.index;

                // Calculate line number (1-based)
                const lineNumber = getLineNumber(content, startOffset);

                // Scoped anti-pattern check (±30 lines around match)
                if (rule.anti_patterns.length > 0) {
                    const scopeStart = Math.max(0, lineNumber - 31);
                    const scopeEnd = Math.min(lines.length, lineNumber + 30);
                    const region = lines.slice(scopeStart, scopeEnd).join('\n').toLowerCase();
                    let scopeSuppressed = false;
                    for (const ap of rule.anti_patterns) {
                        if (region.includes(ap.toLowerCase())) {
                            scopeSuppressed = true;
                            break;
                        }
                    }
                    if (scopeSuppressed) continue;
                }

                // String-literal suppression (ROOT CAUSE FIX #1)
                // Skip matches on lines inside docstrings/multiline strings
                if (stringLines.has(lineNumber - 1)) continue;

                // Calculate column
                const lineStart = content.lastIndexOf('\n', startOffset - 1) + 1;
                const column = startOffset - lineStart;

                // Dedup: one finding per (rule, line) — ROOT CAUSE FIX #2
                const dedupKey = `${rule.rule_id}|${lineNumber}`;
                if (seenKeys.has(dedupKey)) continue;
                seenKeys.add(dedupKey);

                // Accuracy: detect import and comment lines → reduce confidence
                let adjustedConfidence = Math.round(rule.confidence * 100);
                const matchLine = lines[lineNumber - 1] || '';
                const matchLineTrimmed = matchLine.trimStart().toLowerCase();

                // Import-line suppression
                if (IMPORT_PREFIXES.some(p => matchLineTrimmed.startsWith(p))) {
                    adjustedConfidence = Math.max(5, adjustedConfidence - IMPORT_LINE_PENALTY);
                }

                // Comment-line suppression
                const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
                const commentPrefixes = COMMENT_PREFIXES[ext] || [];
                if (commentPrefixes.some(p => matchLineTrimmed.startsWith(p))) {
                    adjustedConfidence = Math.max(5, adjustedConfidence - COMMENT_LINE_PENALTY);
                }

                // Extract code snippet
                const snippet = extractSnippet(lines, lineNumber, SNIPPET_CONTEXT_LINES);

                // Generate detection ID
                const detectionId = generateDetectionId(rule.rule_id, fileName, lineNumber, matchedText);

                // Determine end line/column for the match
                const matchEnd = startOffset + match[0].length;
                const endLine = getLineNumber(content, Math.max(matchEnd - 1, startOffset));
                const endLineStart = content.lastIndexOf('\n', matchEnd - 1) + 1;
                const endColumn = matchEnd - endLineStart;

                findings.push({
                    ruleId: rule.rule_id,
                    title: rule.title,
                    description: rule.description,
                    severity: rule.severity,
                    confidence: adjustedConfidence,
                    fileName,
                    line: lineNumber,
                    endLine,
                    column,
                    endColumn,
                    category: rule.category,
                    cwe: rule.cwe,
                    owasp: rule.owasp,
                    impact: rule.impact,
                    remediation: rule.remediation,
                    matchedText,
                    codeSnippet: snippet,
                    detectionId,
                });

                // Prevent infinite loops on zero-length matches
                if (match[0].length === 0) {
                    globalPattern.lastIndex++;
                }
            }
        }
    }

    // CWE-based dedup: merge findings with same CWE within ±5 lines
    return deduplicateByCwe(findings);
}

/**
 * Build a set of 0-based line indices that are inside string literals.
 * Detects: triple-quoted blocks (Python), block comments, string assignments.
 */
function buildStringLineMap(lines: string[], fileName: string): Set<number> {
    const stringLines = new Set<number>();
    const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();

    // Track triple-quote blocks (Python)
    if (ext === '.py' || ext === '.pyw') {
        let inTriple = false;
        for (let i = 0; i < lines.length; i++) {
            const stripped = lines[i].trim();
            const dbl = (stripped.match(/\"\"\"/g) || []).length;
            const sgl = (stripped.match(/'''/g) || []).length;
            const toggles = dbl + sgl;

            if (inTriple) {
                stringLines.add(i);
                if (toggles % 2 === 1) inTriple = false;
            } else {
                if (toggles % 2 === 1) {
                    inTriple = true;
                    stringLines.add(i);
                } else if (toggles >= 2) {
                    stringLines.add(i);
                }
            }
        }
    }

    // Track /* */ block comments (C-family languages)
    if (['.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.cs', '.kt', '.swift', '.c', '.cpp', '.php', '.scala'].includes(ext)) {
        let inBlock = false;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (inBlock) {
                stringLines.add(i);
                if (line.includes('*/')) inBlock = false;
            } else {
                if (line.includes('/*')) {
                    if (!line.includes('*/') || line.indexOf('/*') > line.indexOf('*/')) {
                        inBlock = true;
                        stringLines.add(i);
                    }
                }
            }
        }
    }

    // String assignment lines (all languages)
    for (let i = 0; i < lines.length; i++) {
        if (stringLines.has(i)) continue;
        const stripped = lines[i].trim();
        // Pure string lines starting with quotes (>15 chars = likely doc string)
        if (/^["']/.test(stripped) && stripped.length > 15) {
            // Skip f-strings
            if (!stripped.startsWith('f"') && !stripped.startsWith("f'")) {
                stringLines.add(i);
            }
        }
        // String assignments: key = "....." or key: "....."
        const sepIdx = Math.max(stripped.indexOf('= "'), stripped.indexOf("= '"), stripped.indexOf(': "'), stripped.indexOf(": '"));
        if (sepIdx > 0) {
            const afterSep = stripped.substring(sepIdx + 3);
            if (afterSep.length > 30) {
                stringLines.add(i);
            }
        }
    }

    return stringLines;
}


// ── Helpers ──────────────────────────────────────────────────────

/**
 * Get 1-based line number for a character offset.
 */
function getLineNumber(content: string, offset: number): number {
    let line = 1;
    for (let i = 0; i < offset && i < content.length; i++) {
        if (content[i] === '\n') line++;
    }
    return line;
}

/**
 * Extract a code snippet around a line number.
 */
function extractSnippet(lines: string[], lineNumber: number, contextLines: number): string {
    const start = Math.max(0, lineNumber - 1 - contextLines);
    const end = Math.min(lines.length, lineNumber + contextLines);
    const snippetLines = lines.slice(start, end);

    let snippet = snippetLines
        .map((l, i) => {
            const num = start + i + 1;
            const marker = num === lineNumber ? '>>>' : '   ';
            return `${marker} ${num}: ${l}`;
        })
        .join('\n');

    if (snippet.length > MAX_SNIPPET_CHARS) {
        snippet = snippet.substring(0, MAX_SNIPPET_CHARS) + '...';
    }

    return snippet;
}

/**
 * Generate a deterministic detection ID.
 * sha256(rule_id|file_name|line|pattern) truncated to 16 hex chars.
 */
function generateDetectionId(
    ruleId: string,
    fileName: string,
    line: number,
    matchedText: string,
): string {
    const raw = `${ruleId}|${fileName}|${line}|${matchedText}`;
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
}

/**
 * CWE-based deduplication: merge findings with same CWE + file within ±5 lines.
 * Keeps the finding with highest confidence in each cluster.
 */
function deduplicateByCwe(findings: Finding[]): Finding[] {
    if (findings.length <= 1) return findings;

    // Group by (fileName, cwe)
    const groups = new Map<string, Finding[]>();
    const noCwe: Finding[] = [];

    for (const f of findings) {
        if (f.cwe) {
            const key = `${f.fileName}|${f.cwe}`;
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key)!.push(f);
        } else {
            noCwe.push(f);
        }
    }

    const result: Finding[] = [...noCwe];

    for (const group of groups.values()) {
        if (group.length === 1) {
            result.push(group[0]);
            continue;
        }

        // Sort by line
        group.sort((a, b) => a.line - b.line);

        // Cluster by proximity
        let cluster: Finding[] = [group[0]];
        for (let i = 1; i < group.length; i++) {
            if (group[i].line - cluster[cluster.length - 1].line <= CWE_DEDUP_PROXIMITY) {
                cluster.push(group[i]);
            } else {
                // Keep best from cluster
                result.push(bestFromCluster(cluster));
                cluster = [group[i]];
            }
        }
        result.push(bestFromCluster(cluster));
    }

    return result;
}

function bestFromCluster(cluster: Finding[]): Finding {
    const severityOrder: Record<string, number> = {
        'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4
    };
    return cluster.reduce((best, f) => {
        const bestSev = severityOrder[best.severity] ?? 4;
        const fSev = severityOrder[f.severity] ?? 4;
        if (fSev < bestSev || (fSev === bestSev && f.confidence > best.confidence)) {
            return f;
        }
        return best;
    });
}
