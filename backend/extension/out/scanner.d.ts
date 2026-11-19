/**
 * Scanner — Core pattern matching engine for VS Code extension.
 *
 * TypeScript port of engine/detection_engine.py detect_in_file().
 * Runs compiled regex rules against file content, applies anti-pattern
 * suppression, extracts line numbers, deduplicates, and returns findings.
 */
import { CompiledRule } from './ruleLoader';
export interface Finding {
    ruleId: string;
    title: string;
    description: string;
    severity: string;
    confidence: number;
    fileName: string;
    line: number;
    endLine: number;
    column: number;
    endColumn: number;
    category: string;
    cwe: string;
    owasp: string;
    impact: string;
    remediation: string;
    matchedText: string;
    codeSnippet: string;
    detectionId: string;
}
/**
 * Scan a document's text against compiled rules.
 * Returns array of findings with precise line/column locations.
 */
export declare function scanDocument(content: string, fileName: string, rules: CompiledRule[]): Finding[];
