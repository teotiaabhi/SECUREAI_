/**
 * Diagnostics Provider — Converts scanner findings to VS Code diagnostics.
 *
 * Uses grey underline (DiagnosticTag.Unnecessary) for all findings,
 * with severity mapped to DiagnosticSeverity for proper icon coloring.
 */

import * as vscode from 'vscode';
import { Finding } from './scanner';

export const DIAGNOSTIC_COLLECTION_NAME = 'SecureAI';

/**
 * Severity icon for diagnostic messages.
 */
const SEVERITY_ICONS: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: '🟣',
};

/**
 * Map finding severity to VS Code DiagnosticSeverity.
 * All findings also get DiagnosticTag.Unnecessary for grey underline.
 */
function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toLowerCase()) {
        case 'critical':
            return vscode.DiagnosticSeverity.Error;
        case 'high':
            return vscode.DiagnosticSeverity.Warning;
        case 'medium':
            return vscode.DiagnosticSeverity.Information;
        case 'low':
        case 'info':
            return vscode.DiagnosticSeverity.Hint;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

/**
 * Convert findings to VS Code diagnostics with grey underline styling.
 */
export function createDiagnostics(
    findings: Finding[],
    document: vscode.TextDocument,
): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];

    for (const finding of findings) {
        // Create range — use the matched text span for precise underline
        const startLine = Math.max(0, finding.line - 1); // Convert to 0-based
        const endLine = Math.max(startLine, finding.endLine - 1);

        let range: vscode.Range;

        if (startLine < document.lineCount) {
            const docLine = document.lineAt(startLine);

            if (finding.column >= 0 && finding.endColumn > 0 && startLine === endLine) {
                // Precise column range from pattern match
                range = new vscode.Range(
                    startLine,
                    Math.min(finding.column, docLine.text.length),
                    endLine,
                    Math.min(finding.endColumn, docLine.text.length),
                );
            } else {
                // Fall back to full line (trimmed)
                range = new vscode.Range(
                    startLine,
                    docLine.firstNonWhitespaceCharacterIndex,
                    startLine,
                    docLine.text.length,
                );
            }
        } else {
            // Line out of bounds, use last line
            const lastLine = Math.max(0, document.lineCount - 1);
            range = new vscode.Range(lastLine, 0, lastLine, 0);
        }

        const icon = SEVERITY_ICONS[finding.severity] || '⚠️';
        const sevLabel = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);

        // Build diagnostic message
        const message = `${icon} ${finding.title} (${sevLabel})`;

        const diagnostic = new vscode.Diagnostic(range, message, mapSeverity(finding.severity));

        // Source label
        diagnostic.source = DIAGNOSTIC_COLLECTION_NAME;

        // Code: link to CWE if available
        if (finding.cwe) {
            const cweNum = finding.cwe.replace(/[^0-9]/g, '');
            if (cweNum) {
                diagnostic.code = {
                    value: finding.cwe,
                    target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweNum}.html`),
                };
            } else {
                diagnostic.code = finding.ruleId;
            }
        } else {
            diagnostic.code = finding.ruleId;
        }

        // Grey underline effect via Unnecessary tag
        diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];

        diagnostics.push(diagnostic);
    }

    return diagnostics;
}
