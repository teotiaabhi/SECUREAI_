/**
 * Hover Provider — Shows detailed vulnerability info when hovering over
 * underlined code.
 *
 * Renders a rich Markdown tooltip with:
 * - Vulnerability title + severity badge
 * - CWE/OWASP mapping
 * - Description
 * - Impact
 * - Remediation steps
 * - Code snippet
 */

import * as vscode from 'vscode';
import { Finding } from './scanner';

// ── Severity Colors & Badges ─────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
    critical: '🔴 **CRITICAL**',
    high: '🟠 **HIGH**',
    medium: '🟡 **MEDIUM**',
    low: '🔵 **LOW**',
    info: '🟣 **INFO**',
};

export class SecureAIHoverProvider implements vscode.HoverProvider {
    constructor(private findingsMap: Map<string, Finding[]>) {}

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        _token: vscode.CancellationToken,
    ): vscode.Hover | null {
        const findings = this.findingsMap.get(document.uri.toString());
        if (!findings || findings.length === 0) return null;

        // Find findings that overlap with the hover position
        const hoveredFindings = findings.filter((f) => {
            const startLine = f.line - 1; // Convert to 0-based
            const endLine = f.endLine - 1;
            return position.line >= startLine && position.line <= endLine;
        });

        if (hoveredFindings.length === 0) return null;

        // Build markdown content for all findings on this line
        const contents = new vscode.MarkdownString('', true);
        contents.isTrusted = true;
        contents.supportHtml = true;

        for (let i = 0; i < hoveredFindings.length; i++) {
            const finding = hoveredFindings[i];

            if (i > 0) {
                contents.appendMarkdown('\n\n---\n\n');
            }

            // Header
            const badge = SEVERITY_BADGE[finding.severity] || '⚠️ **UNKNOWN**';
            contents.appendMarkdown(`## 🛡️ ${finding.title}\n\n`);
            contents.appendMarkdown(`${badge}`);

            // CWE / OWASP tags
            const tags: string[] = [];
            if (finding.cwe) tags.push(`\`${finding.cwe}\``);
            if (finding.owasp) tags.push(`\`${finding.owasp}\``);
            if (tags.length > 0) {
                contents.appendMarkdown(` · ${tags.join(' · ')}`);
            }
            contents.appendMarkdown(` · Confidence: ${finding.confidence}%`);
            contents.appendMarkdown('\n\n');

            // Separator
            contents.appendMarkdown('---\n\n');

            // Description
            if (finding.description) {
                contents.appendMarkdown(`**📋 Description**\n\n`);
                contents.appendMarkdown(`${finding.description}\n\n`);
            }

            // Impact
            if (finding.impact) {
                contents.appendMarkdown(`**💥 Impact**\n\n`);
                contents.appendMarkdown(`${finding.impact}\n\n`);
            }

            // Remediation
            if (finding.remediation) {
                contents.appendMarkdown(`**🔧 How to Fix**\n\n`);
                contents.appendMarkdown(`${finding.remediation}\n\n`);
            }

            // Rule metadata
            contents.appendMarkdown(`\n*Rule: \`${finding.ruleId}\` · Category: ${finding.category}*`);
        }

        return new vscode.Hover(contents);
    }
}
