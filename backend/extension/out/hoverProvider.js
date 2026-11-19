"use strict";
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
exports.SecureAIHoverProvider = void 0;
const vscode = __importStar(require("vscode"));
// ── Severity Colors & Badges ─────────────────────────────────────
const SEVERITY_BADGE = {
    critical: '🔴 **CRITICAL**',
    high: '🟠 **HIGH**',
    medium: '🟡 **MEDIUM**',
    low: '🔵 **LOW**',
    info: '🟣 **INFO**',
};
class SecureAIHoverProvider {
    constructor(findingsMap) {
        this.findingsMap = findingsMap;
    }
    provideHover(document, position, _token) {
        const findings = this.findingsMap.get(document.uri.toString());
        if (!findings || findings.length === 0)
            return null;
        // Find findings that overlap with the hover position
        const hoveredFindings = findings.filter((f) => {
            const startLine = f.line - 1; // Convert to 0-based
            const endLine = f.endLine - 1;
            return position.line >= startLine && position.line <= endLine;
        });
        if (hoveredFindings.length === 0)
            return null;
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
            const tags = [];
            if (finding.cwe)
                tags.push(`\`${finding.cwe}\``);
            if (finding.owasp)
                tags.push(`\`${finding.owasp}\``);
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
exports.SecureAIHoverProvider = SecureAIHoverProvider;
//# sourceMappingURL=hoverProvider.js.map