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
export declare class SecureAIHoverProvider implements vscode.HoverProvider {
    private findingsMap;
    constructor(findingsMap: Map<string, Finding[]>);
    provideHover(document: vscode.TextDocument, position: vscode.Position, _token: vscode.CancellationToken): vscode.Hover | null;
}
