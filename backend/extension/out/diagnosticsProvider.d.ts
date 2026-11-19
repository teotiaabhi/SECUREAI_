/**
 * Diagnostics Provider — Converts scanner findings to VS Code diagnostics.
 *
 * Uses grey underline (DiagnosticTag.Unnecessary) for all findings,
 * with severity mapped to DiagnosticSeverity for proper icon coloring.
 */
import * as vscode from 'vscode';
import { Finding } from './scanner';
export declare const DIAGNOSTIC_COLLECTION_NAME = "SecureAI";
/**
 * Convert findings to VS Code diagnostics with grey underline styling.
 */
export declare function createDiagnostics(findings: Finding[], document: vscode.TextDocument): vscode.Diagnostic[];
