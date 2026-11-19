/**
 * SecureAI VS Code Extension — Main Entry Point
 *
 * Activates on startup, hooks into file open/save/change events,
 * scans code in real-time using 1000+ YAML security rules,
 * and shows grey underline diagnostics with hover tooltips.
 */
import * as vscode from 'vscode';
import { Finding } from './scanner';
export declare const findingsMap: Map<string, Finding[]>;
export declare function activate(context: vscode.ExtensionContext): void;
export declare function deactivate(): void;
