/**
 * SecureAI VS Code Extension — Main Entry Point
 *
 * Activates on startup, hooks into file open/save/change events,
 * scans code in real-time using 1000+ YAML security rules,
 * and shows grey underline diagnostics with hover tooltips.
 */

import * as vscode from 'vscode';
import { loadRules, RuleIndex } from './ruleLoader';
import { scanDocument } from './scanner';
import { createDiagnostics, DIAGNOSTIC_COLLECTION_NAME } from './diagnosticsProvider';
import { SecureAIHoverProvider } from './hoverProvider';
import { classifyLanguage, shouldSkipFile } from './fileClassifier';
import { Finding } from './scanner';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let ruleIndex: RuleIndex | null = null;
let enabled = true;
let debounceTimers: Map<string, NodeJS.Timeout> = new Map();

// Store findings per file for hover provider
export const findingsMap: Map<string, Finding[]> = new Map();

export function activate(context: vscode.ExtensionContext) {
    console.log('[SecureAI] Extension activating...');

    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
    context.subscriptions.push(diagnosticCollection);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'secureai.toggleRealTime';
    statusBarItem.tooltip = 'Click to toggle SecureAI real-time scanning';
    updateStatusBar(0);
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Load rules
    try {
        ruleIndex = loadRules(context.extensionPath);
        const stats = ruleIndex.stats;
        console.log(`[SecureAI] Loaded ${stats.total} rules across ${stats.languages} languages`);
    } catch (err) {
        console.error('[SecureAI] Failed to load rules:', err);
        vscode.window.showErrorMessage('SecureAI: Failed to load security rules. Check extension logs.');
        return;
    }

    // Register hover provider for all supported languages
    const hoverProvider = new SecureAIHoverProvider(findingsMap);
    context.subscriptions.push(
        vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider)
    );

    // ── Commands ──────────────────────────────────────────────────

    context.subscriptions.push(
        vscode.commands.registerCommand('secureai.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                scanAndReport(editor.document);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('secureai.toggleRealTime', () => {
            enabled = !enabled;
            if (!enabled) {
                diagnosticCollection.clear();
                findingsMap.clear();
                updateStatusBar(0);
            } else {
                // Re-scan active document
                const editor = vscode.window.activeTextEditor;
                if (editor) {
                    scanAndReport(editor.document);
                }
            }
            vscode.window.showInformationMessage(
                `SecureAI: Real-time scanning ${enabled ? 'enabled' : 'disabled'}`
            );
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('secureai.clearDiagnostics', () => {
            diagnosticCollection.clear();
            findingsMap.clear();
            updateStatusBar(0);
        })
    );

    // ── File Event Hooks ──────────────────────────────────────────

    // Scan on file open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((doc) => {
            if (isEnabled() && doc.uri.scheme === 'file') {
                scanAndReport(doc);
            }
        })
    );

    // Scan on file save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((doc) => {
            const config = vscode.workspace.getConfiguration('secureai');
            if (isEnabled() && config.get<boolean>('scanOnSave', true)) {
                scanAndReport(doc);
            }
        })
    );

    // Scan on type (debounced)
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            const config = vscode.workspace.getConfiguration('secureai');
            if (!isEnabled() || !config.get<boolean>('scanOnType', true)) {
                return;
            }

            const doc = event.document;
            if (doc.uri.scheme !== 'file') return;

            const key = doc.uri.toString();
            const existing = debounceTimers.get(key);
            if (existing) clearTimeout(existing);

            const delay = config.get<number>('scanDelay', 800);
            const timer = setTimeout(() => {
                debounceTimers.delete(key);
                scanAndReport(doc);
            }, delay);

            debounceTimers.set(key, timer);
        })
    );

    // Clear diagnostics when file is closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((doc) => {
            diagnosticCollection.delete(doc.uri);
            findingsMap.delete(doc.uri.toString());
        })
    );

    // Scan already-open documents on activation
    for (const doc of vscode.workspace.textDocuments) {
        if (doc.uri.scheme === 'file' && isEnabled()) {
            scanAndReport(doc);
        }
    }

    console.log('[SecureAI] Extension activated successfully');
}

export function deactivate() {
    // Clear all timers
    for (const timer of debounceTimers.values()) {
        clearTimeout(timer);
    }
    debounceTimers.clear();
    findingsMap.clear();
    console.log('[SecureAI] Extension deactivated');
}

// ── Internal Helpers ──────────────────────────────────────────────

function isEnabled(): boolean {
    if (!enabled) return false;
    const config = vscode.workspace.getConfiguration('secureai');
    return config.get<boolean>('enabled', true);
}

function scanAndReport(document: vscode.TextDocument): void {
    if (!ruleIndex) return;

    const filePath = document.uri.fsPath;
    if (shouldSkipFile(filePath)) return;

    const language = classifyLanguage(filePath, document.languageId);
    if (!language) return;

    const config = vscode.workspace.getConfiguration('secureai');
    const minSeverity = config.get<string>('minSeverity', 'low');
    const minConfidence = config.get<number>('minConfidence', 40);

    // Get rules for this language
    const rules = ruleIndex.rulesForLanguage(language);
    if (rules.length === 0) return;

    // Scan
    const findings = scanDocument(document.getText(), filePath, rules);

    // Filter by severity and confidence
    const severityOrder: Record<string, number> = {
        critical: 4, high: 3, medium: 2, low: 1, info: 0
    };
    const minSevLevel = severityOrder[minSeverity] ?? 1;

    const filtered = findings.filter((f) => {
        const sevLevel = severityOrder[f.severity] ?? 0;
        return sevLevel >= minSevLevel && f.confidence >= minConfidence;
    });

    // Store findings for hover provider
    findingsMap.set(document.uri.toString(), filtered);

    // Convert to diagnostics
    const diagnostics = createDiagnostics(filtered, document);
    diagnosticCollection.set(document.uri, diagnostics);

    // Update status bar
    updateStatusBar(filtered.length);
}

function updateStatusBar(count: number): void {
    if (!enabled) {
        statusBarItem.text = '$(shield) SecureAI: OFF';
        statusBarItem.backgroundColor = undefined;
        return;
    }

    if (count === 0) {
        statusBarItem.text = '$(shield) SecureAI: Clean';
        statusBarItem.backgroundColor = undefined;
    } else {
        statusBarItem.text = `$(shield) SecureAI: ${count} finding${count > 1 ? 's' : ''}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
}
