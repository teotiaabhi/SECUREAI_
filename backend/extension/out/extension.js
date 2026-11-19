"use strict";
/**
 * SecureAI VS Code Extension — Main Entry Point
 *
 * Activates on startup, hooks into file open/save/change events,
 * scans code in real-time using 1000+ YAML security rules,
 * and shows grey underline diagnostics with hover tooltips.
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
exports.findingsMap = void 0;
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const ruleLoader_1 = require("./ruleLoader");
const scanner_1 = require("./scanner");
const diagnosticsProvider_1 = require("./diagnosticsProvider");
const hoverProvider_1 = require("./hoverProvider");
const fileClassifier_1 = require("./fileClassifier");
let diagnosticCollection;
let statusBarItem;
let ruleIndex = null;
let enabled = true;
let debounceTimers = new Map();
// Store findings per file for hover provider
exports.findingsMap = new Map();
function activate(context) {
    console.log('[SecureAI] Extension activating...');
    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection(diagnosticsProvider_1.DIAGNOSTIC_COLLECTION_NAME);
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
        ruleIndex = (0, ruleLoader_1.loadRules)(context.extensionPath);
        const stats = ruleIndex.stats;
        console.log(`[SecureAI] Loaded ${stats.total} rules across ${stats.languages} languages`);
    }
    catch (err) {
        console.error('[SecureAI] Failed to load rules:', err);
        vscode.window.showErrorMessage('SecureAI: Failed to load security rules. Check extension logs.');
        return;
    }
    // Register hover provider for all supported languages
    const hoverProvider = new hoverProvider_1.SecureAIHoverProvider(exports.findingsMap);
    context.subscriptions.push(vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider));
    // ── Commands ──────────────────────────────────────────────────
    context.subscriptions.push(vscode.commands.registerCommand('secureai.scanFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            scanAndReport(editor.document);
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('secureai.toggleRealTime', () => {
        enabled = !enabled;
        if (!enabled) {
            diagnosticCollection.clear();
            exports.findingsMap.clear();
            updateStatusBar(0);
        }
        else {
            // Re-scan active document
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                scanAndReport(editor.document);
            }
        }
        vscode.window.showInformationMessage(`SecureAI: Real-time scanning ${enabled ? 'enabled' : 'disabled'}`);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('secureai.clearDiagnostics', () => {
        diagnosticCollection.clear();
        exports.findingsMap.clear();
        updateStatusBar(0);
    }));
    // ── File Event Hooks ──────────────────────────────────────────
    // Scan on file open
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument((doc) => {
        if (isEnabled() && doc.uri.scheme === 'file') {
            scanAndReport(doc);
        }
    }));
    // Scan on file save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
        const config = vscode.workspace.getConfiguration('secureai');
        if (isEnabled() && config.get('scanOnSave', true)) {
            scanAndReport(doc);
        }
    }));
    // Scan on type (debounced)
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        const config = vscode.workspace.getConfiguration('secureai');
        if (!isEnabled() || !config.get('scanOnType', true)) {
            return;
        }
        const doc = event.document;
        if (doc.uri.scheme !== 'file')
            return;
        const key = doc.uri.toString();
        const existing = debounceTimers.get(key);
        if (existing)
            clearTimeout(existing);
        const delay = config.get('scanDelay', 800);
        const timer = setTimeout(() => {
            debounceTimers.delete(key);
            scanAndReport(doc);
        }, delay);
        debounceTimers.set(key, timer);
    }));
    // Clear diagnostics when file is closed
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument((doc) => {
        diagnosticCollection.delete(doc.uri);
        exports.findingsMap.delete(doc.uri.toString());
    }));
    // Scan already-open documents on activation
    for (const doc of vscode.workspace.textDocuments) {
        if (doc.uri.scheme === 'file' && isEnabled()) {
            scanAndReport(doc);
        }
    }
    console.log('[SecureAI] Extension activated successfully');
}
function deactivate() {
    // Clear all timers
    for (const timer of debounceTimers.values()) {
        clearTimeout(timer);
    }
    debounceTimers.clear();
    exports.findingsMap.clear();
    console.log('[SecureAI] Extension deactivated');
}
// ── Internal Helpers ──────────────────────────────────────────────
function isEnabled() {
    if (!enabled)
        return false;
    const config = vscode.workspace.getConfiguration('secureai');
    return config.get('enabled', true);
}
function scanAndReport(document) {
    if (!ruleIndex)
        return;
    const filePath = document.uri.fsPath;
    if ((0, fileClassifier_1.shouldSkipFile)(filePath))
        return;
    const language = (0, fileClassifier_1.classifyLanguage)(filePath, document.languageId);
    if (!language)
        return;
    const config = vscode.workspace.getConfiguration('secureai');
    const minSeverity = config.get('minSeverity', 'low');
    const minConfidence = config.get('minConfidence', 40);
    // Get rules for this language
    const rules = ruleIndex.rulesForLanguage(language);
    if (rules.length === 0)
        return;
    // Scan
    const findings = (0, scanner_1.scanDocument)(document.getText(), filePath, rules);
    // Filter by severity and confidence
    const severityOrder = {
        critical: 4, high: 3, medium: 2, low: 1, info: 0
    };
    const minSevLevel = severityOrder[minSeverity] ?? 1;
    const filtered = findings.filter((f) => {
        const sevLevel = severityOrder[f.severity] ?? 0;
        return sevLevel >= minSevLevel && f.confidence >= minConfidence;
    });
    // Store findings for hover provider
    exports.findingsMap.set(document.uri.toString(), filtered);
    // Convert to diagnostics
    const diagnostics = (0, diagnosticsProvider_1.createDiagnostics)(filtered, document);
    diagnosticCollection.set(document.uri, diagnostics);
    // Update status bar
    updateStatusBar(filtered.length);
}
function updateStatusBar(count) {
    if (!enabled) {
        statusBarItem.text = '$(shield) SecureAI: OFF';
        statusBarItem.backgroundColor = undefined;
        return;
    }
    if (count === 0) {
        statusBarItem.text = '$(shield) SecureAI: Clean';
        statusBarItem.backgroundColor = undefined;
    }
    else {
        statusBarItem.text = `$(shield) SecureAI: ${count} finding${count > 1 ? 's' : ''}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
}
//# sourceMappingURL=extension.js.map