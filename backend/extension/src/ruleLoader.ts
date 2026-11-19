/**
 * Rule Loader — Loads bundled security rules from rules.json
 *
 * The rules are pre-compiled from YAML by scripts/bundleRules.ts.
 * At runtime, we load the JSON, compile regex patterns, and index by language.
 */

import * as path from 'path';
import * as fs from 'fs';

// ── Types ────────────────────────────────────────────────────────

export interface BundledRule {
    rule_id: string;
    title: string;
    description: string;
    language: string;
    category: string;
    severity: string;        // "critical" | "high" | "medium" | "low" | "info"
    confidence: number;      // 0.0 – 1.0
    cwe: string;
    owasp: string;
    impact: string;
    remediation: string;
    patterns: Array<{ pattern: string; flags: number }>;
    anti_patterns: string[];
}

export interface CompiledRule {
    rule: BundledRule;
    compiledPatterns: RegExp[];
}

export interface RuleIndex {
    rulesForLanguage(lang: string): CompiledRule[];
    getRule(ruleId: string): CompiledRule | undefined;
    readonly stats: { total: number; languages: number };
}

// ── Flag Mapping ─────────────────────────────────────────────────

/**
 * Convert Python re flags (integer) to JavaScript RegExp flags string.
 * Python: re.IGNORECASE=2, re.MULTILINE=8, re.DOTALL=16
 */
function pythonFlagsToJS(flags: number): string {
    let jsFlags = '';
    if (flags & 2) jsFlags += 'i';   // re.IGNORECASE
    if (flags & 8) jsFlags += 'm';   // re.MULTILINE
    if (flags & 16) jsFlags += 's';  // re.DOTALL
    return jsFlags;
}

/**
 * Convert Python regex syntax to JavaScript-compatible regex.
 * Handles common incompatibilities.
 */
function pythonRegexToJS(pattern: string): string {
    // Convert Python named groups (?P<name>...) → (?<name>...)
    let result = pattern.replace(/\(\?P<([^>]+)>/g, '(?<$1>');

    // Convert Python named backreferences (?P=name) → \k<name>
    result = result.replace(/\(\?P=([^)]+)\)/g, '\\k<$1>');

    return result;
}

// ── Loader ───────────────────────────────────────────────────────

export function loadRules(extensionPath: string): RuleIndex {
    const rulesPath = path.join(extensionPath, 'out', 'rules.json');

    if (!fs.existsSync(rulesPath)) {
        throw new Error(`Rules file not found: ${rulesPath}. Run 'npm run bundle-rules' first.`);
    }

    const raw = fs.readFileSync(rulesPath, 'utf-8');
    const bundledRules: BundledRule[] = JSON.parse(raw);

    // Compile patterns and build index
    const byLanguage = new Map<string, CompiledRule[]>();
    const byId = new Map<string, CompiledRule>();
    const universalRules: CompiledRule[] = [];
    let compiled = 0;
    let failed = 0;

    for (const rule of bundledRules) {
        const compiledPatterns: RegExp[] = [];

        for (const p of rule.patterns) {
            try {
                const jsPattern = pythonRegexToJS(p.pattern);
                const jsFlags = pythonFlagsToJS(p.flags);
                compiledPatterns.push(new RegExp(jsPattern, jsFlags));
            } catch {
                failed++;
                // Skip invalid patterns silently
            }
        }

        if (compiledPatterns.length === 0) {
            continue; // No valid patterns
        }

        const compiledRule: CompiledRule = { rule, compiledPatterns };

        // Index by language
        const lang = rule.language.toLowerCase();
        if (!byLanguage.has(lang)) {
            byLanguage.set(lang, []);
        }
        byLanguage.get(lang)!.push(compiledRule);

        // Universal rules (apply to all languages)
        if (lang === 'all' || lang === 'universal' || lang === 'yaml') {
            universalRules.push(compiledRule);
        }

        byId.set(rule.rule_id, compiledRule);
        compiled++;
    }

    console.log(`[SecureAI] Compiled ${compiled} rules (${failed} pattern failures)`);

    return {
        rulesForLanguage(lang: string): CompiledRule[] {
            const specific = byLanguage.get(lang.toLowerCase()) || [];
            // Add universal rules, avoiding duplicates
            const seenIds = new Set(specific.map(r => r.rule.rule_id));
            const combined = [...specific];
            for (const ur of universalRules) {
                if (!seenIds.has(ur.rule.rule_id)) {
                    combined.push(ur);
                }
            }
            return combined;
        },

        getRule(ruleId: string): CompiledRule | undefined {
            return byId.get(ruleId);
        },

        get stats() {
            return {
                total: compiled,
                languages: byLanguage.size,
            };
        },
    };
}
