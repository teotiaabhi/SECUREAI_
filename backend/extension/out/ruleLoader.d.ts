/**
 * Rule Loader — Loads bundled security rules from rules.json
 *
 * The rules are pre-compiled from YAML by scripts/bundleRules.ts.
 * At runtime, we load the JSON, compile regex patterns, and index by language.
 */
export interface BundledRule {
    rule_id: string;
    title: string;
    description: string;
    language: string;
    category: string;
    severity: string;
    confidence: number;
    cwe: string;
    owasp: string;
    impact: string;
    remediation: string;
    patterns: Array<{
        pattern: string;
        flags: number;
    }>;
    anti_patterns: string[];
}
export interface CompiledRule {
    rule: BundledRule;
    compiledPatterns: RegExp[];
}
export interface RuleIndex {
    rulesForLanguage(lang: string): CompiledRule[];
    getRule(ruleId: string): CompiledRule | undefined;
    readonly stats: {
        total: number;
        languages: number;
    };
}
export declare function loadRules(extensionPath: string): RuleIndex;
