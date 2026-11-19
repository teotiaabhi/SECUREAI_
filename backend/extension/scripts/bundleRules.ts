/**
 * Rule Bundler — Converts backend YAML security rules to a compact JSON bundle.
 *
 * Reads all .yaml/.yml files from backend/rules/, extracts relevant fields,
 * and writes out/rules.json for the extension to consume at runtime.
 *
 * Usage: npx ts-node scripts/bundleRules.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

// ── Types ────────────────────────────────────────────────────────

interface BundledRule {
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
    patterns: Array<{ pattern: string; flags: number }>;
    anti_patterns: string[];
}

// ── Flag Mapping (mirrors Python re module) ──────────────────────

const FLAG_MAP: Record<string, number> = {
    'IGNORECASE': 2,   // re.IGNORECASE
    'MULTILINE': 8,    // re.MULTILINE
    'DOTALL': 16,      // re.DOTALL
};

function determineFlags(flagsSpec?: string[]): number {
    if (!flagsSpec || flagsSpec.length === 0) {
        return 2 | 8; // Default: IGNORECASE | MULTILINE
    }
    let combined = 0;
    for (const name of flagsSpec) {
        const upper = name.toUpperCase();
        if (upper in FLAG_MAP) {
            combined |= FLAG_MAP[upper];
        }
    }
    return combined;
}

// ── Sanitization ─────────────────────────────────────────────────

function sanitizePattern(pattern: string): string {
    // Replace unbounded quantifiers with bounded equivalents
    // Same logic as Python rule_loader.py _sanitize_regex_pattern
    pattern = pattern.replace(/(?<!\\)\.\*\?(?!\{)/g, '.{0,500}?');
    pattern = pattern.replace(/(?<!\\)\.\*(?!\?|\{)/g, '.{0,500}');
    pattern = pattern.replace(/(?<!\\)\.\+\?(?!\{)/g, '.{1,500}?');
    pattern = pattern.replace(/(?<!\\)\.\+(?!\?|\{)/g, '.{1,500}');
    return pattern;
}

// ── Text Flattening ──────────────────────────────────────────────

function flattenValue(value: unknown): string {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return value.map(flattenValue).join('; ');
    if (typeof value === 'object') {
        const obj = value as Record<string, unknown>;
        if ('description' in obj) return String(obj.description || '');
        if ('steps' in obj && Array.isArray(obj.steps)) {
            return obj.steps.map(String).join('; ');
        }
        return Object.values(obj).map(flattenValue).join('; ');
    }
    return String(value);
}

// ── Main Bundler ─────────────────────────────────────────────────

function bundleRules(): void {
    const rulesDir = path.resolve(__dirname, '..', '..', 'rules');
    const outDir = path.resolve(__dirname, '..', 'out');

    if (!fs.existsSync(rulesDir)) {
        console.error(`Rules directory not found: ${rulesDir}`);
        process.exit(1);
    }

    // Ensure output directory exists
    fs.mkdirSync(outDir, { recursive: true });

    // Find all YAML files
    const yamlFiles = findYamlFiles(rulesDir);
    console.log(`Found ${yamlFiles.length} YAML rule files in ${rulesDir}`);

    const bundledRules: BundledRule[] = [];
    const seenIds = new Set<string>();
    let errors = 0;

    for (const filePath of yamlFiles) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const documents = yaml.loadAll(content) as unknown[];

            for (const doc of documents) {
                if (!doc || typeof doc !== 'object') continue;
                const docObj = doc as Record<string, unknown>;

                // Handle {rules: [...]} wrapper or direct rule dict
                let ruleItems: Record<string, unknown>[];
                if ('rules' in docObj && Array.isArray(docObj.rules)) {
                    ruleItems = docObj.rules as Record<string, unknown>[];
                } else if ('rule_id' in docObj) {
                    ruleItems = [docObj];
                } else {
                    continue;
                }

                for (const raw of ruleItems) {
                    const rule = parseRule(raw, filePath);
                    if (rule) {
                        if (seenIds.has(rule.rule_id)) {
                            // Remove old, keep new (last wins)
                            const idx = bundledRules.findIndex(r => r.rule_id === rule.rule_id);
                            if (idx >= 0) bundledRules.splice(idx, 1);
                        }
                        seenIds.add(rule.rule_id);
                        bundledRules.push(rule);
                    } else {
                        errors++;
                    }
                }
            }
        } catch (err) {
            console.error(`Error parsing ${filePath}: ${err}`);
            errors++;
        }
    }

    // Write output
    const outPath = path.join(outDir, 'rules.json');
    fs.writeFileSync(outPath, JSON.stringify(bundledRules), 'utf-8');

    const sizeKB = (fs.statSync(outPath).size / 1024).toFixed(1);
    console.log(`\n✅ Bundled ${bundledRules.length} rules → ${outPath} (${sizeKB} KB)`);
    console.log(`   Languages: ${new Set(bundledRules.map(r => r.language)).size}`);
    console.log(`   Errors: ${errors}`);
}

// ── Rule Parser ──────────────────────────────────────────────────

function parseRule(raw: Record<string, unknown>, sourcePath: string): BundledRule | null {
    // Required fields
    for (const field of ['rule_id', 'title', 'language', 'category', 'severity']) {
        if (!(field in raw)) {
            return null;
        }
    }

    const rawPatterns = raw.patterns as unknown[];
    if (!rawPatterns || !Array.isArray(rawPatterns) || rawPatterns.length === 0) {
        return null;
    }

    // Extract patterns
    const flagsSpec = raw.regex_flags as string[] | undefined;
    const defaultFlags = determineFlags(flagsSpec);
    const patterns: Array<{ pattern: string; flags: number }> = [];

    for (const entry of rawPatterns) {
        let patternStr: string;
        let flags: number;

        if (typeof entry === 'object' && entry !== null) {
            const obj = entry as Record<string, unknown>;
            patternStr = String(obj.pattern || '');
            flags = obj.flags ? determineFlags(obj.flags as string[]) : defaultFlags;
        } else {
            patternStr = String(entry);
            flags = defaultFlags;
        }

        if (!patternStr) continue;

        // Sanitize
        patternStr = sanitizePattern(patternStr);

        // Validate: try to compile as JS regex
        try {
            let jsFlags = '';
            if (flags & 2) jsFlags += 'i';
            if (flags & 8) jsFlags += 'm';
            if (flags & 16) jsFlags += 's';

            // Convert Python syntax
            let jsPattern = patternStr.replace(/\(\?P<([^>]+)>/g, '(?<$1>');
            jsPattern = jsPattern.replace(/\(\?P=([^)]+)\)/g, '\\k<$1>');

            new RegExp(jsPattern, jsFlags);
            patterns.push({ pattern: patternStr, flags });
        } catch {
            // Skip invalid patterns
        }
    }

    if (patterns.length === 0) return null;

    // Confidence normalization
    const rawConf = Number(raw.confidence || 0.5);
    const confidence = rawConf <= 1.0 ? rawConf : rawConf / 100.0;

    // Anti-patterns
    const rawAnti = (raw.anti_patterns || []) as unknown[];
    const antiPatterns: string[] = [];
    for (const ap of rawAnti) {
        if (!ap) continue;
        if (typeof ap === 'object') {
            const obj = ap as Record<string, unknown>;
            const p = String(obj.pattern || '');
            if (p) antiPatterns.push(p);
        } else {
            antiPatterns.push(String(ap));
        }
    }

    return {
        rule_id: String(raw.rule_id),
        title: String(raw.title),
        description: String(raw.description || ''),
        language: String(raw.language).toLowerCase(),
        category: String(raw.category).toLowerCase(),
        severity: String(raw.severity || 'medium').toLowerCase(),
        confidence,
        cwe: String(raw.cwe || ''),
        owasp: String(raw.owasp || ''),
        impact: flattenValue(raw.impact),
        remediation: flattenValue(raw.remediation),
        patterns,
        anti_patterns: antiPatterns,
    };
}

// ── File Discovery ───────────────────────────────────────────────

function findYamlFiles(dir: string): string[] {
    const results: string[] = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...findYamlFiles(fullPath));
        } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
            results.push(fullPath);
        }
    }

    return results.sort();
}

// ── Run ──────────────────────────────────────────────────────────

bundleRules();
