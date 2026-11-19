"use strict";
/**
 * Rule Loader — Loads bundled security rules from rules.json
 *
 * The rules are pre-compiled from YAML by scripts/bundleRules.ts.
 * At runtime, we load the JSON, compile regex patterns, and index by language.
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
exports.loadRules = loadRules;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
// ── Flag Mapping ─────────────────────────────────────────────────
/**
 * Convert Python re flags (integer) to JavaScript RegExp flags string.
 * Python: re.IGNORECASE=2, re.MULTILINE=8, re.DOTALL=16
 */
function pythonFlagsToJS(flags) {
    let jsFlags = '';
    if (flags & 2)
        jsFlags += 'i'; // re.IGNORECASE
    if (flags & 8)
        jsFlags += 'm'; // re.MULTILINE
    if (flags & 16)
        jsFlags += 's'; // re.DOTALL
    return jsFlags;
}
/**
 * Convert Python regex syntax to JavaScript-compatible regex.
 * Handles common incompatibilities.
 */
function pythonRegexToJS(pattern) {
    // Convert Python named groups (?P<name>...) → (?<name>...)
    let result = pattern.replace(/\(\?P<([^>]+)>/g, '(?<$1>');
    // Convert Python named backreferences (?P=name) → \k<name>
    result = result.replace(/\(\?P=([^)]+)\)/g, '\\k<$1>');
    return result;
}
// ── Loader ───────────────────────────────────────────────────────
function loadRules(extensionPath) {
    const rulesPath = path.join(extensionPath, 'out', 'rules.json');
    if (!fs.existsSync(rulesPath)) {
        throw new Error(`Rules file not found: ${rulesPath}. Run 'npm run bundle-rules' first.`);
    }
    const raw = fs.readFileSync(rulesPath, 'utf-8');
    const bundledRules = JSON.parse(raw);
    // Compile patterns and build index
    const byLanguage = new Map();
    const byId = new Map();
    const universalRules = [];
    let compiled = 0;
    let failed = 0;
    for (const rule of bundledRules) {
        const compiledPatterns = [];
        for (const p of rule.patterns) {
            try {
                const jsPattern = pythonRegexToJS(p.pattern);
                const jsFlags = pythonFlagsToJS(p.flags);
                compiledPatterns.push(new RegExp(jsPattern, jsFlags));
            }
            catch {
                failed++;
                // Skip invalid patterns silently
            }
        }
        if (compiledPatterns.length === 0) {
            continue; // No valid patterns
        }
        const compiledRule = { rule, compiledPatterns };
        // Index by language
        const lang = rule.language.toLowerCase();
        if (!byLanguage.has(lang)) {
            byLanguage.set(lang, []);
        }
        byLanguage.get(lang).push(compiledRule);
        // Universal rules (apply to all languages)
        if (lang === 'all' || lang === 'universal' || lang === 'yaml') {
            universalRules.push(compiledRule);
        }
        byId.set(rule.rule_id, compiledRule);
        compiled++;
    }
    console.log(`[SecureAI] Compiled ${compiled} rules (${failed} pattern failures)`);
    return {
        rulesForLanguage(lang) {
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
        getRule(ruleId) {
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
//# sourceMappingURL=ruleLoader.js.map