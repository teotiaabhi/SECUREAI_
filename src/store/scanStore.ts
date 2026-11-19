import { create } from 'zustand';
import type {
  ExploitGraph,
  RemediationFix,
  DeveloperExplanation,
} from '@/types/security';
import { scanApi, type VulnerabilityData } from '@/api/scans';

export type ScanDepth = 'basic' | 'standard' | 'deep';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type VulnStatus = 'open' | 'fixed' | 'ignored';
export type ScanPhase = 'idle' | 'uploading' | 'queued' | 'cloning' | 'extracting' | 'classifying' | 'analyzing' | 'scanning' | 'ai_validating' | 'ai_reasoning' | 'reporting' | 'generating_report' | 'complete' | 'failed' | 'cancelled';

export interface InputFile {
    id: string;
    name: string;
    language: string;
    size: number;
    content: string;
    errors: string[];
}

export interface ScanConfig {
    depth: ScanDepth;
    categories: {
        backend: boolean;
        frontend: boolean;
        api: boolean;
        config: boolean;
        dependencies: boolean;
    };
    aiReasoning: boolean;
    exploitExamples: boolean;
    secureRewrite: boolean;
}

export interface Vulnerability {
    id: string;
    name: string;
    type: string;
    severity: SeverityLevel;
    file: string;
    line: number | null;
    confidence: number;
    status: VulnStatus;
    impact: string;
    exploitExample: string;
    securePatch: string;
    codeSnippet: string;
    fixedCode: string;
    owaspRef: string;
    cweRef: string;
    category: string;
    ruleId: string;
    detectionId: string;
    // Enrichment fields
    exploitChainName: string;
    chainRiskMultiplier: number;
    attackSurfaceType: string;
    detectionLayer: number;
    vulnerabilityFamily: string;
    exploitabilityScore: string;
    adjustedConfidence: number | null;
    intelligenceModifiers: string[];
    correlationFlags: string[];
    evidenceCount: number;
    clusteredRuleIds: string[];
    mergedRuleIds: string[];
}

export interface ScanResult {
    id: string;
    timestamp: string;
    totalFiles: number;
    totalVulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    securityScore: number;
    grade: string;
    confidenceScore: number;
    vulnerabilities: Vulnerability[];
    duration: number;
    repoName: string;
}

// Report analytics (loaded separately)
export interface ReportData {
    securityScore: number;
    confidenceScore: number;
    grade: string;
    totalFiles: number;
    totalFindings: number;
    severityCounts: Record<string, number>;
    owaspDistribution: Record<string, number>;
    cweDistribution: Record<string, number>;
    categoryDistribution: Record<string, number>;
    fileRiskRanking: Array<{ file: string; riskScore: number; vulnCount: number; criticalCount?: number; highCount?: number }>;
    executiveSummary: string;
    postureSummary: string;
}

export interface ScanProgress {
    phase: ScanPhase;
    percent: number;
    currentFile: string;
    chunksProcessed: number;
    totalChunks: number;
    estimatedTimeRemaining: number;
    liveVulnCount: number;
}

interface ScanState {
    files: InputFile[];
    config: ScanConfig;
    progress: ScanProgress;
    result: ScanResult | null;
    activeScanId: string | null;
    error: string | null;
    _pollAbort: AbortController | null;
    // Enrichment state
    reportData: ReportData | null;
    enrichmentCache: Record<string, { remediationFix: RemediationFix | null; developerExplanation: DeveloperExplanation | null }>;
    exploitGraph: ExploitGraph | null;
    loadingReport: boolean;
    loadingGraph: boolean;
    // Base actions
    addFile: (file: InputFile) => void;
    removeFile: (id: string) => void;
    clearFiles: () => void;
    setConfig: (config: Partial<ScanConfig>) => void;
    setCategoryConfig: (key: string, value: boolean) => void;
    updateProgress: (progress: Partial<ScanProgress>) => void;
    setResult: (result: ScanResult | null) => void;
    setError: (error: string | null) => void;
    startPasteScan: (code: string, filename: string, language: string) => Promise<void>;
    startUploadScan: (files: File[]) => Promise<void>;
    startGitHubScan: (repoFullName: string, branch: string) => Promise<void>;
    pollScanStatus: (scanId: string) => Promise<void>;
    cancelScan: () => Promise<void>;
    fetchResult: (scanId: string) => Promise<void>;
    cleanup: () => void;
    // Enrichment actions
    fetchReport: (scanId: string) => Promise<void>;
    fetchExploitGraph: (scanId: string) => Promise<void>;
    fetchEnrichment: (scanId: string, vulnId: string) => Promise<{ remediationFix: RemediationFix | null; developerExplanation: DeveloperExplanation | null }>;
}

const defaultConfig: ScanConfig = {
    depth: 'standard',
    categories: { backend: true, frontend: true, api: true, config: true, dependencies: true },
    aiReasoning: true,
    exploitExamples: true,
    secureRewrite: true,
};

const defaultProgress: ScanProgress = {
    phase: 'idle',
    percent: 0,
    currentFile: '',
    chunksProcessed: 0,
    totalChunks: 0,
    estimatedTimeRemaining: 0,
    liveVulnCount: 0,
};

function errorMessage(err: unknown): string {
    if (err && typeof err === 'object' && 'message' in err) {
        return String((err as { message: unknown }).message);
    }
    return 'Something went wrong. Please try again.';
}

/** Maps a backend vulnerability record to the frontend's richer display shape. */
function mapVulnerability(v: VulnerabilityData): Vulnerability {
    const snippet = v.code_snippet as Record<string, unknown> | null;
    const code = snippet && typeof snippet.content === 'string' ? snippet.content : '';
    return {
        id: v.id,
        name: v.vulnerability_type || 'Unknown Vulnerability',
        type: v.vulnerability_type || '',
        severity: (v.severity as SeverityLevel) || 'info',
        file: v.file_name || '',
        line: v.line_reference,
        confidence: Math.round(v.confidence || 0),
        status: (v.status as VulnStatus) || 'open',
        impact: v.impact || '',
        exploitExample: v.exploit_example || '',
        securePatch: v.remediation || '',
        codeSnippet: code,
        fixedCode: '',
        owaspRef: v.owasp_mapping || '',
        cweRef: '',
        category: v.category || '',
        ruleId: '',
        detectionId: v.id,
        exploitChainName: '',
        chainRiskMultiplier: 1,
        attackSurfaceType: '',
        detectionLayer: 1,
        vulnerabilityFamily: v.category || '',
        exploitabilityScore: '',
        adjustedConfidence: null,
        intelligenceModifiers: [],
        correlationFlags: [],
        evidenceCount: 0,
        clusteredRuleIds: [],
        mergedRuleIds: [],
    };
}

/** Polls /scan/status/:id until the scan reaches a terminal phase. */
function pollScanLoop(scanId: string, set: (s: Partial<ScanState>) => void, get: () => ScanState) {
    const controller = new AbortController();
    set({ _pollAbort: controller });

    const tick = async () => {
        if (controller.signal.aborted) return;
        try {
            const status = await scanApi.getStatus(scanId);
            const phase = (status.phase || status.status) as ScanPhase;
            set({
                progress: {
                    phase,
                    percent: status.progress_percent,
                    currentFile: status.current_file,
                    chunksProcessed: status.chunks_processed,
                    totalChunks: status.total_chunks,
                    estimatedTimeRemaining: status.estimated_time_remaining,
                    liveVulnCount: status.live_vuln_count,
                },
            });

            if (controller.signal.aborted) return;

            if (phase === 'complete') {
                await get().fetchResult(scanId);
                return;
            }
            if (phase === 'failed' || phase === 'cancelled') {
                if (phase === 'failed') set({ error: 'Scan failed. Please try again.' });
                return;
            }
            setTimeout(tick, 1500);
        } catch (err) {
            if (!controller.signal.aborted) {
                set({ error: errorMessage(err), progress: { ...get().progress, phase: 'failed' } });
            }
        }
    };
    tick();
}

export const useScanStore = create<ScanState>((set, get) => ({
    files: [],
    config: defaultConfig,
    progress: defaultProgress,
    result: null,
    activeScanId: null,
    error: null,
    _pollAbort: null,
    reportData: null,
    enrichmentCache: {},
    exploitGraph: null,
    loadingReport: false,
    loadingGraph: false,

    addFile: (file) => set((s) => ({ files: [...s.files, file] })),
    removeFile: (id) => set((s) => ({ files: s.files.filter((f) => f.id !== id) })),
    clearFiles: () => set({ files: [] }),
    setConfig: (cfg) => set((s) => ({ config: { ...s.config, ...cfg } })),
    setCategoryConfig: (key, value) =>
        set((s) => ({
            config: { ...s.config, categories: { ...s.config.categories, [key]: value } },
        })),
    updateProgress: (p) => set((s) => ({ progress: { ...s.progress, ...p } })),
    setResult: (result) => set({ result }),
    setError: (error) => set({ error }),

    startPasteScan: async (code, filename, language) => {
        set({ progress: { ...defaultProgress, phase: 'uploading' }, error: null, result: null, activeScanId: null });
        try {
            const { config } = get();
            const { scan_id } = await scanApi.start({
                source_type: 'paste',
                repo_name: filename || 'pasted-code',
                config: {
                    depth: config.depth,
                    categories: config.categories,
                    ai_reasoning: config.aiReasoning,
                    exploit_examples: config.exploitExamples,
                    secure_rewrite: config.secureRewrite,
                },
                code_paste: { code, language, filename },
            });
            set({ activeScanId: scan_id, progress: { ...defaultProgress, phase: 'queued' } });
            pollScanLoop(scan_id, set, get);
        } catch (err) {
            set({ error: errorMessage(err), progress: { ...defaultProgress, phase: 'failed' } });
        }
    },

    startUploadScan: async (files) => {
        set({ progress: { ...defaultProgress, phase: 'uploading' }, error: null, result: null, activeScanId: null });
        try {
            const { config } = get();
            const { scan_id } = await scanApi.upload(files, {
                depth: config.depth,
                categories: config.categories,
                ai_reasoning: config.aiReasoning,
                exploit_examples: config.exploitExamples,
                secure_rewrite: config.secureRewrite,
            });
            set({ activeScanId: scan_id, progress: { ...defaultProgress, phase: 'queued' } });
            pollScanLoop(scan_id, set, get);
        } catch (err) {
            set({ error: errorMessage(err), progress: { ...defaultProgress, phase: 'failed' } });
        }
    },

    startGitHubScan: async (repoFullName, branch) => {
        set({ progress: { ...defaultProgress, phase: 'uploading' }, error: null, result: null, activeScanId: null });
        try {
            const { config } = get();
            const { scan_id } = await scanApi.start({
                source_type: 'github',
                repo_name: repoFullName,
                branch,
                config: {
                    depth: config.depth,
                    categories: config.categories,
                    ai_reasoning: config.aiReasoning,
                    exploit_examples: config.exploitExamples,
                    secure_rewrite: config.secureRewrite,
                },
                github_repo: { repo_full_name: repoFullName, branch },
            });
            set({ activeScanId: scan_id, progress: { ...defaultProgress, phase: 'queued' } });
            pollScanLoop(scan_id, set, get);
        } catch (err) {
            set({ error: errorMessage(err), progress: { ...defaultProgress, phase: 'failed' } });
        }
    },

    pollScanStatus: async (scanId) => {
        pollScanLoop(scanId, set, get);
    },

    cancelScan: async () => {
        const { activeScanId, _pollAbort } = get();
        _pollAbort?.abort();
        if (activeScanId) {
            try {
                await scanApi.cancel(activeScanId);
            } catch {
                // Best-effort cancel — still reflect cancellation locally
            }
        }
        set({ progress: { ...defaultProgress, phase: 'cancelled' }, activeScanId: null, _pollAbort: null });
    },

    fetchResult: async (scanId) => {
        try {
            const data = await scanApi.getResult(scanId);
            set({
                activeScanId: scanId,
                result: {
                    id: data.id,
                    timestamp: data.created_at,
                    totalFiles: data.total_files,
                    totalVulnerabilities: data.total_vulnerabilities,
                    critical: data.critical_count,
                    high: data.high_count,
                    medium: data.medium_count,
                    low: data.low_count,
                    info: data.info_count,
                    securityScore: data.security_score,
                    grade: data.grade,
                    confidenceScore: data.confidence_score,
                    duration: data.duration,
                    repoName: data.repo_name,
                    vulnerabilities: data.vulnerabilities.map(mapVulnerability),
                },
                progress: { ...defaultProgress, phase: 'complete', percent: 100 },
            });
        } catch (err) {
            set({
                error: errorMessage(err),
                progress: { ...get().progress, phase: 'failed' },
            });
        }
    },

    cleanup: () => {
        get()._pollAbort?.abort();
        set({ _pollAbort: null });
    },

    fetchReport: async (scanId) => {
        set({ loadingReport: true });
        try {
            const data = await scanApi.getReport(scanId);
            set({
                reportData: {
                    securityScore: data.security_score,
                    confidenceScore: data.confidence_score,
                    grade: data.grade,
                    totalFiles: data.total_files,
                    totalFindings: data.total_findings,
                    severityCounts: data.severity_counts,
                    owaspDistribution: data.owasp_distribution,
                    cweDistribution: data.cwe_distribution,
                    categoryDistribution: data.category_distribution,
                    fileRiskRanking: data.file_risk_ranking.map((f) => ({
                        file: String(f.file),
                        riskScore: Number(f.risk_score),
                        vulnCount: Number(f.vuln_count),
                        criticalCount: f.critical_count !== undefined ? Number(f.critical_count) : undefined,
                        highCount: f.high_count !== undefined ? Number(f.high_count) : undefined,
                    })),
                    executiveSummary: data.executive_summary,
                    postureSummary: data.posture_summary,
                },
                loadingReport: false,
            });
        } catch {
            set({ reportData: null, loadingReport: false });
        }
    },

    fetchExploitGraph: async (scanId) => {
        set({ loadingGraph: true });
        try {
            const data = await scanApi.getExploitGraph(scanId);
            const graph: ExploitGraph = {
                nodes: data.nodes.map((n) => ({
                    id: n.id, type: n.type as ExploitGraph['nodes'][number]['type'], label: n.label, file: n.file, line: n.line,
                    severity: n.severity as SeverityLevel, exposureLevel: n.exposure_level as ExploitGraph['nodes'][number]['exposureLevel'],
                })),
                edges: data.edges.map((e) => ({ source: e.source, target: e.target, type: e.type as ExploitGraph['edges'][number]['type'], label: e.label, weight: e.weight })),
                paths: data.paths.map((p) => ({
                    pathId: p.path_id, nodes: p.nodes, totalRisk: p.total_risk,
                    exposureLevel: p.exposure_level as ExploitGraph['paths'][number]['exposureLevel'], description: p.description,
                })),
                totalNodes: data.total_nodes,
                totalEdges: data.total_edges,
                maxExposureLevel: data.max_exposure_level as ExploitGraph['maxExposureLevel'],
            };
            set({ exploitGraph: graph, loadingGraph: false });
        } catch {
            // No exploit-graph data available for this scan
            set({ exploitGraph: null, loadingGraph: false });
        }
    },

    fetchEnrichment: async (scanId, vulnId) => {
        const cached = get().enrichmentCache[vulnId];
        if (cached) return cached;
        try {
            const data = await scanApi.getEnrichment(scanId, vulnId);
            const result = {
                remediationFix: data.remediation_fix ? {
                    vulnerableCode: data.remediation_fix.vulnerable_code,
                    secureFix: data.remediation_fix.secure_fix,
                    fixExplanation: data.remediation_fix.fix_explanation,
                    securityPrinciple: data.remediation_fix.security_principle,
                    bestPractice: data.remediation_fix.best_practice,
                    confidence: data.remediation_fix.confidence,
                } as RemediationFix : null,
                developerExplanation: data.developer_explanation ? {
                    ruleId: data.developer_explanation.rule_id,
                    vulnerabilityType: data.developer_explanation.vulnerability_type,
                    severity: data.developer_explanation.severity,
                    whyDangerous: data.developer_explanation.why_this_is_dangerous,
                    realWorldExploit: data.developer_explanation.real_world_exploit,
                    attackerScenario: data.developer_explanation.attacker_abuse_scenario,
                    secureFix: data.developer_explanation.secure_fix,
                    secureCodeExample: data.developer_explanation.secure_code_example,
                    commonMistakes: data.developer_explanation.common_mistakes,
                    references: data.developer_explanation.references,
                    severityGuidance: data.developer_explanation.severity_guidance,
                    detectionLayerInfo: data.developer_explanation.detection_layer_info,
                } as DeveloperExplanation : null,
            };
            set((s) => ({ enrichmentCache: { ...s.enrichmentCache, [vulnId]: result } }));
            return result;
        } catch {
            // Enrichment not available for this vulnerability
            const empty = { remediationFix: null, developerExplanation: null };
            return empty;
        }
    },
}));
