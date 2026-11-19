/**
 * Security Intelligence Types — comprehensive TypeScript models
 * covering all backend engine outputs: exploit chains, attack graphs,
 * dataflow taint analysis, remediation fixes, developer explanations,
 * clustering metadata, and confidence calibration.
 */

// ── Severity & Status ───────────────────────────────────────

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type VulnStatus = 'open' | 'fixed' | 'ignored';
export type ExposureLevel = 1 | 2 | 3 | 4;

// ── Remediation Fix (from remediation_engine.py) ────────────

export interface RemediationFix {
  vulnerableCode: string;
  secureFix: string;
  fixExplanation: string;
  securityPrinciple: string;
  bestPractice: string;
  confidence: number;
}

// ── Developer Explanation (from developer_learning.py) ──────

export interface DeveloperExplanation {
  ruleId: string;
  vulnerabilityType: string;
  severity: string;
  whyDangerous: string;
  realWorldExploit: string;
  attackerScenario: string;
  secureFix: string;
  secureCodeExample: string;
  commonMistakes: string[];
  references: string[];
  severityGuidance: string;
  detectionLayerInfo: string;
}

// ── Exploit Chain ───────────────────────────────────────────

export interface ExploitChainLeg {
  stepNumber: number;
  findingId: string;
  vulnerabilityType: string;
  file: string;
  line: number;
  severity: SeverityLevel;
  description: string;
}

export interface ExploitChain {
  chainName: string;
  description: string;
  severity: SeverityLevel;
  legs: ExploitChainLeg[];
  riskMultiplier: number;
  exposureLevel: ExposureLevel;
}

// ── Attack Graph (from exploit_graph.py) ────────────────────

export type AttackNodeType =
  | 'vulnerability'
  | 'source'
  | 'sink'
  | 'privileged_op'
  | 'data_store'
  | 'credential'
  | 'auth_boundary';

export type AttackEdgeType =
  | 'dataflow'
  | 'privilege_transition'
  | 'file_access'
  | 'network_access'
  | 'exploit_enables';

export interface AttackGraphNode {
  id: string;
  type: AttackNodeType;
  label: string;
  file: string;
  line: number;
  severity: SeverityLevel;
  exposureLevel: ExposureLevel;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  type: AttackEdgeType;
  label: string;
  weight: number;
}

export interface AttackPath {
  pathId: string;
  nodes: string[];
  totalRisk: number;
  exposureLevel: ExposureLevel;
  description: string;
}

export interface ExploitGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  paths: AttackPath[];
  totalNodes: number;
  totalEdges: number;
  maxExposureLevel: ExposureLevel;
}

// ── Dataflow / Taint Analysis ───────────────────────────────

export interface TaintSource {
  file: string;
  line: number;
  variable: string;
  sourceType: string;
}

export interface TaintSink {
  file: string;
  line: number;
  sinkType: string;
  dangerLevel: string;
}

export interface TaintPropagation {
  file: string;
  line: number;
  operation: string;
}

export interface TaintChain {
  chainId: string;
  source: TaintSource;
  sink: TaintSink;
  propagation: TaintPropagation[];
  confidence: number;
  isSanitized: boolean;
}

// ── Confidence Calibration ──────────────────────────────────

export interface ConfidenceCalibration {
  rawConfidence: number;
  adjustedConfidence: number;
  intelligenceModifiers: string[];
  correlationFlags: string[];
}

// ── Clustering Metadata ─────────────────────────────────────

export interface ClusteringInfo {
  evidenceCount: number;
  clusteredRuleIds: string[];
  mergedRuleIds: string[];
  vulnerabilityFamily: string;
}

// ── Enhanced Vulnerability ──────────────────────────────────

export interface EnrichedVulnerability {
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
  // Enrichment data
  remediationFix: RemediationFix | null;
  developerExplanation: DeveloperExplanation | null;
  exploitChainName: string;
  confidenceCalibration: ConfidenceCalibration | null;
  clustering: ClusteringInfo | null;
  chainRiskMultiplier: number;
  attackSurfaceType: string;
  detectionLayer: number;
  vulnerabilityFamily: string;
  exploitabilityScore: string;
}

// ── Scan Report Analytics ───────────────────────────────────

export interface FileRiskEntry {
  file: string;
  riskScore: number;
  vulnCount: number;
  criticalCount: number;
  highCount: number;
}

export interface ScanReportData {
  securityScore: number;
  confidenceScore: number;
  grade: string;
  totalFiles: number;
  totalFindings: number;
  severityCounts: Record<string, number>;
  owaspDistribution: Record<string, number>;
  cweDistribution: Record<string, number>;
  categoryDistribution: Record<string, number>;
  fileRiskRanking: FileRiskEntry[];
  executiveSummary: string;
  postureSummary: string;
}

// ── Enhanced Scan Result ────────────────────────────────────

export interface EnrichedScanResult {
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
  vulnerabilities: EnrichedVulnerability[];
  duration: number;
  repoName: string;
  // Report analytics (lazy-loaded)
  report: ScanReportData | null;
  // Exploit chains (derived)
  exploitChains: ExploitChain[];
  // Attack graph (lazy-loaded)
  exploitGraph: ExploitGraph | null;
}

// ── Severity Helpers ────────────────────────────────────────

export const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_COLORS: Record<SeverityLevel, {
  text: string; bg: string; border: string; gutter: string;
}> = {
  critical: {
    text: 'var(--severity-critical)',
    bg: 'var(--severity-critical-bg)',
    border: 'var(--severity-critical)',
    gutter: 'rgba(220, 38, 38, 0.15)',
  },
  high: {
    text: 'var(--severity-high)',
    bg: 'var(--severity-high-bg)',
    border: 'var(--severity-high)',
    gutter: 'rgba(234, 88, 12, 0.15)',
  },
  medium: {
    text: 'var(--severity-medium)',
    bg: 'var(--severity-medium-bg)',
    border: 'var(--severity-medium)',
    gutter: 'rgba(217, 119, 6, 0.15)',
  },
  low: {
    text: 'var(--severity-low)',
    bg: 'var(--severity-low-bg)',
    border: 'var(--severity-low)',
    gutter: 'rgba(37, 99, 235, 0.15)',
  },
  info: {
    text: 'var(--severity-info)',
    bg: 'var(--severity-info-bg)',
    border: 'var(--severity-info)',
    gutter: 'rgba(124, 58, 237, 0.15)',
  },
};

export const EXPOSURE_LABELS: Record<ExposureLevel, string> = {
  1: 'Basic',
  2: 'Elevated',
  3: 'Serious',
  4: 'System Compromise',
};

export const ATTACK_NODE_COLORS: Record<AttackNodeType, string> = {
  vulnerability: '#DC2626',
  source: '#2563EB',
  sink: '#EA580C',
  privileged_op: '#7C3AED',
  data_store: '#059669',
  credential: '#D97706',
  auth_boundary: '#DB2777',
};

export const ATTACK_EDGE_COLORS: Record<AttackEdgeType, string> = {
  dataflow: '#2563EB',
  privilege_transition: '#7C3AED',
  file_access: '#059669',
  network_access: '#D97706',
  exploit_enables: '#DC2626',
};
