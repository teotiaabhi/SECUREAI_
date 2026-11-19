/**
 * Scan API — Start, status, results, history, cancel, delete.
 */

import { apiGet, apiPost, apiDelete, apiRequest, requireValidUUID } from './apiClient';

// ── Request types ───────────────────────────────────────────

export interface ScanStartPayload {
  source_type: 'paste' | 'upload' | 'github';
  repo_name: string;
  config: {
    depth: string;
    categories: Record<string, boolean>;
    ai_reasoning: boolean;
    exploit_examples: boolean;
    secure_rewrite: boolean;
  };
  code_paste?: { code: string; language: string; filename: string };
  github_repo?: { repo_full_name: string; branch: string };
  branch?: string;
  scan_mode?: 'full' | 'diff';
}

// ── Response types ──────────────────────────────────────────

export interface ScanStartResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface ScanStatusResponse {
  id: string;
  status: string;
  phase: string;
  progress_percent: number;
  current_file: string;
  chunks_processed: number;
  total_chunks: number;
  estimated_time_remaining: number;
  live_vuln_count: number;
}

export interface VulnerabilityData {
  id: string;
  file_name: string;
  vulnerability_type: string;
  severity: string;
  confidence: number;
  line_reference: number | null;
  impact: string | null;
  remediation: string | null;
  exploit_example: string | null;
  owasp_mapping: string | null;
  category: string | null;
  status: string;
  code_snippet: Record<string, unknown> | null;
}

export interface ScanResultResponse {
  id: string;
  repo_name: string;
  status: string;
  total_files: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  security_score: number;
  confidence_score: number;
  grade: string;
  duration: number;
  created_at: string;
  vulnerabilities: VulnerabilityData[];
}

export interface ScanHistoryItem {
  id: string;
  repo_name: string;
  status: string;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  security_score: number;
  grade: string;
  duration: number;
  created_at: string;
}

export interface ScanReportResponse {
  security_score: number;
  confidence_score: number;
  grade: string;
  total_files: number;
  total_findings: number;
  severity_counts: Record<string, number>;
  owasp_distribution: Record<string, number>;
  cwe_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
  file_risk_ranking: Array<{ file: string; risk_score: number; vuln_count: number; critical_count?: number; high_count?: number }>;
  executive_summary: string;
  posture_summary: string;
}

export interface RemediationFixData {
  vulnerable_code: string;
  secure_fix: string;
  fix_explanation: string;
  security_principle: string;
  best_practice: string;
  confidence: number;
}

export interface DeveloperExplanationData {
  rule_id: string;
  vulnerability_type: string;
  severity: string;
  why_this_is_dangerous: string;
  real_world_exploit: string;
  attacker_abuse_scenario: string;
  secure_fix: string;
  secure_code_example: string;
  common_mistakes: string[];
  references: string[];
  severity_guidance: string;
  detection_layer_info: string;
}

export interface EnrichmentData {
  remediation_fix: RemediationFixData | null;
  developer_explanation: DeveloperExplanationData | null;
  exploit_chain_name: string;
  adjusted_confidence: number | null;
  intelligence_modifiers: string[];
  correlation_flags: string[];
  evidence_count: number;
  clustered_rule_ids: string[];
  merged_rule_ids: string[];
  vulnerability_family: string;
  chain_risk_multiplier: number;
  attack_surface_type: string;
  detection_layer: number;
  exploitability_score: string;
  cwe: string;
  rule_id: string;
  detection_id: string;
}

export interface ExploitGraphNode {
  id: string;
  type: string;
  label: string;
  file: string;
  line: number;
  severity: string;
  exposure_level: number;
}

export interface ExploitGraphEdge {
  source: string;
  target: string;
  type: string;
  label: string;
  weight: number;
}

export interface ExploitGraphPath {
  path_id: string;
  nodes: string[];
  total_risk: number;
  exposure_level: number;
  description: string;
}

export interface ExploitGraphResponse {
  nodes: ExploitGraphNode[];
  edges: ExploitGraphEdge[];
  paths: ExploitGraphPath[];
  total_nodes: number;
  total_edges: number;
  max_exposure_level: number;
}

export interface CostEstimate {
  estimated_tokens: number;
  estimated_cost_usd: number;
  tokens_remaining: number;
  allowed: boolean;
  tier: string;
}

export interface FileViewerVulnerability {
  id: string;
  severity: string;
  confidence: number;
  type: string;
  detection_id: string;
  impact: string;
  remediation: string;
  owasp_mapping: string;
  category: string;
}

export interface FileViewerResponse {
  file_name: string;
  content: string;
  highlight_line: number;
  context_start: number;
  context_end: number;
  total_lines: number;
  vulnerability: FileViewerVulnerability;
}

// ── API ─────────────────────────────────────────────────────

export const scanApi = {
  /** Start a new scan. */
  start: (payload: ScanStartPayload) =>
    apiPost<ScanStartResponse>('/scan/start', payload),

  /** Upload files for scanning. */
  upload: (files: File[], config: Record<string, unknown> = {}) => {
    const formData = new FormData();
    files.forEach((f) => formData.append('files', f));
    formData.append('config', JSON.stringify(config));
    return apiRequest<{ scan_id: string; status: string; files_ingested: number }>(
      '/scan/upload', { method: 'POST', body: formData }
    );
  },

  /** Get scan status (for polling). Uses shorter timeout to fail fast. */
  getStatus: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiGet<ScanStatusResponse>(`/scan/status/${scanId}`, { timeout: 10_000 });
  },

  /** Get scan result. */
  getResult: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiGet<ScanResultResponse>(`/scan/result/${scanId}`);
  },

  /** Get structured report. */
  getReport: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiGet<ScanReportResponse>(`/scan/report/${scanId}`);
  },

  /** Get scan history. */
  getHistory: () => apiGet<ScanHistoryItem[]>('/scan/history'),

  /** Delete a scan. */
  delete: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiDelete<{ message: string }>(`/scan/delete/${scanId}`);
  },

  /** Cancel a running scan. */
  cancel: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiPost<{ message: string }>(`/scan/cancel/${scanId}`);
  },

  /** Compare two scans. */
  compare: (scanIdA: string, scanIdB: string) => {
    requireValidUUID(scanIdA, 'scan ID A');
    requireValidUUID(scanIdB, 'scan ID B');
    return apiGet<Record<string, unknown>>(`/scan/compare/${scanIdA}/${scanIdB}`);
  },

  /** Get file content for vulnerability code viewer. */
  getFileContent: (scanId: string, fileName: string, detectionId?: string) => {
    requireValidUUID(scanId, 'scan ID');
    const params = new URLSearchParams({ file_name: fileName });
    if (detectionId) params.set('detection_id', detectionId);
    return apiGet<FileViewerResponse>(`/scans/${scanId}/file?${params.toString()}`);
  },

  /** Get enrichment data for a vulnerability (remediation fix, developer explanation, etc). */
  getEnrichment: (scanId: string, vulnId: string) => {
    requireValidUUID(scanId, 'scan ID');
    requireValidUUID(vulnId, 'vulnerability ID');
    return apiGet<EnrichmentData>(`/scan/${scanId}/enrichment/${vulnId}`);
  },

  /** Get exploit graph for a scan. */
  getExploitGraph: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiGet<ExploitGraphResponse>(`/scan/${scanId}/exploit-graph`);
  },

  /** Get developer learning explanation for a vulnerability. */
  getLearning: (scanId: string, vulnId: string) => {
    requireValidUUID(scanId, 'scan ID');
    requireValidUUID(vulnId, 'vulnerability ID');
    return apiGet<DeveloperExplanationData>(`/scan/${scanId}/learning/${vulnId}`);
  },

  /** Get remediation fix for a vulnerability. */
  getRemediationFix: (scanId: string, vulnId: string) => {
    requireValidUUID(scanId, 'scan ID');
    requireValidUUID(vulnId, 'vulnerability ID');
    return apiGet<RemediationFixData>(`/scan/${scanId}/remediation/${vulnId}`);
  },
};
