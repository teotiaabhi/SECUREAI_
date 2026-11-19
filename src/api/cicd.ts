/**
 * CI/CD API — Pipeline management, baselines, delta reports, webhooks.
 */

import { apiGet, apiPost, apiDelete, requireValidUUID } from './apiClient';

// ── Types ───────────────────────────────────────────────────

export interface Pipeline {
  id: string;
  repo_full_name: string;
  default_branch: string;
  auto_scan_on_push: boolean;
  auto_scan_on_pr: boolean;
  pr_comment_enabled: boolean;
  min_severity: string;
  webhook_secret_set: boolean;
  created_at: string;
}

export interface CreatePipelinePayload {
  repo_full_name: string;
  default_branch?: string;
  auto_scan_on_push?: boolean;
  auto_scan_on_pr?: boolean;
  pr_comment_enabled?: boolean;
  min_severity?: string;
}

export interface BaselineSummary {
  repo_full_name: string;
  commit_sha: string;
  total_findings: number;
  severity_counts: Record<string, number>;
  created_at: string;
}

export interface DeltaReport {
  scan_id: string;
  new_findings: number;
  fixed_findings: number;
  unchanged_findings: number;
  regression_detected: boolean;
  risk_score_change: number;
  new_vulnerabilities: Array<{
    id: string;
    vulnerability_type: string;
    severity: string;
    file_name: string;
    line_reference: number | null;
  }>;
  fixed_vulnerabilities: Array<{
    id: string;
    vulnerability_type: string;
    severity: string;
    file_name: string;
  }>;
}

export interface TimelineEntry {
  scan_id: string;
  commit_sha: string;
  risk_score: number;
  total_findings: number;
  new_findings: number;
  fixed_findings: number;
  created_at: string;
}

export interface WebhookConnectResponse {
  webhook_url: string;
  webhook_secret: string;
  instructions: string;
}

// ── API ─────────────────────────────────────────────────────

export const cicdApi = {
  /** List all pipelines. */
  listPipelines: () =>
    apiGet<{ pipelines: Pipeline[] }>('/cicd/pipelines'),

  /** Create a new pipeline. */
  createPipeline: (payload: CreatePipelinePayload) =>
    apiPost<Pipeline>('/cicd/pipelines', payload),

  /** Delete a pipeline. */
  deletePipeline: (pipelineId: string) => {
    requireValidUUID(pipelineId, 'pipeline ID');
    return apiDelete<{ message: string }>(`/cicd/pipelines/${pipelineId}`);
  },

  /** Connect pipeline with webhook (get secret). */
  connectWebhook: (pipelineId: string) => {
    requireValidUUID(pipelineId, 'pipeline ID');
    return apiPost<WebhookConnectResponse>(`/cicd/pipelines/${pipelineId}/connect`);
  },

  /** Get baseline for a repository. */
  getBaseline: (repoFullName: string) =>
    apiGet<BaselineSummary>(`/cicd/baselines/${encodeURIComponent(repoFullName)}`),

  /** Get risk score timeline for a repository. */
  getTimeline: (repoFullName: string) =>
    apiGet<{ timeline: TimelineEntry[] }>(`/cicd/timeline/${encodeURIComponent(repoFullName)}`),

  /** Get delta report for a scan. */
  getDelta: (scanId: string) => {
    requireValidUUID(scanId, 'scan ID');
    return apiGet<DeltaReport>(`/cicd/delta/${scanId}`);
  },
};
