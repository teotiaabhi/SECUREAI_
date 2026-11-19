/**
 * Usage API — Metering, cost estimation, tier info.
 */

import { apiGet } from './apiClient';

export interface UsageSummary {
  user_id: string;
  tier: string;
  period_start: string;
  period_end: string;
  scans_used: number;
  scans_limit: number;
  ai_tokens_used: number;
  ai_tokens_limit: number;
  storage_used_bytes: number;
  storage_limit_bytes: number;
}

export interface UsageQuota {
  daily_scan_limit: number;
  scans_used: number;
  scans_remaining: number;
  token_limit: number;
  tokens_used: number;
  tokens_remaining: number;
}

export interface CostEstimate {
  estimated_tokens: number;
  estimated_cost_usd: number;
  tokens_remaining: number;
  allowed: boolean;
  tier: string;
  scan_mode: string;
}

export interface TierPlan {
  name: string;
  display_name: string;
  scans_per_day: number;
  max_repo_size_mb: number;
  max_files: number;
  ai_tokens_per_day: number;
  storage_cap_bytes: number;
  storage_cap_display: string;
}

export interface TiersResponse {
  tiers: TierPlan[];
}

export const usageApi = {
  /** Get daily quota status (scans + tokens used/remaining). */
  getQuota: () => apiGet<UsageQuota>('/usage'),

  /** Get current period usage. */
  getCurrent: () => apiGet<UsageSummary>('/usage/current'),

  /** Get cost estimate before scan. */
  getCostEstimate: (params: {
    file_count?: number;
    total_size_bytes?: number;
    scan_mode?: string;
  }) => {
    const q = new URLSearchParams();
    if (params.file_count !== undefined) q.set('file_count', String(params.file_count));
    if (params.total_size_bytes !== undefined) q.set('total_size_bytes', String(params.total_size_bytes));
    if (params.scan_mode) q.set('scan_mode', params.scan_mode);
    return apiGet<CostEstimate>(`/usage/cost-estimate?${q.toString()}`);
  },

  /** Get all tier plan configurations (public, no auth). */
  getTiers: () => apiGet<TiersResponse>('/usage/tiers'),
};
