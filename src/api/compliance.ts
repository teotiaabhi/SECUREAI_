/**
 * Compliance API — SOC2 status, audit log, GDPR, audit chain verification.
 */

import { apiGet, apiPost } from './apiClient';

// ── Types ───────────────────────────────────────────────────

export interface ComplianceControl {
  status: 'compliant' | 'partial' | 'non_compliant' | 'unknown';
  detail: string;
  verified_entries?: number;
}

export interface ComplianceStatus {
  overall_status: 'compliant' | 'partial' | 'non_compliant';
  controls: Record<string, ComplianceControl>;
  recommendations: string[];
  evaluated_at: string;
}

export interface AuditLogEntry {
  id: string;
  event_type: string;
  event_category: string;
  user_id: string | null;
  detail: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string | null;
  integrity_hash: string | null;
}

export interface AuditLogResponse {
  count: number;
  offset: number;
  entries: AuditLogEntry[];
}

export interface AuditVerifyResult {
  valid: boolean;
  verified_count: number;
  total_checked: number;
  broken_at: string | null;
  message: string;
}

export interface GdprDeleteResult {
  status: string;
  message: string;
  summary: Record<string, number>;
}

export interface GdprExportResult {
  export_date: string;
  user_id: string;
  profile: Record<string, unknown>;
  scans: Array<Record<string, unknown>>;
  audit_logs: Array<Record<string, unknown>>;
}

// ── API ─────────────────────────────────────────────────────

export const complianceApi = {
  /** SOC2 readiness report. */
  getStatus: () => apiGet<ComplianceStatus>('/compliance/status'),

  /** Query audit log with filters. */
  getAuditLog: (params: {
    start?: string;
    end?: string;
    event_type?: string;
    category?: string;
    limit?: number;
    offset?: number;
  } = {}) => {
    const q = new URLSearchParams();
    if (params.start) q.set('start', params.start);
    if (params.end) q.set('end', params.end);
    if (params.event_type) q.set('event_type', params.event_type);
    if (params.category) q.set('category', params.category);
    if (params.limit !== undefined) q.set('limit', String(params.limit));
    if (params.offset !== undefined) q.set('offset', String(params.offset));
    return apiGet<AuditLogResponse>(`/compliance/audit-log?${q.toString()}`);
  },

  /** Verify audit hash-chain integrity. */
  verifyAuditChain: (limit = 1000) =>
    apiPost<AuditVerifyResult>(`/compliance/audit-verify?limit=${limit}`),

  /** GDPR: Delete all user data (right-to-be-forgotten). */
  gdprDelete: () =>
    apiPost<GdprDeleteResult>('/compliance/gdpr/delete-my-data'),

  /** GDPR: Export all user data (data portability). */
  gdprExport: () =>
    apiGet<GdprExportResult>('/compliance/gdpr/export-my-data'),
};
