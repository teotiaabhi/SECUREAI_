/**
 * Metrics API — Internal admin/monitoring (read-only).
 */

import { apiGet, AUTH_BASE } from './apiClient';

export interface HealthStatus {
  status: string;
  checks?: Record<string, boolean>;
  timings?: Record<string, number>;
}

export interface SystemHealth {
  liveness: HealthStatus;
  readiness: HealthStatus;
  deep: HealthStatus | null;
}

export const metricsApi = {
  /** Liveness probe. */
  healthLive: () =>
    fetch(`${AUTH_BASE}/health`, { credentials: 'include' })
      .then((r) => r.json() as Promise<HealthStatus>),

  /** Readiness probe. */
  healthReady: () =>
    fetch(`${AUTH_BASE}/health/ready`, { credentials: 'include' })
      .then((r) => r.json() as Promise<HealthStatus>),

  /** Deep health check. */
  healthDeep: () =>
    fetch(`${AUTH_BASE}/health/deep`, { credentials: 'include' })
      .then((r) => r.json() as Promise<HealthStatus>),

  /** Prometheus metrics (text exposition format). */
  getPrometheusMetrics: () =>
    fetch(`${AUTH_BASE}/metrics`, { credentials: 'include' })
      .then((r) => r.text()),

  /** Aggregate system health. */
  getSystemHealth: async (): Promise<SystemHealth> => {
    const [liveness, readiness] = await Promise.all([
      metricsApi.healthLive().catch(() => ({ status: 'unreachable' })),
      metricsApi.healthReady().catch(() => ({ status: 'unreachable' })),
    ]);
    let deep: HealthStatus | null = null;
    try { deep = await metricsApi.healthDeep(); } catch { /* optional */ }
    return { liveness, readiness, deep };
  },
};
