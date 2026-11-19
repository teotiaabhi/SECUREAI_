/**
 * API module index — re-exports all API modules.
 */

export { apiRequest, apiGet, apiPost, apiPut, apiDelete, onApiEvent, isValidUUID, requireValidUUID, AUTH_BASE } from './apiClient';
export { authApi, GOOGLE_LOGIN_URL, GITHUB_LOGIN_URL } from './auth';
export type { AuthUser, UserStats } from './auth';
export { scanApi } from './scans';
export { cicdApi } from './cicd';
export { usageApi } from './usage';
export { complianceApi } from './compliance';
export { metricsApi } from './metrics';
