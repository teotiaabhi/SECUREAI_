/**
 * Auth API — Login, logout, token refresh, user profile.
 */

import { apiGet, apiPost, apiPut, AUTH_BASE } from './apiClient';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  provider: string;
  avatar_url: string | null;
  created_at: string;
  role?: string;
  tier?: string;
  status?: string;
  github_connected?: boolean;
}

export interface UserStats {
  total_scans: number;
  created_at: string | null;
}

// OAuth redirect URLs (browser navigates here, not API calls)
export const GOOGLE_LOGIN_URL = `${AUTH_BASE}/auth/google`;
export const GITHUB_LOGIN_URL = `${AUTH_BASE}/auth/github`;

export const authApi = {
  /** Get current authenticated user. */
  getMe: () => apiGet<AuthUser>('/auth/me'),

  /** Logout — revoke tokens server-side. */
  logout: () => apiPost<{ message: string }>('/auth/logout'),

  /** Refresh access token. */
  refreshToken: (refreshToken: string) =>
    apiPost<{ access_token: string; refresh_token: string }>(
      '/auth/refresh',
      { refresh_token: refreshToken }
    ),

  /** Update user profile. */
  updateProfile: (data: { name: string }) =>
    apiPut<AuthUser>('/auth/user/update', data),

  /** Get user stats. */
  getStats: () => apiGet<UserStats>('/auth/user/stats'),
};
