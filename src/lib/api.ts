/** Frontend → Backend API Client */

import { parseApiError, parseNetworkError, type AppError } from './errors';

// ── Single source of truth for API URLs ────────────────────────
const API_BASE = process.env.NEXT_PUBLIC_API_URL || '/api/v1';
export const AUTH_BASE = API_BASE.replace('/api/v1', '') || '';

const REQUEST_TIMEOUT_MS = 30_000; // 30 seconds

class ApiClient {
    private baseUrl: string;

    constructor(baseUrl: string) {
        this.baseUrl = baseUrl;
    }

    private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            ...(options.headers as Record<string, string> || {}),
        };

        // Remove Content-Type for FormData
        if (options.body instanceof FormData) {
            delete headers['Content-Type'];
        }

        // Add request timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        try {
            const res = await fetch(url, {
                ...options,
                headers,
                credentials: 'include', // Send HTTP-only cookies
                signal: controller.signal,
            });

            if (!res.ok) {
                const appError: AppError = await parseApiError(res);
                throw appError;
            }

            if (res.status === 204) return {} as T;
            return res.json();
        } catch (err) {
            // If already an AppError (from parseApiError), re-throw
            if (err && typeof err === 'object' && 'code' in err && 'isAuthError' in err) {
                throw err;
            }
            // Network / timeout error
            throw parseNetworkError(err);
        } finally {
            clearTimeout(timeoutId);
        }
    }

    // ── Auth ────────────────────────────────────────────────
    async loginGoogle(idToken: string) {
        return this.request<{ access_token: string; refresh_token: string }>('/auth/google', {
            method: 'POST',
            body: JSON.stringify({ token: idToken }),
        });
    }

    async loginGitHub(code: string) {
        return this.request<{ access_token: string; refresh_token: string }>('/auth/github', {
            method: 'POST',
            body: JSON.stringify({ code }),
        });
    }

    async getMe() {
        return this.request<{
            id: string;
            email: string;
            name: string;
            provider: string;
            avatar_url: string | null;
            created_at: string;
        }>('/auth/me');
    }

    async logout() {
        return this.request<{ message: string }>('/auth/logout', { method: 'POST' });
    }

    async refreshToken(refreshToken: string) {
        return this.request<{ access_token: string; refresh_token: string }>(
            '/auth/refresh',
            { method: 'POST', body: JSON.stringify({ refresh_token: refreshToken }) }
        );
    }

    async updateProfile(data: { name: string }) {
        return this.request<{
            id: string; email: string; name: string;
            provider: string; avatar_url: string | null; created_at: string;
        }>('/auth/user/update', {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async getUserStats() {
        return this.request<{ total_scans: number; created_at: string | null }>('/auth/user/stats');
    }

    // ── Repos ───────────────────────────────────────────────
    async listRepos() {
        return this.request<{
            repos: Array<{
                id: number;
                name: string;
                full_name: string;
                language: string | null;
                stargazers_count: number;
                updated_at: string;
                private: boolean;
                default_branch: string;
            }>;
        }>('/repos');
    }

    // ── Scan ────────────────────────────────────────────────
    async startScan(payload: {
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
    }) {
        return this.request<{ scan_id: string; status: string; message: string }>('/scan/start', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
    }

    async uploadScan(files: File[], config: Record<string, unknown> = {}) {
        const formData = new FormData();
        files.forEach((file) => formData.append('files', file));
        formData.append('config', JSON.stringify(config));
        return this.request<{ scan_id: string; status: string; files_ingested: number }>('/scan/upload', {
            method: 'POST',
            body: formData,
        });
    }

    async getScanStatus(scanId: string) {
        return this.request<{
            id: string;
            status: string;
            progress_percent: number;
            current_file: string;
            chunks_processed: number;
            total_chunks: number;
            estimated_time_remaining: number;
            live_vuln_count: number;
        }>(`/scan/status/${scanId}`);
    }

    async getScanResult(scanId: string) {
        return this.request<{
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
            vulnerabilities: Array<{
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
            }>;
        }>(`/scan/result/${scanId}`);
    }

    async getScanHistory() {
        return this.request<Array<{
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
        }>>('/scan/history');
    }

    async deleteScan(scanId: string) {
        return this.request<{ message: string }>(`/scan/delete/${scanId}`, { method: 'DELETE' });
    }

    async cancelScan(scanId: string) {
        return this.request<{ message: string }>(`/scan/cancel/${scanId}`, { method: 'POST' });
    }
}

export const api = new ApiClient(API_BASE);
