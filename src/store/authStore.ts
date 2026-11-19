import { create } from 'zustand';
import { authApi } from '@/api/auth';
import { apiGet } from '@/api/apiClient';

export type UserRole = 'user' | 'admin' | 'auditor';

export interface AuthUser {
    id: string;
    email: string;
    name: string;
    provider: string;
    avatar_url: string | null;
    created_at: string;
    role: UserRole;
    tier: string;
    status: string;
    githubConnected: boolean;
}

export interface GitHubRepo {
    id: number;
    name: string;
    full_name: string;
    language: string | null;
    stargazers_count: number;
    updated_at: string;
    private: boolean;
    default_branch: string;
}

interface AuthState {
    isAuthenticated: boolean;
    user: AuthUser | null;
    repos: GitHubRepo[];
    selectedRepo: GitHubRepo | null;
    isLoading: boolean;
    authChecked: boolean;
    error: string | null;
    checkAuth: () => Promise<void>;
    updateUser: (data: { name: string }) => Promise<void>;
    logout: () => Promise<void>;
    setSelectedRepo: (repo: GitHubRepo | null) => void;
    fetchRepos: () => Promise<void>;
    clearError: () => void;
    // RBAC helpers
    hasRole: (role: UserRole | UserRole[]) => boolean;
    isAdmin: () => boolean;
    isAuditor: () => boolean;
    canManageUsers: () => boolean;
    canCreateScans: () => boolean;
    canDeleteScans: () => boolean;
    canReadAudit: () => boolean;
    canReadCompliance: () => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
    isAuthenticated: false,
    user: null,
    repos: [],
    selectedRepo: null,
    isLoading: false,
    authChecked: false,
    error: null,

    checkAuth: async () => {
        set({ isLoading: true });
        try {
            const me = await authApi.getMe();
            set({
                isAuthenticated: true,
                user: {
                    id: me.id,
                    email: me.email,
                    name: me.name,
                    provider: me.provider,
                    avatar_url: me.avatar_url,
                    created_at: me.created_at,
                    role: (me.role as UserRole) || 'user',
                    tier: me.tier || 'free',
                    status: me.status || 'active',
                    githubConnected: Boolean(me.github_connected),
                },
                isLoading: false,
                authChecked: true,
            });
        } catch {
            set({ isAuthenticated: false, user: null, isLoading: false, authChecked: true });
        }
    },

    updateUser: async (data: { name: string }) => {
        const updated = await authApi.updateProfile(data);
        const current = get().user;
        if (current) set({ user: { ...current, name: updated.name } });
    },

    logout: async () => {
        try {
            await authApi.logout();
        } catch {
            // Clear local state even if the server call fails
        }
        set({ isAuthenticated: false, user: null, repos: [], selectedRepo: null, authChecked: true });
    },

    setSelectedRepo: (repo) => set({ selectedRepo: repo }),

    fetchRepos: async () => {
        try {
            const { repos } = await apiGet<{ repos: GitHubRepo[] }>('/repos');
            set({ repos });
        } catch {
            set({ repos: [] });
        }
    },

    clearError: () => set({ error: null }),

    hasRole: (role) => {
        const userRole = get().user?.role || 'user';
        if (Array.isArray(role)) return role.includes(userRole);
        return userRole === role;
    },

    isAdmin: () => get().user?.role === 'admin',
    isAuditor: () => get().user?.role === 'auditor',
    canManageUsers: () => get().user?.role === 'admin',
    canCreateScans: () => get().isAuthenticated,
    canDeleteScans: () => get().isAuthenticated,
    canReadAudit: () => get().user?.role === 'admin',
    canReadCompliance: () => get().user?.role === 'admin' || get().user?.role === 'auditor',
}));
