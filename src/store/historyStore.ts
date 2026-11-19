import { create } from 'zustand';
import { scanApi } from '@/api/scans';

interface HistoryItem {
    id: string;
    repoName: string;
    status: string;
    totalVulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    securityScore: number;
    grade: string;
    duration: number;
    timestamp: string;
}

interface HistoryState {
    scans: HistoryItem[];
    isLoading: boolean;
    error: string | null;
    fetchHistory: () => Promise<void>;
    removeScan: (id: string) => Promise<void>;
    clearError: () => void;
}

export const useHistoryStore = create<HistoryState>((set) => ({
    scans: [],
    isLoading: false,
    error: null,

    fetchHistory: async () => {
        set({ isLoading: true, error: null });
        try {
            const items = await scanApi.getHistory();
            set({
                scans: items.map((s) => ({
                    id: s.id,
                    repoName: s.repo_name,
                    status: s.status,
                    totalVulnerabilities: s.total_vulnerabilities,
                    critical: s.critical_count,
                    high: s.high_count,
                    medium: s.medium_count,
                    low: s.low_count,
                    securityScore: s.security_score,
                    grade: s.grade,
                    duration: s.duration,
                    timestamp: s.created_at,
                })),
                isLoading: false,
            });
        } catch (err) {
            const message = err && typeof err === 'object' && 'message' in err ? String((err as { message: unknown }).message) : 'Failed to load scan history';
            set({ error: message, isLoading: false });
        }
    },

    removeScan: async (id) => {
        const prev = useHistoryStore.getState().scans;
        set((s) => ({ scans: s.scans.filter((scan) => scan.id !== id) }));
        try {
            await scanApi.delete(id);
        } catch {
            // Roll back on failure
            set({ scans: prev });
        }
    },

    clearError: () => set({ error: null }),
}));
