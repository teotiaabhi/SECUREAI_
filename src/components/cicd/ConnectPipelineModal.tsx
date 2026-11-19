'use client';

import React, { useState } from 'react';
import { type Pipeline } from '@/api/cicd';
import { useAuthStore, type GitHubRepo } from '@/store/authStore';
import { GitBranch, X, Github, Loader2 } from 'lucide-react';

interface ConnectPipelineModalProps {
    isOpen: boolean;
    onClose: () => void;
    onCreated: (pipeline: Pipeline) => void;
}

export function ConnectPipelineModal({ isOpen, onClose, onCreated }: ConnectPipelineModalProps) {
    const { repos, fetchRepos } = useAuthStore();
    const [selected, setSelected] = useState<GitHubRepo | null>(null);
    const [autoScanPush, setAutoScanPush] = useState(true);
    const [autoScanPr, setAutoScanPr] = useState(true);
    const [prComment, setPrComment] = useState(true);
    const [creating, setCreating] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [reposLoaded, setReposLoaded] = useState(false);

    if (!isOpen) return null;

    const loadRepos = async () => {
        if (reposLoaded) return;
        await fetchRepos();
        setReposLoaded(true);
    };

    // Load repos on mount
    if (!reposLoaded && repos.length === 0) {
        loadRepos();
    }

    const handleCreate = async () => {
        if (!selected) return;
        setCreating(true);
        setError(null);
        try {
            await new Promise((r) => setTimeout(r, 600));
            const pipeline: Pipeline = {
                id: 'pipe-' + Date.now(),
                repo_full_name: selected.full_name,
                default_branch: selected.default_branch,
                auto_scan_on_push: autoScanPush,
                auto_scan_on_pr: autoScanPr,
                pr_comment_enabled: prComment,
                min_severity: 'medium',
                webhook_secret_set: false,
                created_at: new Date().toISOString(),
            };
            onCreated(pipeline);
        } catch (err: unknown) {
            setError((err as Record<string, string>)?.message || 'Failed to create pipeline');
        } finally {
            setCreating(false);
        }
    };

    return (
        <div
            style={{
                position: 'fixed', inset: 0, zIndex: 100,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'rgba(0,0,0,0.4)',
            }}
            onClick={onClose}
        >
            <div
                className="card"
                style={{ maxWidth: 520, width: '90%', padding: 28 }}
                onClick={(e) => e.stopPropagation()}
            >
                <div className="flex items-center justify-between" style={{ marginBottom: 20 }}>
                    <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <GitBranch style={{ width: 20, height: 20 }} /> Connect Repository
                    </h3>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-tertiary)' }}>
                        <X style={{ width: 18, height: 18 }} />
                    </button>
                </div>

                {/* Repo selector */}
                <div style={{ marginBottom: 16 }}>
                    <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6, display: 'block' }}>
                        Repository
                    </label>
                    <div style={{
                        maxHeight: 200, overflow: 'auto',
                        border: '1.5px solid var(--border-primary)', borderRadius: 'var(--radius-md)',
                    }}>
                        {repos.length === 0 ? (
                            <div style={{ padding: 20, textAlign: 'center', fontSize: 12, color: 'var(--text-tertiary)' }}>
                                <Loader2 style={{ width: 16, height: 16, animation: 'spin 0.6s linear infinite', margin: '0 auto 8px' }} />
                                Loading repositories...
                            </div>
                        ) : (
                            repos.map((repo) => (
                                <div
                                    key={repo.id}
                                    onClick={() => setSelected(repo)}
                                    style={{
                                        padding: '10px 14px', cursor: 'pointer',
                                        display: 'flex', alignItems: 'center', gap: 10,
                                        background: selected?.id === repo.id ? 'var(--brand-primary-light)' : undefined,
                                        borderBottom: '1px solid var(--border-light)',
                                        transition: 'background 0.1s ease',
                                    }}
                                >
                                    <Github style={{ width: 14, height: 14, color: 'var(--text-tertiary)', flexShrink: 0 }} />
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{repo.full_name}</p>
                                        <p style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
                                            {repo.language || 'Unknown'} · {repo.default_branch} · {repo.private ? 'Private' : 'Public'}
                                        </p>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Options */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
                    {[
                        { label: 'Auto-scan on push', checked: autoScanPush, onChange: setAutoScanPush },
                        { label: 'Auto-scan on PR', checked: autoScanPr, onChange: setAutoScanPr },
                        { label: 'PR comment with results', checked: prComment, onChange: setPrComment },
                    ].map((opt) => (
                        <label key={opt.label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer', color: 'var(--text-secondary)' }}>
                            <input
                                type="checkbox"
                                checked={opt.checked}
                                onChange={() => opt.onChange(!opt.checked)}
                                style={{ accentColor: '#F5C842' }}
                            />
                            {opt.label}
                        </label>
                    ))}
                </div>

                {error && (
                    <p style={{ fontSize: 12, color: 'var(--severity-critical)', marginBottom: 12 }}>{error}</p>
                )}

                <div className="flex items-center gap-3 justify-end">
                    <button onClick={onClose} className="btn btn-secondary" style={{ fontSize: 13, padding: '8px 16px' }}>
                        Cancel
                    </button>
                    <button
                        onClick={handleCreate}
                        disabled={!selected || creating}
                        className="btn btn-primary"
                        style={{ fontSize: 13, padding: '8px 16px', opacity: selected && !creating ? 1 : 0.5 }}
                    >
                        {creating ? 'Creating...' : 'Connect Pipeline'}
                    </button>
                </div>
            </div>
        </div>
    );
}
