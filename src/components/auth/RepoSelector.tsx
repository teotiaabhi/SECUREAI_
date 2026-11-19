'use client';

import React from 'react';
import { useAuthStore } from '@/store/authStore';
import { Modal } from '@/components/ui/Modal';
import { Search, GitBranch, Star, Lock, Globe } from 'lucide-react';

interface RepoSelectorProps {
    isOpen: boolean;
    onClose: () => void;
    onSelect: (repoName: string) => void;
}

export function RepoSelector({ isOpen, onClose, onSelect }: RepoSelectorProps) {
    const { repos, fetchRepos, isLoading } = useAuthStore();
    const [search, setSearch] = React.useState('');

    React.useEffect(() => {
        if (isOpen && repos.length === 0) fetchRepos();
    }, [isOpen, repos.length, fetchRepos]);

    const filtered = repos.filter((r) =>
        r.name.toLowerCase().includes(search.toLowerCase()) ||
        r.language?.toLowerCase().includes(search.toLowerCase())
    );

    const langColors: Record<string, string> = {
        TypeScript: '#3178c6', Python: '#3572A5', Java: '#b07219', JavaScript: '#f1e05a',
        Go: '#00ADD8', HCL: '#844FBA', Kotlin: '#A97BFF', Rust: '#dea584',
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Select Repository" maxWidth={520}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Search */}
                <div style={{ position: 'relative' }}>
                    <Search style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', width: 16, height: 16, color: 'var(--text-tertiary)' }} />
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search repositories..."
                        className="input"
                        style={{ paddingLeft: 36 }}
                    />
                </div>

                {/* Repo List */}
                <div style={{ maxHeight: 400, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {isLoading ? (
                        Array.from({ length: 4 }).map((_, i) => (
                            <div key={i} className="skeleton" style={{ height: 64, borderRadius: 'var(--radius-md)' }} />
                        ))
                    ) : filtered.length === 0 ? (
                        <p style={{ fontSize: 13, color: 'var(--text-tertiary)', textAlign: 'center', padding: '32px 0' }}>No repositories found.</p>
                    ) : (
                        filtered.map((repo) => (
                            <button
                                key={repo.id}
                                onClick={() => { onSelect(repo.full_name); onClose(); }}
                                style={{
                                    width: '100%',
                                    display: 'flex', alignItems: 'center', gap: 12,
                                    padding: 12,
                                    borderRadius: 'var(--radius-md)',
                                    border: '1.5px solid var(--border-light)',
                                    background: 'var(--bg-primary)',
                                    cursor: 'pointer',
                                    textAlign: 'left',
                                    transition: 'all 0.15s ease',
                                }}
                                onMouseEnter={(e) => {
                                    e.currentTarget.style.borderColor = 'var(--border-primary)';
                                    e.currentTarget.style.background = 'var(--bg-hover)';
                                }}
                                onMouseLeave={(e) => {
                                    e.currentTarget.style.borderColor = 'var(--border-light)';
                                    e.currentTarget.style.background = 'var(--bg-primary)';
                                }}
                            >
                                <div
                                    style={{
                                        width: 40, height: 40,
                                        borderRadius: 'var(--radius-md)',
                                        background: 'var(--bg-tertiary)',
                                        border: '1px solid var(--border-light)',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        flexShrink: 0,
                                    }}
                                >
                                    <GitBranch style={{ width: 18, height: 18, color: 'var(--text-tertiary)' }} />
                                </div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div className="flex items-center gap-2">
                                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{repo.name}</span>
                                        {repo.private ? <Lock style={{ width: 12, height: 12, color: 'var(--text-tertiary)' }} /> : <Globe style={{ width: 12, height: 12, color: 'var(--text-tertiary)' }} />}
                                    </div>
                                    <div className="flex items-center gap-3" style={{ marginTop: 2 }}>
                                        {repo.language && (
                                            <span className="flex items-center gap-1" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                                                <span style={{ width: 8, height: 8, borderRadius: '50%', background: langColors[repo.language] || '#888', display: 'inline-block' }} />
                                                {repo.language}
                                            </span>
                                        )}
                                        <span className="flex items-center gap-1" style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
                                            <Star style={{ width: 12, height: 12 }} /> {repo.stargazers_count}
                                        </span>
                                        <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{repo.default_branch}</span>
                                    </div>
                                </div>
                            </button>
                        ))
                    )}
                </div>
            </div>
        </Modal>
    );
}
