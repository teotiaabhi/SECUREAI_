'use client';

import React from 'react';
import type { Pipeline } from '@/api/cicd';
import { GitBranch, Webhook, Trash2, ChevronRight, Clock } from 'lucide-react';

interface PipelineListProps {
    pipelines: Pipeline[];
    loading: boolean;
    onSelect: (pipeline: Pipeline) => void;
    onDelete: (id: string) => void;
}

export function PipelineList({ pipelines, loading, onSelect, onDelete }: PipelineListProps) {
    if (loading) {
        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {[1, 2, 3].map((i) => (
                    <div key={i} className="card" style={{ padding: 20, height: 80, opacity: 0.3 }}>
                        <div style={{ width: 200, height: 14, background: 'var(--bg-tertiary)', borderRadius: 4 }} />
                    </div>
                ))}
            </div>
        );
    }

    if (pipelines.length === 0) {
        return (
            <div className="card" style={{ padding: 60, textAlign: 'center' }}>
                <div style={{
                    width: 56, height: 56, borderRadius: 'var(--radius-lg)',
                    background: 'var(--bg-tertiary)', border: '1.5px solid var(--border-light)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    margin: '0 auto 16px',
                }}>
                    <GitBranch style={{ width: 28, height: 28, color: 'var(--text-tertiary)' }} />
                </div>
                <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
                    No Pipelines Connected
                </h3>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 360, margin: '0 auto' }}>
                    Connect a GitHub repository to enable automated security scanning on push and pull requests.
                </p>
            </div>
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {pipelines.map((p) => (
                <div
                    key={p.id}
                    className="card"
                    style={{
                        padding: '16px 20px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 16,
                        cursor: 'pointer',
                        transition: 'border-color 0.15s ease',
                    }}
                    onClick={() => onSelect(p)}
                >
                    <div style={{
                        width: 40, height: 40, borderRadius: 'var(--radius-md)',
                        background: 'var(--brand-primary-light)',
                        border: '1.5px solid var(--border-primary)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        flexShrink: 0,
                    }}>
                        <GitBranch style={{ width: 20, height: 20 }} />
                    </div>

                    <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="flex items-center gap-2">
                            <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                                {p.repo_full_name}
                            </span>
                            <span className="pill" style={{ fontSize: 10, padding: '2px 8px' }}>
                                {p.default_branch}
                            </span>
                        </div>
                        <div className="flex items-center gap-3" style={{ marginTop: 4, fontSize: 11, color: 'var(--text-tertiary)' }}>
                            {p.auto_scan_on_push && <span>Push scan</span>}
                            {p.auto_scan_on_pr && <span>PR scan</span>}
                            {p.pr_comment_enabled && <span>PR comments</span>}
                            <span className="flex items-center gap-1">
                                <Webhook style={{ width: 10, height: 10 }} />
                                {p.webhook_secret_set ? 'Connected' : 'Not connected'}
                            </span>
                            <span className="flex items-center gap-1">
                                <Clock style={{ width: 10, height: 10 }} />
                                {new Date(p.created_at).toLocaleDateString('en-US')}
                            </span>
                        </div>
                    </div>

                    <button
                        onClick={(e) => { e.stopPropagation(); onDelete(p.id); }}
                        style={{
                            background: 'none', border: 'none', cursor: 'pointer',
                            color: 'var(--text-tertiary)', padding: 4,
                        }}
                        title="Delete pipeline"
                    >
                        <Trash2 style={{ width: 14, height: 14 }} />
                    </button>

                    <ChevronRight style={{ width: 16, height: 16, color: 'var(--text-tertiary)', flexShrink: 0 }} />
                </div>
            ))}
        </div>
    );
}
