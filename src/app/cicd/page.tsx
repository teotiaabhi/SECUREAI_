'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { PipelineList } from '@/components/cicd/PipelineList';
import { PipelineDetail } from '@/components/cicd/PipelineDetail';
import { ConnectPipelineModal } from '@/components/cicd/ConnectPipelineModal';
import type { Pipeline } from '@/api/cicd';
import { GitBranch, Plus, AlertCircle } from 'lucide-react';

const MOCK_PIPELINES: Pipeline[] = [
    { id: 'pipe-001', repo_full_name: 'demo/my-web-app', default_branch: 'main', auto_scan_on_push: true, auto_scan_on_pr: true, pr_comment_enabled: true, min_severity: 'medium', webhook_secret_set: true, created_at: '2024-08-01T00:00:00Z' },
    { id: 'pipe-002', repo_full_name: 'demo/api-server', default_branch: 'main', auto_scan_on_push: true, auto_scan_on_pr: false, pr_comment_enabled: false, min_severity: 'high', webhook_secret_set: false, created_at: '2024-07-15T00:00:00Z' },
];

export default function CicdPage() {
    return (
        <AuthGuard>
            <CicdContent />
        </AuthGuard>
    );
}

function CicdContent() {
    const [pipelines, setPipelines] = useState<Pipeline[]>(MOCK_PIPELINES);
    const [loading] = useState(false);
    const [error] = useState<string | null>(null);
    const [selectedPipeline, setSelectedPipeline] = useState<Pipeline | null>(null);
    const [showConnect, setShowConnect] = useState(false);

    const handleDelete = async (id: string) => {
        setPipelines((prev) => prev.filter((p) => p.id !== id));
        if (selectedPipeline?.id === id) setSelectedPipeline(null);
    };

    const handleCreated = (pipeline: Pipeline) => {
        setPipelines((prev) => [pipeline, ...prev]);
        setShowConnect(false);
        setSelectedPipeline(pipeline);
    };

    return (
        <AppShell>
            <div style={{ maxWidth: 1100, margin: '0 auto' }}>
                {/* Header */}
                <div className="flex items-center justify-between animate-fade-in" style={{ marginBottom: 24 }}>
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                <GitBranch style={{ width: 14, height: 14 }} /> CI/CD
                            </div>
                        </div>
                        <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                            CI/CD Pipelines
                        </h1>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                            Connect repositories, configure webhooks, and track security trends.
                        </p>
                    </div>
                    <button onClick={() => setShowConnect(true)} className="btn btn-primary" style={{ fontSize: 13, padding: '8px 16px' }}>
                        <Plus style={{ width: 16, height: 16 }} /> Connect Repo
                    </button>
                </div>

                {/* Error */}
                {error && (
                    <div style={{
                        marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10,
                        padding: '12px 16px', borderRadius: 'var(--radius-md)',
                        background: 'var(--severity-critical-bg)', border: '1px solid var(--severity-critical)',
                    }}>
                        <AlertCircle style={{ width: 16, height: 16, color: 'var(--severity-critical)', flexShrink: 0 }} />
                        <p style={{ fontSize: 13, color: 'var(--severity-critical)' }}>{error}</p>
                    </div>
                )}

                {selectedPipeline ? (
                    <PipelineDetail
                        pipeline={selectedPipeline}
                        onBack={() => setSelectedPipeline(null)}
                        onDelete={handleDelete}
                    />
                ) : (
                    <PipelineList
                        pipelines={pipelines}
                        loading={loading}
                        onSelect={setSelectedPipeline}
                        onDelete={handleDelete}
                    />
                )}
            </div>

            <ConnectPipelineModal
                isOpen={showConnect}
                onClose={() => setShowConnect(false)}
                onCreated={handleCreated}
            />
        </AppShell>
    );
}
