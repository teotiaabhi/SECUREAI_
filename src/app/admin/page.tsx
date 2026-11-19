'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import type { SystemHealth } from '@/api/metrics';
import type { UsageSummary } from '@/api/usage';
import {
    Activity, Server, Database, Cpu, HardDrive, Users,
    CheckCircle, AlertTriangle, XCircle, RefreshCw,
} from 'lucide-react';

const MOCK_HEALTH: SystemHealth = {
    liveness: { status: 'healthy' },
    readiness: { status: 'healthy', checks: { database: true, redis: true, ai_engine: true } },
    deep: { status: 'healthy', timings: { database_ms: 2.3, redis_ms: 0.8, ai_inference_ms: 45.2 } },
};

const MOCK_USAGE: UsageSummary = {
    user_id: 'demo-user-001',
    tier: 'pro',
    period_start: new Date(Date.now() - 30 * 86400000).toISOString(),
    period_end: new Date().toISOString(),
    scans_used: 12,
    scans_limit: 100,
    ai_tokens_used: 48200,
    ai_tokens_limit: 500000,
    storage_used_bytes: 25165824,
    storage_limit_bytes: 1073741824,
};

export default function AdminPage() {
    return (
        <AuthGuard requiredRole="admin">
            <AdminContent />
        </AuthGuard>
    );
}

function HealthBadge({ status }: { status: string }) {
    if (status === 'healthy' || status === 'ok') {
        return <CheckCircle style={{ width: 16, height: 16, color: '#16A34A' }} />;
    }
    if (status === 'degraded') {
        return <AlertTriangle style={{ width: 16, height: 16, color: '#F59E0B' }} />;
    }
    return <XCircle style={{ width: 16, height: 16, color: '#DC2626' }} />;
}

function AdminContent() {
    const [health] = useState<SystemHealth | null>(MOCK_HEALTH);
    const [usage] = useState<UsageSummary | null>(MOCK_USAGE);
    const [loading] = useState(false);
    const [error] = useState<string | null>(null);

    const formatUptime = (seconds: number) => {
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return `${d}d ${h}h ${m}m`;
    };

    return (
        <AppShell>
            <div style={{ maxWidth: 1100, margin: '0 auto' }}>
                {/* Header */}
                <div className="flex items-center justify-between animate-fade-in" style={{ marginBottom: 24 }}>
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                <Server style={{ width: 14, height: 14 }} /> Admin
                            </div>
                        </div>
                        <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                            System Administration
                        </h1>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                            System health, metrics, and platform overview.
                        </p>
                    </div>
                    <button onClick={() => {}} className="btn btn-secondary" style={{ fontSize: 13, padding: '8px 16px' }}>
                        <RefreshCw style={{ width: 14, height: 14 }} /> Refresh
                    </button>
                </div>

                {error && (
                    <div style={{
                        marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10,
                        padding: '12px 16px', borderRadius: 'var(--radius-md)',
                        background: 'var(--severity-critical-bg)', border: '1px solid var(--severity-critical)',
                    }}>
                        <AlertTriangle style={{ width: 16, height: 16, color: 'var(--severity-critical)' }} />
                        <p style={{ fontSize: 13, color: 'var(--severity-critical)' }}>{error}</p>
                    </div>
                )}

                {loading ? null : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        {/* System Health Cards */}
                        {health && (
                            <>
                                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                                    <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                                        <div className="flex items-center justify-center gap-2" style={{ marginBottom: 8 }}>
                                            <Activity style={{ width: 18, height: 18, color: 'var(--text-tertiary)' }} />
                                            <HealthBadge status={health.liveness.status} />
                                        </div>
                                        <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Liveness</p>
                                        <p style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginTop: 4, textTransform: 'capitalize' }}>
                                            {health.liveness.status}
                                        </p>
                                    </div>

                                    <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                                        <div className="flex items-center justify-center gap-2" style={{ marginBottom: 8 }}>
                                            <Database style={{ width: 18, height: 18, color: 'var(--text-tertiary)' }} />
                                            <HealthBadge status={health.readiness.status} />
                                        </div>
                                        <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Readiness</p>
                                        <p style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginTop: 4, textTransform: 'capitalize' }}>
                                            {health.readiness.status}
                                        </p>
                                    </div>

                                    {health.deep && (
                                        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                                            <div className="flex items-center justify-center gap-2" style={{ marginBottom: 8 }}>
                                                <Cpu style={{ width: 18, height: 18, color: 'var(--text-tertiary)' }} />
                                                <HealthBadge status={health.deep.status} />
                                            </div>
                                            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Deep Check</p>
                                            <p style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginTop: 4, textTransform: 'capitalize' }}>
                                                {health.deep.status}
                                            </p>
                                        </div>
                                    )}
                                </div>

                                {/* Readiness checks detail */}
                                {health.readiness.checks && (
                                    <div className="card" style={{ padding: 20 }}>
                                        <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>Readiness Checks</h3>
                                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                            {Object.entries(health.readiness.checks).map(([name, ok]) => (
                                                <div key={name} className="flex items-center gap-2">
                                                    {ok ? <CheckCircle style={{ width: 14, height: 14, color: '#16A34A' }} /> : <XCircle style={{ width: 14, height: 14, color: '#DC2626' }} />}
                                                    <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                                                        {name.replace(/_/g, ' ')}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Timing details */}
                                {health.deep?.timings && (
                                    <div className="card" style={{ padding: 20 }}>
                                        <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>Response Timings</h3>
                                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                            {Object.entries(health.deep.timings).map(([name, ms]) => (
                                                <div key={name}>
                                                    <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>{name.replace(/_/g, ' ')}</p>
                                                    <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginTop: 2, fontFamily: 'monospace' }}>{ms.toFixed(1)}ms</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </>
                        )}

                        {/* Usage Overview */}
                        {usage && (
                            <div className="card" style={{ padding: 20 }}>
                                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <Users style={{ width: 14, height: 14 }} /> Usage Overview
                                </h3>
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                    <div>
                                        <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Scans Used</p>
                                        <p style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>
                                            {usage.scans_used} / {usage.scans_limit}
                                        </p>
                                    </div>
                                    <div>
                                        <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>AI Tokens Used</p>
                                        <p style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>
                                            {usage.ai_tokens_used.toLocaleString()} / {usage.ai_tokens_limit.toLocaleString()}
                                        </p>
                                    </div>
                                    <div>
                                        <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Tier</p>
                                        <p style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2, textTransform: 'capitalize' }}>
                                            {usage.tier}
                                        </p>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </AppShell>
    );
}
