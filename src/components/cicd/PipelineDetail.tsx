'use client';

import React, { useEffect, useState } from 'react';
import type { Pipeline, BaselineSummary, DeltaReport, TimelineEntry } from '@/api/cicd';
import { ArrowLeft, GitBranch, Webhook, Shield, TrendingUp, TrendingDown, AlertTriangle, CheckCircle, Minus, Copy, Eye, EyeOff } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface PipelineDetailProps {
    pipeline: Pipeline;
    onBack: () => void;
    onDelete: (id: string) => void;
}

export function PipelineDetail({ pipeline, onBack, onDelete }: PipelineDetailProps) {
    const [baseline, setBaseline] = useState<BaselineSummary | null>(null);
    const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
    const [delta, setDelta] = useState<DeltaReport | null>(null);
    const [webhookInfo, setWebhookInfo] = useState<{ webhook_url: string; webhook_secret: string; instructions: string } | null>(null);
    const [secretVisible, setSecretVisible] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        setBaseline({
            repo_full_name: pipeline.repo_full_name,
            commit_sha: 'abc1234',
            total_findings: 7,
            severity_counts: { critical: 1, high: 2, medium: 3, low: 1 },
            created_at: new Date(Date.now() - 7 * 86400000).toISOString(),
        });
        setTimeline([
            { scan_id: 'scan-t1', commit_sha: 'abc1234', risk_score: 78, total_findings: 7, new_findings: 2, fixed_findings: 3, created_at: new Date(Date.now() - 86400000).toISOString() },
            { scan_id: 'scan-t2', commit_sha: 'bcd2345', risk_score: 65, total_findings: 9, new_findings: 4, fixed_findings: 1, created_at: new Date(Date.now() - 3 * 86400000).toISOString() },
            { scan_id: 'scan-t3', commit_sha: 'cde3456', risk_score: 58, total_findings: 12, new_findings: 5, fixed_findings: 0, created_at: new Date(Date.now() - 7 * 86400000).toISOString() },
        ]);
        setLoading(false);
    }, [pipeline.repo_full_name]);

    useEffect(() => {
        if (timeline.length > 0) {
            setDelta({ scan_id: timeline[0].scan_id, new_findings: 2, fixed_findings: 3, unchanged_findings: 5, regression_detected: false, risk_score_change: -8.5, new_vulnerabilities: [], fixed_vulnerabilities: [] });
        }
    }, [timeline]);

    const handleConnectWebhook = async () => {
        setWebhookInfo({ webhook_url: 'https://secureai.dev/api/v1/webhooks/github', webhook_secret: 'demo-secret-key-123456', instructions: 'Add this URL and secret to your GitHub repo webhook settings (Settings → Webhooks → Add webhook).' });
    };

    const timelineData = timeline.map((t) => ({
        date: new Date(t.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        score: t.risk_score,
        findings: t.total_findings,
        newFindings: t.new_findings,
        fixed: t.fixed_findings,
    })).reverse();

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Back + Header */}
            <div className="flex items-center gap-3">
                <button onClick={onBack} className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: 12 }}>
                    <ArrowLeft style={{ width: 14, height: 14 }} /> Back
                </button>
                <div style={{ flex: 1 }}>
                    <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>{pipeline.repo_full_name}</h2>
                    <p style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                        Branch: {pipeline.default_branch} · Min severity: {pipeline.min_severity}
                    </p>
                </div>
                <button
                    onClick={() => onDelete(pipeline.id)}
                    className="btn btn-secondary"
                    style={{ padding: '6px 12px', fontSize: 12, color: 'var(--severity-critical)' }}
                >
                    Delete Pipeline
                </button>
            </div>

            {/* Delta Report / Regression Banner */}
            {delta && delta.regression_detected && (
                <div style={{
                    padding: '14px 20px', borderRadius: 'var(--radius-md)',
                    background: 'var(--severity-critical-bg)', border: '1.5px solid var(--severity-critical)',
                    display: 'flex', alignItems: 'center', gap: 12,
                }}>
                    <AlertTriangle style={{ width: 20, height: 20, color: 'var(--severity-critical)', flexShrink: 0 }} />
                    <div>
                        <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--severity-critical)' }}>Security Regression Detected</p>
                        <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                            {delta.new_findings} new finding{delta.new_findings !== 1 ? 's' : ''} introduced.
                            Risk score changed by {delta.risk_score_change > 0 ? '+' : ''}{delta.risk_score_change}.
                        </p>
                    </div>
                </div>
            )}

            {/* Stats Row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                {/* Baseline */}
                <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                    <Shield style={{ width: 20, height: 20, color: 'var(--text-tertiary)', margin: '0 auto 8px' }} />
                    <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Baseline</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginTop: 4 }}>
                        {baseline?.total_findings ?? '--'}
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>findings</p>
                </div>

                {/* New Findings */}
                <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                    <TrendingUp style={{ width: 20, height: 20, color: '#DC2626', margin: '0 auto 8px' }} />
                    <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>New</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: delta && delta.new_findings > 0 ? '#DC2626' : 'var(--text-primary)', marginTop: 4 }}>
                        {delta?.new_findings ?? '--'}
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>introduced</p>
                </div>

                {/* Fixed */}
                <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                    <TrendingDown style={{ width: 20, height: 20, color: '#16A34A', margin: '0 auto 8px' }} />
                    <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Fixed</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: delta && delta.fixed_findings > 0 ? '#16A34A' : 'var(--text-primary)', marginTop: 4 }}>
                        {delta?.fixed_findings ?? '--'}
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>resolved</p>
                </div>

                {/* Risk Change */}
                <div className="card" style={{ padding: 16, textAlign: 'center' }}>
                    {delta && delta.risk_score_change !== 0 ? (
                        delta.risk_score_change > 0 ? (
                            <TrendingUp style={{ width: 20, height: 20, color: '#DC2626', margin: '0 auto 8px' }} />
                        ) : (
                            <TrendingDown style={{ width: 20, height: 20, color: '#16A34A', margin: '0 auto 8px' }} />
                        )
                    ) : (
                        <Minus style={{ width: 20, height: 20, color: 'var(--text-tertiary)', margin: '0 auto 8px' }} />
                    )}
                    <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Risk</p>
                    <p style={{
                        fontSize: 20, fontWeight: 800, marginTop: 4,
                        color: delta ? (delta.risk_score_change > 0 ? '#DC2626' : delta.risk_score_change < 0 ? '#16A34A' : 'var(--text-primary)') : 'var(--text-primary)',
                    }}>
                        {delta ? (delta.risk_score_change > 0 ? `+${delta.risk_score_change}` : String(delta.risk_score_change)) : '--'}
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>change</p>
                </div>
            </div>

            {/* Risk Timeline Chart */}
            {timelineData.length > 1 && (
                <div className="card" style={{ padding: 20 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <GitBranch style={{ width: 14, height: 14 }} /> Risk Score Timeline
                    </h3>
                    <div style={{ width: '100%', height: 240 }}>
                        <ResponsiveContainer>
                            <AreaChart data={timelineData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
                                <XAxis dataKey="date" tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} />
                                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} />
                                <Tooltip
                                    contentStyle={{
                                        background: 'var(--bg-primary)',
                                        border: '1.5px solid var(--border-primary)',
                                        borderRadius: 'var(--radius-md)',
                                        fontSize: 12,
                                    }}
                                />
                                <Area type="monotone" dataKey="score" stroke="#F5C842" fill="#F5C842" fillOpacity={0.15} strokeWidth={2} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}

            {/* Delta Vulnerabilities */}
            {delta && (delta.new_vulnerabilities.length > 0 || delta.fixed_vulnerabilities.length > 0) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {delta.new_vulnerabilities.length > 0 && (
                        <div className="card" style={{ padding: 20 }}>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#DC2626', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                                <AlertTriangle style={{ width: 14, height: 14 }} /> New Vulnerabilities ({delta.new_vulnerabilities.length})
                            </h4>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {delta.new_vulnerabilities.map((v) => (
                                    <div key={v.id} style={{
                                        padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                                        border: '1px solid var(--border-light)', fontSize: 12,
                                    }}>
                                        <div className="flex items-center gap-2">
                                            <span className="pill" style={{
                                                fontSize: 10, padding: '1px 6px',
                                                background: v.severity === 'critical' ? '#DC2626' : v.severity === 'high' ? '#EA580C' : '#D97706',
                                                color: 'white',
                                            }}>
                                                {v.severity}
                                            </span>
                                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{v.vulnerability_type}</span>
                                        </div>
                                        <p style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2, fontFamily: 'monospace' }}>
                                            {v.file_name}{v.line_reference ? `:${v.line_reference}` : ''}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {delta.fixed_vulnerabilities.length > 0 && (
                        <div className="card" style={{ padding: 20 }}>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#16A34A', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                                <CheckCircle style={{ width: 14, height: 14 }} /> Fixed Vulnerabilities ({delta.fixed_vulnerabilities.length})
                            </h4>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {delta.fixed_vulnerabilities.map((v) => (
                                    <div key={v.id} style={{
                                        padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                                        border: '1px solid var(--border-light)', fontSize: 12,
                                    }}>
                                        <div className="flex items-center gap-2">
                                            <span className="pill" style={{
                                                fontSize: 10, padding: '1px 6px',
                                                background: '#16A34A', color: 'white',
                                            }}>
                                                fixed
                                            </span>
                                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{v.vulnerability_type}</span>
                                        </div>
                                        <p style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2, fontFamily: 'monospace' }}>
                                            {v.file_name}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Webhook Status */}
            <div className="card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Webhook style={{ width: 14, height: 14 }} /> Webhook Configuration
                </h3>
                {webhookInfo ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        <div style={{ padding: '10px 14px', borderRadius: 'var(--radius-sm)', background: 'var(--bg-code)', fontFamily: 'monospace', fontSize: 12 }}>
                            <p><strong>URL:</strong> {webhookInfo.webhook_url}</p>
                            <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                                <strong>Secret:</strong>
                                <span>{secretVisible ? webhookInfo.webhook_secret : '\u2022'.repeat(24)}</span>
                                <button
                                    onClick={() => setSecretVisible(!secretVisible)}
                                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--text-tertiary)' }}
                                    title={secretVisible ? 'Hide secret' : 'Show secret'}
                                >
                                    {secretVisible ? <EyeOff style={{ width: 14, height: 14 }} /> : <Eye style={{ width: 14, height: 14 }} />}
                                </button>
                                <button
                                    onClick={() => { navigator.clipboard.writeText(webhookInfo.webhook_secret); }}
                                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--text-tertiary)' }}
                                    title="Copy secret"
                                >
                                    <Copy style={{ width: 14, height: 14 }} />
                                </button>
                            </div>
                        </div>
                        <p style={{ fontSize: 11, color: 'var(--severity-high)', fontWeight: 500 }}>
                            Save this secret now. It will not be shown again after you leave this page.
                        </p>
                        <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{webhookInfo.instructions}</p>
                    </div>
                ) : (
                    <div className="flex items-center justify-between">
                        <div>
                            <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                                {pipeline.webhook_secret_set ? 'Webhook is active and receiving events.' : 'No webhook configured. Connect to enable automated scanning.'}
                            </p>
                        </div>
                        {!pipeline.webhook_secret_set && (
                            <button onClick={handleConnectWebhook} className="btn btn-primary" style={{ fontSize: 12, padding: '6px 14px' }}>
                                Connect Webhook
                            </button>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
