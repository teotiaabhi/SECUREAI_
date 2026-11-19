'use client';

import React, { useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { useHistoryStore } from '@/store/historyStore';
import { EmptyState } from '@/components/ui/EmptyState';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { History, Trash2, TrendingUp, Calendar, Clock, BarChart3, AlertCircle } from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import Link from 'next/link';

export default function HistoryPage() {
    return (
        <AuthGuard>
            <HistoryContent />
        </AuthGuard>
    );
}

function HistoryContent() {
    const { scans, isLoading, error, fetchHistory, removeScan, clearError } = useHistoryStore();

    useEffect(() => {
        fetchHistory();
    }, [fetchHistory]);

    const trendData = [...scans]
        .reverse()
        .map((s) => ({
            date: new Date(s.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
            score: s.securityScore,
            vulns: s.totalVulnerabilities,
        }));

    const gradeColor = (grade: string) => {
        const colors: Record<string, string> = { A: 'var(--grade-a)', B: 'var(--grade-b)', C: 'var(--grade-c)', D: 'var(--grade-d)', F: 'var(--grade-f)' };
        return colors[grade] || 'var(--text-tertiary)';
    };

    return (
        <AppShell>
            <div style={{ maxWidth: 1000, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
                {/* Header */}
                <div className="animate-fade-in">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                            <History style={{ width: 14, height: 14 }} /> History
                        </div>
                    </div>
                    <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>Scan History</h1>
                </div>

                {/* Error */}
                {error && (
                    <div
                        className="animate-fade-in"
                        style={{
                            display: 'flex', alignItems: 'center', gap: 10,
                            padding: '12px 16px', borderRadius: 'var(--radius-md)',
                            background: 'var(--severity-critical-bg)', border: '1px solid var(--severity-critical)',
                        }}
                    >
                        <AlertCircle style={{ width: 16, height: 16, color: 'var(--severity-critical)', flexShrink: 0 }} />
                        <p style={{ fontSize: 13, color: 'var(--severity-critical)', flex: 1 }}>{error}</p>
                        <button onClick={clearError} style={{ fontSize: 12, textDecoration: 'underline', color: 'var(--text-tertiary)', background: 'none', border: 'none', cursor: 'pointer' }}>Dismiss</button>
                    </div>
                )}

                {isLoading ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <Skeleton className="h-48" />
                        <Skeleton className="h-20" count={3} />
                    </div>
                ) : scans.length === 0 ? (
                    <EmptyState
                        icon="scan"
                        title="No Scan History"
                        description="Complete a security scan to see your history here."
                        action={
                            <Link href="/scan" className="btn btn-primary">
                                Start a Scan
                            </Link>
                        }
                    />
                ) : (
                    <>
                        {/* Score Trend */}
                        {trendData.length > 1 && (
                            <div className="card animate-fade-in-up" style={{ padding: 20 }}>
                                <div className="flex items-center gap-2" style={{ marginBottom: 16 }}>
                                    <TrendingUp style={{ width: 16, height: 16 }} />
                                    <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>Security Score Trend</h3>
                                </div>
                                <ResponsiveContainer width="100%" height={200}>
                                    <LineChart data={trendData}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
                                        <XAxis dataKey="date" tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} />
                                        <YAxis tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} domain={[0, 100]} />
                                        <Tooltip
                                            contentStyle={{
                                                background: 'var(--bg-card)',
                                                border: '1.5px solid var(--border-primary)',
                                                borderRadius: 'var(--radius-md)',
                                                fontSize: 12,
                                                boxShadow: 'var(--shadow-md)',
                                            }}
                                        />
                                        <Line type="monotone" dataKey="score" stroke="#F5C842" strokeWidth={2.5} dot={{ r: 5, fill: '#F5C842', stroke: '#1A1A1A', strokeWidth: 1.5 }} />
                                    </LineChart>
                                </ResponsiveContainer>
                            </div>
                        )}

                        {/* Scan List */}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            {scans.map((scan) => (
                                <Link
                                    key={scan.id}
                                    href={`/results?id=${scan.id}`}
                                    className="card card-interactive animate-fade-in"
                                    style={{
                                        padding: 16,
                                        display: 'flex', alignItems: 'center', gap: 16,
                                        textDecoration: 'none',
                                    }}
                                >
                                    {/* Grade */}
                                    <div
                                        style={{
                                            width: 48, height: 48,
                                            borderRadius: 'var(--radius-md)',
                                            border: '1.5px solid var(--border-primary)',
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            background: 'var(--bg-secondary)',
                                            flexShrink: 0,
                                        }}
                                    >
                                        <span style={{ fontSize: 20, fontWeight: 800, color: gradeColor(scan.grade) }}>{scan.grade}</span>
                                    </div>

                                    {/* Info */}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div className="flex items-center gap-2">
                                            <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{scan.repoName}</span>
                                            <Badge variant={scan.securityScore >= 80 ? 'low' : scan.securityScore >= 60 ? 'medium' : 'critical'}>
                                                Score: {scan.securityScore}
                                            </Badge>
                                        </div>
                                        <div className="flex items-center gap-3" style={{ marginTop: 4, fontSize: 12, color: 'var(--text-tertiary)' }}>
                                            <span suppressHydrationWarning className="flex items-center gap-1"><Calendar style={{ width: 12, height: 12 }} /> {new Date(scan.timestamp).toLocaleDateString('en-US')}</span>
                                            <span className="flex items-center gap-1"><Clock style={{ width: 12, height: 12 }} /> {scan.duration}s</span>
                                            <span className="flex items-center gap-1"><BarChart3 style={{ width: 12, height: 12 }} /> {scan.totalVulnerabilities} vulns</span>
                                        </div>
                                    </div>

                                    {/* Severity Chips */}
                                    <div className="hidden sm:flex items-center gap-1.5">
                                        {scan.critical > 0 && <span className="badge-critical">{scan.critical}C</span>}
                                        {scan.high > 0 && <span className="badge-high">{scan.high}H</span>}
                                        {scan.medium > 0 && <span className="badge-medium">{scan.medium}M</span>}
                                        {scan.low > 0 && <span className="badge-low">{scan.low}L</span>}
                                    </div>

                                    {/* Delete */}
                                    <button
                                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); removeScan(scan.id); }}
                                        style={{
                                            width: 32, height: 32,
                                            borderRadius: 'var(--radius-md)',
                                            border: '1px solid var(--border-light)',
                                            background: 'var(--bg-primary)',
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            cursor: 'pointer', color: 'var(--text-tertiary)',
                                            opacity: 0, transition: 'all 0.15s ease',
                                        }}
                                        className="group-hover:opacity-100"
                                        title="Delete scan"
                                    >
                                        <Trash2 style={{ width: 14, height: 14 }} />
                                    </button>
                                </Link>
                            ))}
                        </div>
                    </>
                )}
            </div>
        </AppShell>
    );
}
