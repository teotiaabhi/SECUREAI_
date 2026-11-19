'use client';

import React, { useEffect, useMemo } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { useAuthStore } from '@/store/authStore';
import { useHistoryStore } from '@/store/historyStore';
import { useScanStore } from '@/store/scanStore';
import { Skeleton } from '@/components/ui/Skeleton';
import Link from 'next/link';
import dynamic from 'next/dynamic';
import {
    Shield, ScanSearch, History, TrendingUp, Bug,
    ArrowRight, BarChart3, Clock, Zap, FileWarning, GitBranch, AlertTriangle,
} from 'lucide-react';

// Lazy-load heavy recharts components — only imported when charts are visible
const LazyAreaChart = dynamic(() => import('recharts').then(m => ({ default: m.AreaChart })), { ssr: false });
const LazyArea = dynamic(() => import('recharts').then(m => ({ default: m.Area })), { ssr: false });
const LazyXAxis = dynamic(() => import('recharts').then(m => ({ default: m.XAxis })), { ssr: false });
const LazyYAxis = dynamic(() => import('recharts').then(m => ({ default: m.YAxis })), { ssr: false });
const LazyCartesianGrid = dynamic(() => import('recharts').then(m => ({ default: m.CartesianGrid })), { ssr: false });
const LazyTooltip = dynamic(() => import('recharts').then(m => ({ default: m.Tooltip })), { ssr: false });
const LazyResponsiveContainer = dynamic(() => import('recharts').then(m => ({ default: m.ResponsiveContainer })), { ssr: false });
const LazyPieChart = dynamic(() => import('recharts').then(m => ({ default: m.PieChart })), { ssr: false });
const LazyPie = dynamic(() => import('recharts').then(m => ({ default: m.Pie })), { ssr: false });
const LazyCell = dynamic(() => import('recharts').then(m => ({ default: m.Cell })), { ssr: false });
const UsageSummaryCard = dynamic(() => import('@/components/scan/UsageSummary').then(m => ({ default: m.UsageSummaryCard })), { ssr: false });

export default function DashboardPage() {
    return (
        <AuthGuard>
            <DashboardContent />
        </AuthGuard>
    );
}

function DashboardContent() {
    const { isAuthenticated, user } = useAuthStore();
    const { scans, isLoading: historyLoading, fetchHistory } = useHistoryStore();
    const { result } = useScanStore();

    // AuthGuard guarantees isAuthenticated = true here, so just fetch data
    useEffect(() => {
        if (isAuthenticated) {
            fetchHistory();
        }
    }, [isAuthenticated, fetchHistory]);

    const latestScan = scans[0];
    const trendData = useMemo(() => [...scans].reverse().map((s) => ({
        date: new Date(s.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        score: s.securityScore,
    })), [scans]);

    const totalVulns = useMemo(() => scans.reduce((sum, s) => sum + s.totalVulnerabilities, 0), [scans]);
    const avgScore = useMemo(() => scans.length > 0 ? Math.round(scans.reduce((sum, s) => sum + s.securityScore, 0) / scans.length) : 0, [scans]);

    const gradeColor = (grade: string) => {
        const c: Record<string, string> = { A: 'var(--grade-a)', B: 'var(--grade-b)', C: 'var(--grade-c)', D: 'var(--grade-d)', F: 'var(--grade-f)' };
        return c[grade] || 'var(--text-tertiary)';
    };

    return (
        <AppShell>
            <div style={{ maxWidth: 1100, margin: '0 auto' }}>
                {/* Welcome */}
                <div className="animate-fade-in" style={{ marginBottom: 32 }}>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Zap style={{ width: 14, height: 14 }} /> Dashboard
                        </div>
                    </div>
                    <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                        Security Overview
                    </h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                        Monitor and improve your codebase security posture
                    </p>
                </div>

                {/* Quick Stats */}
                {historyLoading ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" style={{ marginBottom: 24 }}>
                        <Skeleton className="h-28" count={4} />
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in-up" style={{ marginBottom: 24 }}>
                        {[
                            { icon: Shield, label: 'Average Score', value: avgScore || '—', accent: false },
                            { icon: Bug, label: 'Total Vulnerabilities', value: totalVulns, accent: false },
                            { icon: BarChart3, label: 'Scans Completed', value: scans.length, accent: false },
                            { icon: TrendingUp, label: 'Latest Grade', value: latestScan?.grade || '—', accent: true },
                        ].map((stat, i) => {
                            const Icon = stat.icon;
                            return (
                                <div
                                    key={i}
                                    className={stat.accent ? 'card-accent' : 'card'}
                                    style={{ padding: 20 }}
                                >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                                        <div
                                            style={{
                                                width: 36, height: 36,
                                                borderRadius: 'var(--radius-md)',
                                                background: stat.accent ? 'rgba(0,0,0,0.1)' : 'var(--brand-primary-light)',
                                                border: '1.5px solid var(--border-primary)',
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            }}
                                        >
                                            <Icon style={{ width: 18, height: 18 }} />
                                        </div>
                                    </div>
                                    <p style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)' }}>
                                        {stat.value}
                                    </p>
                                    <p style={{ fontSize: 12, color: stat.accent ? 'var(--text-primary)' : 'var(--text-tertiary)', marginTop: 2, fontWeight: 500 }}>
                                        {stat.label}
                                    </p>
                                </div>
                            );
                        })}
                    </div>
                )}

                {/* Main Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Score Trend */}
                    <div className="lg:col-span-2 card animate-fade-in-up" style={{ padding: 24, animationDelay: '0.1s' }}>
                        <div className="flex items-center justify-between" style={{ marginBottom: 16 }}>
                            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                                <TrendingUp style={{ width: 16, height: 16 }} />
                                Security Score Trend
                            </h3>
                            <Link href="/history" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 4, textDecoration: 'none' }}>
                                View all <ArrowRight style={{ width: 12, height: 12 }} />
                            </Link>
                        </div>
                        {trendData.length > 0 ? (
                            <LazyResponsiveContainer width="100%" height={220}>
                                <LazyAreaChart data={trendData}>
                                    <defs>
                                        <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#F5C842" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#F5C842" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <LazyCartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
                                    <LazyXAxis dataKey="date" tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} />
                                    <LazyYAxis domain={[0, 100]} tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} />
                                    <LazyTooltip
                                        contentStyle={{
                                            background: 'var(--bg-card)',
                                            border: '1.5px solid var(--border-primary)',
                                            borderRadius: 'var(--radius-md)',
                                            fontSize: 12,
                                            boxShadow: 'var(--shadow-md)',
                                        }}
                                    />
                                    <LazyArea
                                        type="monotone"
                                        dataKey="score"
                                        stroke="#F5C842"
                                        strokeWidth={2.5}
                                        fill="url(#scoreGradient)"
                                        dot={{ r: 5, fill: '#F5C842', stroke: '#1A1A1A', strokeWidth: 1.5 }}
                                    />
                                </LazyAreaChart>
                            </LazyResponsiveContainer>
                        ) : (
                            <div className="flex items-center justify-center" style={{ height: 220, fontSize: 14, color: 'var(--text-tertiary)' }}>
                                No scan data yet. Start your first scan to see trends.
                            </div>
                        )}
                    </div>

                    {/* Quick Actions */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <div className="card animate-fade-in-up" style={{ padding: 20, animationDelay: '0.2s' }}>
                            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
                                Quick Actions
                            </h3>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {[
                                    { href: '/scan', icon: ScanSearch, title: 'New Scan', desc: 'Upload code or connect repo', accent: true },
                                    { href: '/results', icon: Shield, title: 'View Results', desc: 'Latest scan analysis', accent: false },
                                    { href: '/history', icon: History, title: 'Scan History', desc: 'Compare past scans', accent: false },
                                ].map((action) => {
                                    const Icon = action.icon;
                                    return (
                                        <Link
                                            key={action.href}
                                            href={action.href}
                                            className="card-interactive"
                                            style={{
                                                display: 'flex', alignItems: 'center', gap: 12,
                                                padding: 12,
                                                border: '1.5px solid var(--border-primary)',
                                                borderRadius: 'var(--radius-md)',
                                                textDecoration: 'none',
                                                background: action.accent ? 'var(--brand-primary)' : 'var(--bg-primary)',
                                                transition: 'all 0.15s ease',
                                            }}
                                        >
                                            <div
                                                style={{
                                                    width: 36, height: 36,
                                                    borderRadius: 'var(--radius-md)',
                                                    background: action.accent ? 'rgba(0,0,0,0.1)' : 'var(--brand-primary-light)',
                                                    border: '1.5px solid var(--border-primary)',
                                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                    flexShrink: 0,
                                                }}
                                            >
                                                <Icon style={{ width: 18, height: 18 }} />
                                            </div>
                                            <div style={{ flex: 1 }}>
                                                <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{action.title}</p>
                                                <p style={{ fontSize: 11, color: action.accent ? 'var(--text-primary)' : 'var(--text-tertiary)' }}>{action.desc}</p>
                                            </div>
                                            <ArrowRight style={{ width: 14, height: 14, color: 'var(--text-tertiary)' }} />
                                        </Link>
                                    );
                                })}
                            </div>
                        </div>

                        {/* Recent Scan */}
                        {latestScan && (
                            <Link
                                href={`/results?id=${latestScan.id}`}
                                className="card card-interactive animate-fade-in-up"
                                style={{ padding: 20, textDecoration: 'none', animationDelay: '0.3s' }}
                            >
                                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>
                                    Latest Scan
                                </h3>
                                <div className="flex items-center gap-3">
                                    <div
                                        style={{
                                            width: 44, height: 44,
                                            borderRadius: 'var(--radius-md)',
                                            border: '1.5px solid var(--border-primary)',
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            fontWeight: 800, fontSize: 18,
                                            color: gradeColor(latestScan.grade),
                                            background: 'var(--bg-secondary)',
                                        }}
                                    >
                                        {latestScan.grade}
                                    </div>
                                    <div style={{ flex: 1 }}>
                                        <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{latestScan.repoName}</p>
                                        <span suppressHydrationWarning style={{ fontSize: 11, color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: 4 }}>
                                            <Clock style={{ width: 12, height: 12 }} /> {new Date(latestScan.timestamp).toLocaleDateString('en-US')}
                                        </span>
                                    </div>
                                    <div className="flex gap-1">
                                        {latestScan.critical > 0 && <span className="badge-critical">{latestScan.critical}</span>}
                                        {latestScan.high > 0 && <span className="badge-high">{latestScan.high}</span>}
                                        {latestScan.medium > 0 && <span className="badge-medium">{latestScan.medium}</span>}
                                    </div>
                                </div>
                            </Link>
                        )}

                        {/* Usage Overview */}
                        <div className="animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
                            <UsageSummaryCard />
                        </div>
                    </div>
                </div>

                {/* Severity Breakdown & Analytics */}
                {scans.length > 0 && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in" style={{ marginTop: 24 }}>
                        {/* Aggregate Severity */}
                        <div className="card" style={{ padding: 24 }}>
                            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                                <AlertTriangle style={{ width: 16, height: 16 }} /> Severity Breakdown (All Scans)
                            </h3>
                            {(() => {
                                const sevData = [
                                    { name: 'Critical', value: scans.reduce((s, sc) => s + sc.critical, 0), color: '#DC2626' },
                                    { name: 'High', value: scans.reduce((s, sc) => s + sc.high, 0), color: '#EA580C' },
                                    { name: 'Medium', value: scans.reduce((s, sc) => s + sc.medium, 0), color: '#D97706' },
                                    { name: 'Low', value: scans.reduce((s, sc) => s + sc.low, 0), color: '#2563EB' },
                                ].filter((d) => d.value > 0);

                                if (sevData.length === 0) {
                                    return <p style={{ fontSize: 13, color: 'var(--text-tertiary)', textAlign: 'center', padding: 24 }}>No vulnerabilities found across scans</p>;
                                }

                                return (
                                    <>
                                        <LazyResponsiveContainer width="100%" height={180}>
                                            <LazyPieChart>
                                                <LazyPie data={sevData} cx="50%" cy="50%" innerRadius={50} outerRadius={70} paddingAngle={4} dataKey="value">
                                                    {sevData.map((entry, i) => (
                                                        <LazyCell key={i} fill={entry.color} stroke="var(--border-primary)" strokeWidth={1} />
                                                    ))}
                                                </LazyPie>
                                                <LazyTooltip
                                                    contentStyle={{
                                                        background: 'var(--bg-card)', border: '1.5px solid var(--border-primary)',
                                                        borderRadius: 'var(--radius-md)', fontSize: 12, boxShadow: 'var(--shadow-md)',
                                                    }}
                                                />
                                            </LazyPieChart>
                                        </LazyResponsiveContainer>
                                        <div className="flex flex-wrap justify-center gap-3" style={{ marginTop: 4 }}>
                                            {sevData.map((d) => (
                                                <div key={d.name} className="flex items-center gap-1.5">
                                                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: d.color }} />
                                                    <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-secondary)' }}>{d.name}: {d.value}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </>
                                );
                            })()}
                        </div>

                        {/* Top Vulnerable Files / Attack Surface */}
                        <div className="card" style={{ padding: 24 }}>
                            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                                <FileWarning style={{ width: 16, height: 16 }} /> Top Vulnerable Files
                            </h3>
                            {result && result.vulnerabilities.length > 0 ? (
                                (() => {
                                    const fileMap: Record<string, { count: number; critical: number; high: number }> = {};
                                    result.vulnerabilities.forEach((v) => {
                                        if (!fileMap[v.file]) fileMap[v.file] = { count: 0, critical: 0, high: 0 };
                                        fileMap[v.file].count++;
                                        if (v.severity === 'critical') fileMap[v.file].critical++;
                                        if (v.severity === 'high') fileMap[v.file].high++;
                                    });
                                    const sorted = Object.entries(fileMap).sort(([, a], [, b]) => b.count - a.count).slice(0, 8);
                                    const maxCount = sorted[0]?.[1].count || 1;

                                    return (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                            {sorted.map(([file, data], i) => (
                                                <div key={file} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                                    <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', width: 16, textAlign: 'right' }}>{i + 1}</span>
                                                    <div style={{ flex: 1, minWidth: 0 }}>
                                                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                                                            <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '60%' }}>
                                                                {file}
                                                            </span>
                                                            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>
                                                                {data.count} vulns
                                                                {data.critical > 0 && <span style={{ color: 'var(--severity-critical)', marginLeft: 4 }}>{data.critical}C</span>}
                                                                {data.high > 0 && <span style={{ color: 'var(--severity-high)', marginLeft: 4 }}>{data.high}H</span>}
                                                            </span>
                                                        </div>
                                                        <div style={{ height: 4, borderRadius: 2, background: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                                                            <div style={{
                                                                height: '100%', borderRadius: 2,
                                                                width: `${(data.count / maxCount) * 100}%`,
                                                                background: data.critical > 0 ? 'var(--severity-critical)' : data.high > 0 ? 'var(--severity-high)' : 'var(--brand-primary)',
                                                            }} />
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    );
                                })()
                            ) : (
                                <p style={{ fontSize: 13, color: 'var(--text-tertiary)', textAlign: 'center', padding: 24 }}>
                                    Run a scan to see file-level risk analysis
                                </p>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </AppShell>
    );
}
