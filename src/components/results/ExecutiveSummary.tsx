'use client';

import React from 'react';
import { ScanResult } from '@/store/scanStore';
import { FileText, Bug, Award } from 'lucide-react';

interface ExecutiveSummaryProps {
    result: ScanResult;
}

export function ExecutiveSummary({ result }: ExecutiveSummaryProps) {
    const gradeColor = {
        A: 'var(--grade-a)', B: 'var(--grade-b)', C: 'var(--grade-c)',
        D: 'var(--grade-d)', F: 'var(--grade-f)',
    }[result.grade] || 'var(--text-tertiary)';

    const scoreColor = result.securityScore >= 80 ? 'var(--grade-a)' : result.securityScore >= 60 ? 'var(--grade-c)' : 'var(--grade-f)';

    return (
        <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Top Row */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* Security Score */}
                <div className="card" style={{ padding: 20, display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div style={{ position: 'relative', width: 64, height: 64 }}>
                        <svg className="score-ring" style={{ width: 64, height: 64, transform: 'rotate(-90deg)' }} viewBox="0 0 64 64">
                            <circle cx="32" cy="32" r="28" fill="none" stroke="var(--border-light)" strokeWidth="5" />
                            <circle cx="32" cy="32" r="28" fill="none" stroke={scoreColor} strokeWidth="5"
                                strokeDasharray={`${result.securityScore * 1.76} 176`} strokeLinecap="round" />
                        </svg>
                        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <span style={{ fontSize: 18, fontWeight: 800, color: scoreColor }}>{result.securityScore}</span>
                        </div>
                    </div>
                    <div>
                        <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Security Score</p>
                        <p style={{ fontSize: 24, fontWeight: 800, color: scoreColor }}>{result.securityScore}/100</p>
                    </div>
                </div>

                {/* Risk Grade */}
                <div className="card" style={{ padding: 20, display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div
                        style={{
                            width: 64, height: 64,
                            borderRadius: 'var(--radius-lg)',
                            border: '1.5px solid var(--border-primary)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            background: 'var(--bg-secondary)',
                        }}
                    >
                        <span style={{ fontSize: 32, fontWeight: 800, color: gradeColor }}>{result.grade}</span>
                    </div>
                    <div>
                        <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Grade</p>
                        <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                            {result.grade === 'A' ? 'Excellent' : result.grade === 'B' ? 'Good' : result.grade === 'C' ? 'Fair' : result.grade === 'D' ? 'Poor' : 'Critical'}
                        </p>
                    </div>
                </div>

                {/* Confidence */}
                <div className="card-accent" style={{ padding: 20, display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div
                        style={{
                            width: 64, height: 64,
                            borderRadius: 'var(--radius-lg)',
                            background: 'rgba(0,0,0,0.1)',
                            border: '1.5px solid var(--border-primary)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}
                    >
                        <Award style={{ width: 30, height: 30 }} />
                    </div>
                    <div>
                        <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em', opacity: 0.7 }}>AI Confidence</p>
                        <p style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)' }}>{result.confidenceScore}%</p>
                    </div>
                </div>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                    { icon: <FileText style={{ width: 16, height: 16, color: 'var(--text-tertiary)' }} />, value: result.totalFiles, label: 'Files Scanned' },
                    { icon: <Bug style={{ width: 16, height: 16, color: 'var(--text-secondary)' }} />, value: result.totalVulnerabilities, label: 'Total Vulns' },
                    { dot: 'var(--severity-critical)', value: result.critical, label: 'Critical', color: 'var(--severity-critical)' },
                    { dot: 'var(--severity-high)', value: result.high, label: 'High', color: 'var(--severity-high)' },
                    { dot: 'var(--severity-medium)', value: result.medium, label: 'Medium', color: 'var(--severity-medium)' },
                    { dot: 'var(--severity-low)', value: result.low, label: 'Low', color: 'var(--severity-low)' },
                ].map((stat, i) => (
                    <div key={i} className="card" style={{ padding: 14, textAlign: 'center' }}>
                        {'icon' in stat && stat.icon ? (
                            <div style={{ marginBottom: 6, display: 'flex', justifyContent: 'center' }}>{stat.icon}</div>
                        ) : (
                            <div style={{ width: 10, height: 10, borderRadius: '50%', background: stat.dot, margin: '0 auto 6px' }} />
                        )}
                        <p style={{ fontSize: 22, fontWeight: 800, color: stat.color || 'var(--text-primary)' }}>{stat.value}</p>
                        <p style={{ fontSize: 10, color: 'var(--text-tertiary)', fontWeight: 600 }}>{stat.label}</p>
                    </div>
                ))}
            </div>
        </div>
    );
}
