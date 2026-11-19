'use client';

import React from 'react';
import { ScanResult } from '@/store/scanStore';
import { FileWarning, Bug, ShieldAlert, Target, TrendingDown, AlertTriangle } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';

interface RepoRiskIntelligenceProps {
    result: ScanResult;
}

export function RepoRiskIntelligence({ result }: RepoRiskIntelligenceProps) {
    const fileVulnCount: Record<string, number> = {};
    const typeCount: Record<string, number> = {};
    const categoryCount: Record<string, number> = {};

    result.vulnerabilities.forEach((v) => {
        fileVulnCount[v.file] = (fileVulnCount[v.file] || 0) + 1;
        typeCount[v.type] = (typeCount[v.type] || 0) + 1;
        categoryCount[v.category] = (categoryCount[v.category] || 0) + 1;
    });

    const mostVulnerableFile = Object.entries(fileVulnCount).sort((a, b) => b[1] - a[1])[0];
    const mostCommonIssue = Object.entries(typeCount).sort((a, b) => b[1] - a[1])[0];
    const weakestCategory = Object.entries(categoryCount).sort((a, b) => b[1] - a[1])[0];

    const criticalVulns = result.vulnerabilities.filter((v) => v.severity === 'critical' || v.severity === 'high');
    const priorityFixes = criticalVulns.slice(0, 3);

    const riskPosture = result.securityScore >= 80 ? 'Your codebase has a strong security posture with minor improvements recommended.' :
        result.securityScore >= 60 ? 'Moderate risk detected. Address high-severity issues to improve your security grade.' :
            'Elevated risk level. Immediate attention required on critical vulnerabilities.';

    return (
        <div className="card animate-fade-in" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Target style={{ width: 16, height: 16 }} />
                Repository Risk Intelligence
            </h3>

            {/* Insights */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {[
                    { icon: <FileWarning style={{ width: 16, height: 16 }} />, label: 'Most Vulnerable File', value: mostVulnerableFile?.[0] || 'N/A', detail: mostVulnerableFile ? `${mostVulnerableFile[1]} vulnerabilities` : '', color: 'var(--severity-critical)' },
                    { icon: <Bug style={{ width: 16, height: 16 }} />, label: 'Most Common Issue', value: mostCommonIssue?.[0] || 'N/A', detail: mostCommonIssue ? `${mostCommonIssue[1]} occurrences` : '', color: 'var(--severity-high)' },
                    { icon: <ShieldAlert style={{ width: 16, height: 16 }} />, label: 'Weakest Category', value: weakestCategory?.[0] || 'N/A', detail: weakestCategory ? `${weakestCategory[1]} issues` : '', color: 'var(--severity-medium)' },
                ].map((insight, i) => (
                    <div key={i} style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)', border: '1.5px solid var(--border-light)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, color: insight.color }}>
                            {insight.icon}
                            <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{insight.label}</span>
                        </div>
                        <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{insight.value}</p>
                        <p style={{ fontSize: 10, color: 'var(--text-tertiary)', marginTop: 2 }}>{insight.detail}</p>
                    </div>
                ))}
            </div>

            {/* Priority Fixes */}
            {priorityFixes.length > 0 && (
                <div>
                    <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <TrendingDown style={{ width: 14, height: 14 }} /> Suggested Priority Fixes
                    </h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {priorityFixes.map((vuln, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)', border: '1px solid var(--border-light)' }}>
                                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-tertiary)', width: 18 }}>{i + 1}.</span>
                                <Badge variant={vuln.severity}>{vuln.severity}</Badge>
                                <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{vuln.name}</span>
                                <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-tertiary)' }}>{vuln.file}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Risk Posture */}
            <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--brand-primary-light)', border: '1.5px solid var(--brand-primary)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <AlertTriangle style={{ width: 14, height: 14 }} />
                    <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>Risk Posture Summary</span>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{riskPosture}</p>
            </div>
        </div>
    );
}
