'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import type { ComplianceStatus, AuditLogEntry, AuditVerifyResult } from '@/api/compliance';
import {
    Shield, CheckCircle, AlertTriangle, XCircle, FileSearch,
    RefreshCw, Download, Trash2, Loader2, Hash, Clock,
} from 'lucide-react';

export default function CompliancePage() {
    return (
        <AuthGuard requiredRole={['admin', 'auditor']}>
            <ComplianceContent />
        </AuthGuard>
    );
}

function StatusBadge({ status }: { status: string }) {
    const map: Record<string, { bg: string; color: string; icon: React.ReactNode }> = {
        compliant: { bg: '#F0FFF4', color: '#16A34A', icon: <CheckCircle style={{ width: 12, height: 12 }} /> },
        partial: { bg: '#FFF8E1', color: '#92400E', icon: <AlertTriangle style={{ width: 12, height: 12 }} /> },
        non_compliant: { bg: '#FFF5F5', color: '#DC2626', icon: <XCircle style={{ width: 12, height: 12 }} /> },
        unknown: { bg: 'var(--bg-tertiary)', color: 'var(--text-tertiary)', icon: null },
    };
    const s = map[status] || map.unknown;
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '2px 8px', borderRadius: 'var(--radius-sm)',
            background: s.bg, color: s.color, fontSize: 11, fontWeight: 600,
        }}>
            {s.icon} {status.replace('_', ' ')}
        </span>
    );
}

const MOCK_STATUS: ComplianceStatus = {
    overall_status: 'partial',
    controls: {
        access_control: { status: 'compliant', detail: 'RBAC enforced across all endpoints. Role separation verified.', verified_entries: 48 },
        data_encryption: { status: 'compliant', detail: 'TLS 1.3 in transit. AES-256 at rest. OAuth tokens encrypted.', verified_entries: 12 },
        audit_logging: { status: 'partial', detail: 'Audit log active. Integrity chain partially verified (98%).', verified_entries: 312 },
        vulnerability_management: { status: 'compliant', detail: 'Regular scans scheduled. CVE tracking active.', verified_entries: 5 },
        incident_response: { status: 'non_compliant', detail: 'Incident response plan not yet documented and approved.', verified_entries: 0 },
        change_management: { status: 'partial', detail: 'CI/CD pipeline integrated. Change tickets partially linked.', verified_entries: 22 },
    },
    recommendations: [
        'Document and approve an incident response plan.',
        'Complete audit chain integrity verification.',
        'Link remaining change tickets to CI/CD pipeline runs.',
    ],
    evaluated_at: new Date().toISOString(),
};

const MOCK_AUDIT: AuditLogEntry[] = [
    { id: 'a1', event_type: 'scan_created', event_category: 'scan', user_id: 'demo-user-001', detail: { repo: 'my-web-app' }, ip_address: '192.168.1.1', created_at: new Date(Date.now() - 3600000).toISOString(), integrity_hash: 'sha256:abc123' },
    { id: 'a2', event_type: 'user_login', event_category: 'auth', user_id: 'demo-user-001', detail: { provider: 'github' }, ip_address: '192.168.1.1', created_at: new Date(Date.now() - 7200000).toISOString(), integrity_hash: 'sha256:def456' },
    { id: 'a3', event_type: 'scan_deleted', event_category: 'scan', user_id: 'demo-user-001', detail: { scan_id: 'scan-old' }, ip_address: '192.168.1.1', created_at: new Date(Date.now() - 86400000).toISOString(), integrity_hash: 'sha256:ghi789' },
    { id: 'a4', event_type: 'profile_updated', event_category: 'user', user_id: 'demo-user-001', detail: { field: 'name' }, ip_address: '10.0.0.1', created_at: new Date(Date.now() - 172800000).toISOString(), integrity_hash: 'sha256:jkl012' },
];

function ComplianceContent() {
    const [status] = useState<ComplianceStatus | null>(MOCK_STATUS);
    const [auditEntries] = useState<AuditLogEntry[]>(MOCK_AUDIT);
    const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
    const [loading] = useState(false);
    const [verifying, setVerifying] = useState(false);
    const [error] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'status' | 'audit' | 'gdpr'>('status');

    const handleVerifyChain = async () => {
        setVerifying(true);
        await new Promise((r) => setTimeout(r, 1000));
        setVerifyResult({ valid: true, verified_count: 312, total_checked: 316, broken_at: null, message: 'Audit chain integrity verified. 312/316 entries valid.' });
        setVerifying(false);
    };

    const handleGdprExport = async () => {
        const data = { export_date: new Date().toISOString(), user_id: 'demo-user-001', profile: { name: 'Demo User', email: 'demo@secureai.dev' }, scans: [], audit_logs: MOCK_AUDIT };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `gdpr-export-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleGdprDelete = async () => {
        if (!confirm('This will permanently delete ALL your data. This action cannot be undone. Continue?')) return;
        alert('Demo mode: data deletion is simulated.');
    };

    const tabs = [
        { id: 'status' as const, label: 'SOC2 Status' },
        { id: 'audit' as const, label: 'Audit Log' },
        { id: 'gdpr' as const, label: 'GDPR' },
    ];

    return (
        <AppShell>
            <div style={{ maxWidth: 1100, margin: '0 auto' }}>
                {/* Header */}
                <div className="animate-fade-in" style={{ marginBottom: 24 }}>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                            <Shield style={{ width: 14, height: 14 }} /> Compliance
                        </div>
                    </div>
                    <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                        Compliance & Audit
                    </h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                        SOC2 readiness, audit log, and GDPR data management.
                    </p>
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

                {/* Tabs */}
                <div className="flex items-center gap-2" style={{ marginBottom: 20 }}>
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            style={{
                                padding: '8px 16px', fontSize: 13, fontWeight: 600,
                                borderRadius: 'var(--radius-md)', cursor: 'pointer',
                                border: activeTab === tab.id ? '1.5px solid var(--border-primary)' : '1.5px solid transparent',
                                background: activeTab === tab.id ? 'var(--brand-primary-light)' : 'transparent',
                                color: activeTab === tab.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                            }}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>

                {loading ? (
                    <div style={{ textAlign: 'center', padding: 60 }}>
                        <Loader2 style={{ width: 24, height: 24, animation: 'spin 0.6s linear infinite', margin: '0 auto' }} />
                    </div>
                ) : (
                    <>
                        {/* SOC2 Status */}
                        {activeTab === 'status' && status && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <div className="card" style={{ padding: 20 }}>
                                    <div className="flex items-center justify-between" style={{ marginBottom: 16 }}>
                                        <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>Overall Status</h3>
                                        <StatusBadge status={status.overall_status} />
                                    </div>
                                    <p style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                                        Evaluated: {new Date(status.evaluated_at).toLocaleString()}
                                    </p>
                                </div>

                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                                    {Object.entries(status.controls).map(([key, ctrl]) => (
                                        <div key={key} className="card" style={{ padding: 16 }}>
                                            <div className="flex items-center justify-between" style={{ marginBottom: 8 }}>
                                                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                                                    {key.replace(/_/g, ' ')}
                                                </span>
                                                <StatusBadge status={ctrl.status} />
                                            </div>
                                            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{ctrl.detail}</p>
                                            {ctrl.verified_entries !== undefined && (
                                                <p style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>
                                                    {ctrl.verified_entries} entries verified
                                                </p>
                                            )}
                                        </div>
                                    ))}
                                </div>

                                {status.recommendations.length > 0 && (
                                    <div className="card" style={{ padding: 20 }}>
                                        <h4 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>Recommendations</h4>
                                        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                                            {status.recommendations.map((rec, i) => (
                                                <li key={i} style={{ fontSize: 13, color: 'var(--text-secondary)', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                                                    <AlertTriangle style={{ width: 14, height: 14, color: '#F59E0B', flexShrink: 0, marginTop: 2 }} />
                                                    {rec}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Audit Log */}
                        {activeTab === 'audit' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <div className="flex items-center gap-3">
                                    <button onClick={handleVerifyChain} disabled={verifying} className="btn btn-secondary" style={{ fontSize: 12, padding: '6px 14px' }}>
                                        {verifying ? <Loader2 style={{ width: 14, height: 14, animation: 'spin 0.6s linear infinite' }} /> : <Hash style={{ width: 14, height: 14 }} />}
                                        Verify Chain Integrity
                                    </button>
                                    <button onClick={fetchData} className="btn btn-secondary" style={{ fontSize: 12, padding: '6px 14px' }}>
                                        <RefreshCw style={{ width: 14, height: 14 }} /> Refresh
                                    </button>
                                </div>

                                {verifyResult && (
                                    <div className="card" style={{
                                        padding: 16,
                                        border: verifyResult.valid ? '1.5px solid #16A34A' : '1.5px solid #DC2626',
                                        background: verifyResult.valid ? '#F0FFF4' : '#FFF5F5',
                                    }}>
                                        <div className="flex items-center gap-2">
                                            {verifyResult.valid ? (
                                                <CheckCircle style={{ width: 16, height: 16, color: '#16A34A' }} />
                                            ) : (
                                                <XCircle style={{ width: 16, height: 16, color: '#DC2626' }} />
                                            )}
                                            <span style={{ fontSize: 13, fontWeight: 600, color: verifyResult.valid ? '#16A34A' : '#DC2626' }}>
                                                {verifyResult.message}
                                            </span>
                                        </div>
                                        <p style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>
                                            Verified {verifyResult.verified_count} of {verifyResult.total_checked} entries
                                        </p>
                                    </div>
                                )}

                                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                                        <thead>
                                            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1.5px solid var(--border-primary)' }}>
                                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)' }}>Event</th>
                                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)' }}>Category</th>
                                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)' }}>Time</th>
                                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)' }}>IP</th>
                                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)' }}>Hash</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {auditEntries.map((entry) => (
                                                <tr key={entry.id} style={{ borderBottom: '1px solid var(--border-light)' }}>
                                                    <td style={{ padding: '10px 14px', fontWeight: 500, color: 'var(--text-primary)' }}>{entry.event_type}</td>
                                                    <td style={{ padding: '10px 14px' }}>
                                                        <span className="pill" style={{ fontSize: 10, padding: '1px 6px' }}>{entry.event_category}</span>
                                                    </td>
                                                    <td style={{ padding: '10px 14px', color: 'var(--text-tertiary)' }}>
                                                        <span className="flex items-center gap-1">
                                                            <Clock style={{ width: 10, height: 10 }} />
                                                            {entry.created_at ? new Date(entry.created_at).toLocaleString() : '--'}
                                                        </span>
                                                    </td>
                                                    <td style={{ padding: '10px 14px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                                                        {entry.ip_address || '--'}
                                                    </td>
                                                    <td style={{ padding: '10px 14px', color: 'var(--text-tertiary)', fontFamily: 'monospace', fontSize: 10 }}>
                                                        {entry.integrity_hash ? entry.integrity_hash.slice(0, 12) + '...' : '--'}
                                                    </td>
                                                </tr>
                                            ))}
                                            {auditEntries.length === 0 && (
                                                <tr>
                                                    <td colSpan={5} style={{ padding: 40, textAlign: 'center', color: 'var(--text-tertiary)' }}>
                                                        No audit log entries found.
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}

                        {/* GDPR */}
                        {activeTab === 'gdpr' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <div className="card" style={{ padding: 20 }}>
                                    <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Download style={{ width: 18, height: 18 }} /> Data Portability
                                    </h3>
                                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>
                                        Export all your personal data including profile, scan history, and audit logs as a JSON file.
                                    </p>
                                    <button onClick={handleGdprExport} className="btn btn-secondary" style={{ fontSize: 13, padding: '8px 16px' }}>
                                        <Download style={{ width: 14, height: 14 }} /> Export My Data
                                    </button>
                                </div>

                                <div className="card" style={{ padding: 20, border: '1.5px solid var(--severity-critical)' }}>
                                    <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--severity-critical)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Trash2 style={{ width: 18, height: 18 }} /> Right to Be Forgotten
                                    </h3>
                                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>
                                        Permanently delete all your data from our systems. This includes all scans, results,
                                        vulnerability data, and associated audit logs. This action is irreversible.
                                    </p>
                                    <button onClick={handleGdprDelete} className="btn btn-secondary" style={{
                                        fontSize: 13, padding: '8px 16px',
                                        color: 'var(--severity-critical)', borderColor: 'var(--severity-critical)',
                                    }}>
                                        <Trash2 style={{ width: 14, height: 14 }} /> Delete All My Data
                                    </button>
                                </div>
                            </div>
                        )}
                    </>
                )}
            </div>
        </AppShell>
    );
}
