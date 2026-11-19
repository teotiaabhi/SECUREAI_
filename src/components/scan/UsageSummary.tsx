'use client';

import React from 'react';
import { BarChart3 } from 'lucide-react';

function UsageBar({ used, limit, label, color }: { used: number; limit: number; label: string; color: string }) {
    const pct = limit > 0 ? Math.min((used / limit) * 100, 100) : 0;
    return (
        <div style={{ marginBottom: 12 }}>
            <div className="flex items-center justify-between" style={{ marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</span>
                <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-tertiary)' }}>
                    {used.toLocaleString()} / {limit.toLocaleString()}
                </span>
            </div>
            <div style={{ height: 6, borderRadius: 3, background: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, borderRadius: 3, background: color, transition: 'width 0.3s ease' }} />
            </div>
        </div>
    );
}

export function UsageSummaryCard() {
    return (
        <div className="card" style={{ padding: 16 }}>
            <div className="flex items-center justify-between" style={{ marginBottom: 12 }}>
                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <BarChart3 style={{ width: 14, height: 14 }} /> Usage
                </h4>
                <span className="pill" style={{ fontSize: 10, padding: '2px 8px', textTransform: 'uppercase', fontWeight: 700 }}>pro</span>
            </div>
            <UsageBar used={12} limit={100} label="Scans" color="#F5C842" />
            <UsageBar used={48200} limit={500000} label="AI Tokens" color="#3B82F6" />
            <UsageBar used={25165824} limit={1073741824} label="Storage (24 MB)" color="#8B5CF6" />
        </div>
    );
}

