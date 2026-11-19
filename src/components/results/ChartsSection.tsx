'use client';

import React from 'react';
import { ScanResult } from '@/store/scanStore';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface ChartsSectionProps {
    result: ScanResult;
}

const SEVERITY_COLORS = {
    Critical: '#DC2626',
    High: '#EA580C',
    Medium: '#D97706',
    Low: '#2563EB',
    Info: '#7C3AED',
};

const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        return (
            <div
                style={{
                    background: 'var(--bg-card)',
                    border: '1.5px solid var(--border-primary)',
                    borderRadius: 'var(--radius-md)',
                    padding: '8px 12px',
                    boxShadow: 'var(--shadow-md)',
                }}
            >
                <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{label || payload[0].name}</p>
                <p style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{payload[0].value} vulnerabilities</p>
            </div>
        );
    }
    return null;
};

export function ChartsSection({ result }: ChartsSectionProps) {
    const severityData = [
        { name: 'Critical', value: result.critical, color: SEVERITY_COLORS.Critical },
        { name: 'High', value: result.high, color: SEVERITY_COLORS.High },
        { name: 'Medium', value: result.medium, color: SEVERITY_COLORS.Medium },
        { name: 'Low', value: result.low, color: SEVERITY_COLORS.Low },
    ].filter((d) => d.value > 0);

    const typeMap: Record<string, number> = {};
    result.vulnerabilities.forEach((v) => {
        const shortType = v.type.split('(')[0].trim().slice(0, 20);
        typeMap[shortType] = (typeMap[shortType] || 0) + 1;
    });
    const typeData = Object.entries(typeMap)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);

    return (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-fade-in">
            {/* Severity Pie Chart */}
            <div className="card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>Severity Distribution</h3>
                <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                        <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={4} dataKey="value">
                            {severityData.map((entry, i) => (
                                <Cell key={i} fill={entry.color} stroke="var(--border-primary)" strokeWidth={1} />
                            ))}
                        </Pie>
                        <Tooltip content={<CustomTooltip />} />
                    </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap justify-center gap-3" style={{ marginTop: 8 }}>
                    {severityData.map((d) => (
                        <div key={d.name} className="flex items-center gap-1.5">
                            <div style={{ width: 10, height: 10, borderRadius: '50%', background: d.color, border: '1px solid var(--border-primary)' }} />
                            <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-secondary)' }}>{d.name}: {d.value}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Type Bar Chart */}
            <div className="card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>By Vulnerability Type</h3>
                <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={typeData} layout="vertical" margin={{ left: 10, right: 10 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" horizontal={false} />
                        <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-tertiary)' }} />
                        <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} width={100} />
                        <Tooltip content={<CustomTooltip />} />
                        <Bar dataKey="count" fill="#F5C842" stroke="#1A1A1A" strokeWidth={1} radius={[0, 4, 4, 0]} barSize={16} />
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}
