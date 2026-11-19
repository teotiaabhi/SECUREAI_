'use client';

import React from 'react';
import { useScanStore, ScanDepth } from '@/store/scanStore';
import { Cpu, Layers, Brain, Shield, Globe, Server, Settings, Package, Sparkles, Code, FileWarning } from 'lucide-react';

const depths: { id: ScanDepth; label: string; desc: string; icon: React.ReactNode }[] = [
    { id: 'basic', label: 'Basic', desc: 'Pattern matching', icon: <Layers className="w-5 h-5" /> },
    { id: 'standard', label: 'Standard', desc: 'Static + OWASP', icon: <Cpu className="w-5 h-5" /> },
    { id: 'deep', label: 'Deep AI', desc: 'AI reasoning', icon: <Brain className="w-5 h-5" /> },
];

const categoryItems = [
    { key: 'backend', label: 'Backend', icon: <Server style={{ width: 14, height: 14 }} /> },
    { key: 'frontend', label: 'Frontend', icon: <Globe style={{ width: 14, height: 14 }} /> },
    { key: 'api', label: 'API', icon: <Shield style={{ width: 14, height: 14 }} /> },
    { key: 'config', label: 'Config', icon: <Settings style={{ width: 14, height: 14 }} /> },
    { key: 'dependencies', label: 'Deps', icon: <Package style={{ width: 14, height: 14 }} /> },
];

export function ScanConfigPanel() {
    const { config, setConfig, setCategoryConfig } = useScanStore();

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {/* Scan Depth */}
            <div>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Scan Depth
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {depths.map((d) => (
                        <button
                            key={d.id}
                            onClick={() => setConfig({ depth: d.id })}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 10,
                                padding: '10px 12px',
                                borderRadius: 'var(--radius-md)',
                                border: `1.5px solid ${config.depth === d.id ? 'var(--border-primary)' : 'var(--border-light)'}`,
                                background: config.depth === d.id ? 'var(--brand-primary)' : 'var(--bg-primary)',
                                cursor: 'pointer',
                                transition: 'all 0.15s ease',
                                textAlign: 'left',
                            }}
                        >
                            {d.icon}
                            <div>
                                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{d.label}</span>
                                <span style={{ fontSize: 11, color: 'var(--text-secondary)', marginLeft: 6 }}>{d.desc}</span>
                            </div>
                        </button>
                    ))}
                </div>
            </div>

            {/* Categories */}
            <div>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Categories
                </h4>
                <div className="flex flex-wrap gap-2">
                    {categoryItems.map((cat) => {
                        const checked = config.categories[cat.key as keyof typeof config.categories];
                        return (
                            <button
                                key={cat.key}
                                onClick={() => setCategoryConfig(cat.key, !checked)}
                                className="pill"
                                style={{
                                    background: checked ? 'var(--brand-primary)' : 'var(--bg-primary)',
                                    borderColor: checked ? 'var(--border-primary)' : 'var(--border-light)',
                                    cursor: 'pointer',
                                    fontSize: 12,
                                    padding: '5px 12px',
                                    fontWeight: checked ? 600 : 500,
                                    transition: 'all 0.15s ease',
                                }}
                            >
                                {cat.icon} {cat.label}
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* AI Options */}
            <div>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    AI Options
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {[
                        { key: 'aiReasoning', label: 'AI Reasoning', icon: <Sparkles style={{ width: 14, height: 14 }} /> },
                        { key: 'exploitExamples', label: 'Exploit Examples', icon: <FileWarning style={{ width: 14, height: 14 }} /> },
                        { key: 'secureRewrite', label: 'Secure Rewrite', icon: <Code style={{ width: 14, height: 14 }} /> },
                    ].map((opt) => {
                        const enabled = config[opt.key as keyof typeof config] as boolean;
                        return (
                            <div
                                key={opt.key}
                                onClick={() => setConfig({ [opt.key]: !enabled })}
                                style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                    padding: '10px 12px',
                                    borderRadius: 'var(--radius-md)',
                                    border: '1.5px solid var(--border-light)',
                                    cursor: 'pointer',
                                    background: 'var(--bg-primary)',
                                    transition: 'all 0.15s ease',
                                }}
                            >
                                <div className="flex items-center gap-2">
                                    <span style={{ color: 'var(--text-secondary)' }}>{opt.icon}</span>
                                    <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{opt.label}</span>
                                </div>
                                <div
                                    className={`toggle ${enabled ? 'active' : ''}`}
                                />
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}
