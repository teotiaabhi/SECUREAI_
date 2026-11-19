'use client';

import React, { useState } from 'react';
import type { TierPlan } from '@/api/usage';
import { Skeleton } from '@/components/ui/Skeleton';
import {
    Layers, Check, Zap, Shield, Crown,
    FileSearch, Database, Cpu, Server,
} from 'lucide-react';

/* ── Fallback tier data (if API is unreachable) ───────── */
const FALLBACK_TIERS: TierPlan[] = [
    {
        name: 'free', display_name: 'Free',
        scans_per_day: 5, max_repo_size_mb: 50, max_files: 100,
        ai_tokens_per_day: 10_000, storage_cap_bytes: 524_288_000,
        storage_cap_display: '500 MB',
    },
    {
        name: 'pro', display_name: 'Pro',
        scans_per_day: 50, max_repo_size_mb: 500, max_files: 2_000,
        ai_tokens_per_day: 100_000, storage_cap_bytes: 5_368_709_120,
        storage_cap_display: '5 GB',
    },
    {
        name: 'enterprise', display_name: 'Enterprise',
        scans_per_day: 500, max_repo_size_mb: 2_048, max_files: 10_000,
        ai_tokens_per_day: 500_000, storage_cap_bytes: 53_687_091_200,
        storage_cap_display: '50 GB',
    },
];

/* ── Tier visual config ───────────────────────────────── */
const TIER_META: Record<string, {
    icon: React.ElementType; accent: string; gradient: string; badge?: string;
}> = {
    free: {
        icon: Layers,
        accent: 'var(--brand-primary)',
        gradient: 'linear-gradient(135deg, rgba(99,102,241,0.06) 0%, rgba(99,102,241,0.02) 100%)',
    },
    pro: {
        icon: Zap,
        accent: '#f97316',
        gradient: 'linear-gradient(135deg, rgba(249,115,22,0.06) 0%, rgba(249,115,22,0.02) 100%)',
        badge: 'Popular',
    },
    enterprise: {
        icon: Crown,
        accent: '#8b5cf6',
        gradient: 'linear-gradient(135deg, rgba(139,92,246,0.06) 0%, rgba(139,92,246,0.02) 100%)',
    },
};

/* ── Limit row config ─────────────────────────────────── */
interface LimitRow {
    label: string;
    key: keyof TierPlan;
    icon: React.ElementType;
    format: (val: number | string) => string;
}

const LIMIT_ROWS: LimitRow[] = [
    {
        label: 'Scans per Day',
        key: 'scans_per_day',
        icon: FileSearch,
        format: (v) => String(v),
    },
    {
        label: 'Max Repo Size',
        key: 'max_repo_size_mb',
        icon: Database,
        format: (v) => {
            const n = Number(v);
            return n >= 1024 ? `${(n / 1024).toFixed(0)} GB` : `${n} MB`;
        },
    },
    {
        label: 'Max Files',
        key: 'max_files',
        icon: Server,
        format: (v) => Number(v).toLocaleString(),
    },
    {
        label: 'AI Tokens per Day',
        key: 'ai_tokens_per_day',
        icon: Cpu,
        format: (v) => Number(v).toLocaleString(),
    },
    {
        label: 'Storage',
        key: 'storage_cap_display',
        icon: Database,
        format: (v) => String(v),
    },
];

/* ── Component ────────────────────────────────────────── */

export function PlansSection() {
    const [tiers] = useState<TierPlan[]>(FALLBACK_TIERS);
    const [loading] = useState(false);

    return (
        <section style={{ padding: '64px 0' }}>
            <div className="max-w-7xl mx-auto px-6">
                {/* Header */}
                <div style={{ textAlign: 'center', marginBottom: 48 }}>
                    <span
                        className="highlight-box"
                        style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4, marginBottom: 12 }}
                    >
                        <Shield style={{ width: 12, height: 12 }} /> Plans & Limits
                    </span>
                    <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
                        Choose Your Plan
                    </h2>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', maxWidth: 480, margin: '0 auto' }}>
                        All plans include full vulnerability detection, AI reasoning, and structured reporting.
                    </p>
                </div>

                {/* Cards grid */}
                {loading ? (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6" style={{ maxWidth: 960, margin: '0 auto' }}>
                        {[1, 2, 3].map((i) => (
                            <div key={i} className="card" style={{ padding: 32 }}>
                                <Skeleton className="h-6 w-24 mb-4" />
                                <Skeleton className="h-4 w-full mb-3" count={5} />
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6" style={{ maxWidth: 960, margin: '0 auto' }}>
                        {tiers.map((tier) => {
                            const meta = TIER_META[tier.name] ?? TIER_META.free;
                            const TierIcon = meta.icon;

                            return (
                                <div
                                    key={tier.name}
                                    className="card animate-fade-in"
                                    style={{
                                        padding: 0, overflow: 'hidden',
                                        border: meta.badge
                                            ? `2px solid ${meta.accent}`
                                            : '1.5px solid var(--border-primary)',
                                        position: 'relative',
                                    }}
                                >
                                    {/* Popular badge */}
                                    {meta.badge && (
                                        <div
                                            style={{
                                                position: 'absolute', top: -1, right: 20,
                                                background: meta.accent,
                                                color: '#fff', fontSize: 10, fontWeight: 700,
                                                padding: '4px 12px', borderRadius: '0 0 8px 8px',
                                                textTransform: 'uppercase', letterSpacing: '0.05em',
                                            }}
                                        >
                                            {meta.badge}
                                        </div>
                                    )}

                                    {/* Card header */}
                                    <div style={{ padding: '28px 24px 20px', background: meta.gradient }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                                            <div
                                                style={{
                                                    width: 36, height: 36, borderRadius: 10,
                                                    background: `${meta.accent}15`,
                                                    border: `1.5px solid ${meta.accent}30`,
                                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                }}
                                            >
                                                <TierIcon style={{ width: 18, height: 18, color: meta.accent }} />
                                            </div>
                                            <h3 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                                                {tier.display_name}
                                            </h3>
                                        </div>
                                        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                                            {tier.name === 'free' && 'Get started for free with essential scanning.'}
                                            {tier.name === 'pro' && 'For teams that need higher limits and priority scanning.'}
                                            {tier.name === 'enterprise' && 'Maximum capacity for large organizations.'}
                                        </p>
                                    </div>

                                    {/* Limits list */}
                                    <div style={{ padding: '20px 24px 24px' }}>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                            {LIMIT_ROWS.map((row) => {
                                                const Icon = row.icon;
                                                const val = tier[row.key];
                                                return (
                                                    <div
                                                        key={row.key}
                                                        style={{
                                                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                                            padding: '8px 12px',
                                                            borderRadius: 'var(--radius-sm)',
                                                            border: '1px solid var(--border-light)',
                                                            background: 'var(--bg-secondary)',
                                                        }}
                                                    >
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                            <Icon
                                                                style={{ width: 14, height: 14, color: 'var(--text-tertiary)', flexShrink: 0 }}
                                                            />
                                                            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                                                                {row.label}
                                                            </span>
                                                        </div>
                                                        <span
                                                            style={{
                                                                fontSize: 13, fontWeight: 700,
                                                                color: 'var(--text-primary)',
                                                                fontFamily: "'JetBrains Mono', monospace",
                                                            }}
                                                        >
                                                            {row.format(val as number | string)}
                                                        </span>
                                                    </div>
                                                );
                                            })}
                                        </div>

                                        {/* All-plans features */}
                                        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-light)' }}>
                                            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: 10, letterSpacing: '0.05em' }}>
                                                Included
                                            </div>
                                            {['AI Reasoning', 'Exploit Examples', 'Secure Rewrites', 'OWASP Mapping'].map((f) => (
                                                <div
                                                    key={f}
                                                    style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}
                                                >
                                                    <Check style={{ width: 14, height: 14, color: '#16A34A', flexShrink: 0 }} />
                                                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{f}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>
        </section>
    );
}
