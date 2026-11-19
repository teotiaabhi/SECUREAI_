'use client';

import React from 'react';

/**
 * Reusable skeleton loading components.
 * Consistent loading state across dashboard, history, and results.
 */

export function SkeletonPulse({
    width = '100%',
    height = 16,
    borderRadius = 'var(--radius-sm)',
    style,
}: {
    width?: string | number;
    height?: string | number;
    borderRadius?: string;
    style?: React.CSSProperties;
}) {
    return (
        <div
            style={{
                width,
                height,
                borderRadius,
                background: 'linear-gradient(90deg, var(--bg-secondary) 25%, var(--border-light) 50%, var(--bg-secondary) 75%)',
                backgroundSize: '200% 100%',
                animation: 'shimmer 1.5s ease-in-out infinite',
                ...style,
            }}
        />
    );
}

export function SkeletonText({ lines = 3, width = '100%' }: { lines?: number; width?: string }) {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, width }}>
            {Array.from({ length: lines }).map((_, i) => (
                <SkeletonPulse
                    key={i}
                    height={12}
                    width={i === lines - 1 ? '60%' : '100%'}
                />
            ))}
        </div>
    );
}

export function SkeletonCard({ height = 120 }: { height?: number }) {
    return (
        <div
            className="card"
            style={{ padding: 20, height }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                <SkeletonPulse width={40} height={40} borderRadius="var(--radius-md)" />
                <div style={{ flex: 1 }}>
                    <SkeletonPulse width="40%" height={14} style={{ marginBottom: 6 }} />
                    <SkeletonPulse width="70%" height={10} />
                </div>
            </div>
            <SkeletonText lines={2} />
        </div>
    );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
    return (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            {/* Header */}
            <div style={{
                padding: '12px 20px',
                borderBottom: '1px solid var(--border-light)',
                display: 'flex', gap: 16,
            }}>
                {[120, 80, 100, 60].map((w, i) => (
                    <SkeletonPulse key={i} width={w} height={12} />
                ))}
            </div>
            {/* Rows */}
            {Array.from({ length: rows }).map((_, i) => (
                <div key={i} style={{
                    padding: '14px 20px',
                    borderBottom: i < rows - 1 ? '1px solid var(--border-light)' : 'none',
                    display: 'flex', gap: 16, alignItems: 'center',
                }}>
                    <SkeletonPulse width={140} height={12} />
                    <SkeletonPulse width={80} height={12} />
                    <SkeletonPulse width={100} height={12} />
                    <SkeletonPulse width={60} height={12} />
                </div>
            ))}
        </div>
    );
}

export function SkeletonDashboard() {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Stat cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <SkeletonCard height={100} />
                <SkeletonCard height={100} />
                <SkeletonCard height={100} />
            </div>
            {/* Table */}
            <SkeletonTable rows={4} />
        </div>
    );
}

/**
 * Generic Skeleton — backwards-compatible with existing usage:
 *   <Skeleton className="h-28" count={4} />
 * Renders `count` shimmer blocks matching Tailwind height classes.
 */
export function Skeleton({
    className = '',
    count = 1,
}: {
    className?: string;
    count?: number;
}) {
    // Parse Tailwind-like h-* classes to pixel height
    const match = className.match(/h-(\d+)/);
    const height = match ? parseInt(match[1], 10) * 4 : 48;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {Array.from({ length: count }).map((_, i) => (
                <SkeletonPulse
                    key={i}
                    height={height}
                    borderRadius="var(--radius-md)"
                />
            ))}
        </div>
    );
}
