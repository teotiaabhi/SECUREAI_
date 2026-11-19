'use client';

import React from 'react';

interface ProgressBarProps {
    value: number;
    max?: number;
    label?: string;
    showPercent?: boolean;
}

export function ProgressBar({ value, max = 100, label, showPercent = true }: ProgressBarProps) {
    const percent = Math.min(100, Math.round((value / max) * 100));

    return (
        <div>
            {(label || showPercent) && (
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    {label && <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{label}</span>}
                    {showPercent && <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{percent}%</span>}
                </div>
            )}
            <div
                style={{
                    width: '100%',
                    height: 10,
                    background: 'var(--bg-tertiary)',
                    borderRadius: 999,
                    border: '1.5px solid var(--border-primary)',
                    overflow: 'hidden',
                }}
            >
                <div
                    style={{
                        width: `${percent}%`,
                        height: '100%',
                        background: 'var(--brand-primary)',
                        borderRadius: 999,
                        transition: 'width 0.4s ease',
                    }}
                />
            </div>
        </div>
    );
}
