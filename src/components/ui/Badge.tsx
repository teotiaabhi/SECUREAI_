'use client';

import React from 'react';

interface BadgeProps {
    variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'default';
    children: React.ReactNode;
}

export function Badge({ variant = 'default', children }: BadgeProps) {
    if (variant === 'default') {
        return (
            <span
                style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-light)',
                    background: 'var(--bg-tertiary)',
                    fontSize: 11,
                    fontWeight: 600,
                    color: 'var(--text-secondary)',
                }}
            >
                {children}
            </span>
        );
    }

    return <span className={`badge-${variant}`}>{children}</span>;
}
