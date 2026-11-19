'use client';

import React from 'react';
import { Shield, ScanSearch, FileSearch, Inbox } from 'lucide-react';

interface EmptyStateProps {
    icon?: 'shield' | 'scan' | 'search' | 'inbox';
    title: string;
    description: string;
    action?: React.ReactNode;
}

const icons = {
    shield: Shield,
    scan: ScanSearch,
    search: FileSearch,
    inbox: Inbox,
};

export function EmptyState({ icon = 'inbox', title, description, action }: EmptyStateProps) {
    const Icon = icons[icon];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 64, textAlign: 'center' }}>
            <div
                style={{
                    width: 64, height: 64,
                    borderRadius: 'var(--radius-lg)',
                    background: 'var(--brand-primary-light)',
                    border: '1.5px solid var(--border-primary)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginBottom: 20,
                }}
            >
                <Icon style={{ width: 28, height: 28, color: 'var(--text-secondary)' }} />
            </div>
            <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>{title}</h3>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)', maxWidth: 360, marginBottom: 20 }}>{description}</p>
            {action}
        </div>
    );
}
