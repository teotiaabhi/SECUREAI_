'use client';

import React from 'react';

interface TabItem {
    id: string;
    label: string;
    icon?: React.ReactNode;
}

interface TabsProps {
    items: TabItem[];
    activeTab: string;
    onChange: (id: string) => void;
}

export function Tabs({ items, activeTab, onChange }: TabsProps) {
    return (
        <div
            style={{
                display: 'flex',
                borderBottom: '1.5px solid var(--border-primary)',
                background: 'var(--bg-secondary)',
                overflowX: 'auto',
            }}
        >
            {items.map((item) => {
                const isActive = item.id === activeTab;
                return (
                    <button
                        key={item.id}
                        onClick={() => onChange(item.id)}
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                            padding: '12px 20px',
                            fontSize: 13,
                            fontWeight: isActive ? 600 : 500,
                            color: isActive ? 'var(--text-primary)' : 'var(--text-tertiary)',
                            background: 'transparent',
                            border: 'none',
                            borderBottom: isActive ? '3px solid var(--brand-primary)' : '3px solid transparent',
                            cursor: 'pointer',
                            whiteSpace: 'nowrap',
                            transition: 'all 0.15s ease',
                        }}
                    >
                        {item.icon}
                        {item.label}
                    </button>
                );
            })}
        </div>
    );
}
