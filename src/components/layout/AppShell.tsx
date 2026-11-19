'use client';

import React from 'react';
import { Header } from '@/components/layout/Header';

export function AppShell({ children }: { children: React.ReactNode }) {
    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)' }}>
            <Header />
            <main className="max-w-7xl mx-auto px-6 py-8">{children}</main>
        </div>
    );
}
