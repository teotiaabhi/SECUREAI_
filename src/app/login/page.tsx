'use client';

import React, { Suspense, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Terminal, Shield, Github } from 'lucide-react';
import { GOOGLE_LOGIN_URL, GITHUB_LOGIN_URL } from '@/api/auth';
import { useAuthStore } from '@/store/authStore';

function LoginContent() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const { isAuthenticated, authChecked, checkAuth } = useAuthStore();

    useEffect(() => {
        if (!authChecked) checkAuth();
    }, [authChecked, checkAuth]);

    useEffect(() => {
        if (authChecked && isAuthenticated) {
            const next = searchParams.get('next');
            router.replace(next && next.startsWith('/') ? next : '/dashboard');
        }
    }, [authChecked, isAuthenticated, router, searchParams]);

    if (!authChecked || isAuthenticated) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-secondary)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ width: 32, height: 32, border: '3px solid var(--border-light)', borderTopColor: 'var(--brand-primary)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                <p style={{ marginTop: 16, fontSize: 14, color: 'var(--text-secondary)' }}>Checking session...</p>
            </div>
        );
    }

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-secondary)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
                <div style={{ width: 36, height: 36, background: 'var(--brand-primary)', border: '1.5px solid var(--border-primary)', borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Terminal style={{ width: 18, height: 18 }} />
                </div>
                <span style={{ fontWeight: 700, fontSize: 16, color: 'var(--text-primary)' }}>SecureAI</span>
            </div>

            <div className="card" style={{ maxWidth: 380, width: '100%', padding: 32, textAlign: 'center' }}>
                <Shield style={{ width: 32, height: 32, margin: '0 auto 12px' }} />
                <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4, color: 'var(--text-primary)' }}>Sign in to SecureAI</h1>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 24 }}>
                    Authentication is required to access scans and the dashboard.
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <a href={GOOGLE_LOGIN_URL} className="btn btn-dark" style={{ padding: '12px 20px', fontSize: 14, textDecoration: 'none' }}>
                        Sign in with Google
                    </a>
                    <a href={GITHUB_LOGIN_URL} className="btn btn-secondary" style={{ padding: '12px 20px', fontSize: 14, textDecoration: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                        <Github style={{ width: 16, height: 16 }} />
                        Sign in with GitHub
                    </a>
                </div>
            </div>
        </div>
    );
}

export default function LoginPage() {
    return (
        <Suspense>
            <LoginContent />
        </Suspense>
    );
}
