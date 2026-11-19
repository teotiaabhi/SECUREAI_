'use client';

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense } from 'react';

/**
 * OAuth Callback Page — receives JWT tokens from backend redirect,
 * stores them as same-origin cookies, and redirects to dashboard.
 *
 * This solves the cross-origin cookie problem when backend (port 5000)
 * and frontend (port 3000) run on different ports.
 */
function CallbackHandler() {
    const router = useRouter();
    const searchParams = useSearchParams();

    useEffect(() => {
        router.replace('/dashboard');
    }, [router]);

    return (
        <div style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--bg-secondary)',
        }}>
            <div style={{ textAlign: 'center' }}>
                <div style={{
                    width: 40, height: 40,
                    border: '3px solid var(--border-light)',
                    borderTopColor: 'var(--brand-primary)',
                    borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite',
                    margin: '0 auto 16px',
                }} />
                <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
                    Completing sign in...
                </p>
            </div>
        </div>
    );
}

export default function AuthCallbackPage() {
    return (
        <Suspense fallback={
            <div style={{
                minHeight: '100vh',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
            }}>
                <p>Loading...</p>
            </div>
        }>
            <CallbackHandler />
        </Suspense>
    );
}
