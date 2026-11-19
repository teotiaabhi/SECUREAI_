'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/store/authStore';
import { LogOut, Loader2 } from 'lucide-react';

/**
 * LogoutModal — confirmation dialog before signing out.
 * Calls backend POST /auth/logout, clears state, redirects to /dashboard.
 */
export function LogoutModal({
    isOpen,
    onClose,
}: {
    isOpen: boolean;
    onClose: () => void;
}) {
    const { logout } = useAuthStore();
    const router = useRouter();
    const [loading, setLoading] = useState(false);

    if (!isOpen) return null;

    const handleLogout = async () => {
        if (loading) return; // prevent double-click
        setLoading(true);
        try {
            await logout();
            router.push('/dashboard');
        } catch {
            // Even on network error, clear local state and redirect
            router.push('/dashboard');
        } finally {
            setLoading(false);
            onClose();
        }
    };

    return (
        <div
            style={{
                position: 'fixed',
                inset: 0,
                zIndex: 100,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'rgba(0,0,0,0.35)',
                animation: 'fadeIn 0.15s ease',
            }}
            onClick={onClose}
        >
            <div
                className="card"
                style={{
                    maxWidth: 400,
                    width: '90%',
                    padding: 32,
                    textAlign: 'center',
                    animation: 'slideUp 0.2s ease',
                }}
                onClick={(e) => e.stopPropagation()}
            >
                <div style={{
                    width: 48, height: 48,
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--brand-primary)',
                    border: '1.5px solid var(--border-primary)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 16px',
                }}>
                    <LogOut style={{ width: 22, height: 22 }} />
                </div>

                <h3 style={{
                    fontSize: 18,
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                    marginBottom: 8,
                }}>
                    Confirm Sign Out
                </h3>
                <p style={{
                    fontSize: 13,
                    color: 'var(--text-secondary)',
                    marginBottom: 24,
                    lineHeight: 1.6,
                }}>
                    Are you sure you want to sign out of your account?
                </p>

                <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
                    <button
                        onClick={onClose}
                        disabled={loading}
                        className="btn btn-secondary"
                        style={{ padding: '10px 24px', fontSize: 13, flex: 1 }}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleLogout}
                        disabled={loading}
                        className="btn btn-primary"
                        style={{
                            padding: '10px 24px',
                            fontSize: 13,
                            flex: 1,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                            opacity: loading ? 0.7 : 1,
                        }}
                    >
                        {loading ? (
                            <>
                                <Loader2 style={{ width: 14, height: 14, animation: 'spin 0.8s linear infinite' }} />
                                Signing out...
                            </>
                        ) : (
                            'Yes, Sign Out'
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
}
