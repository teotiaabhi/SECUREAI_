'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { LogoutModal } from '@/components/auth/LogoutModal';
import { useAuthStore } from '@/store/authStore';
import { safeImageUrl } from '@/api/apiClient';
import {
    User, Mail, Shield, Calendar, BarChart3,
    Save, CheckCircle, AlertCircle, LogOut, Settings, Loader2,
} from 'lucide-react';

export default function SettingsPage() {
    return (
        <AuthGuard>
            <SettingsContent />
        </AuthGuard>
    );
}

function SettingsContent() {
    const { user, updateUser, error, clearError } = useAuthStore();
    const [name, setName] = useState(user?.name || '');
    const [saving, setSaving] = useState(false);
    const [success, setSuccess] = useState(false);
    const [stats] = useState<{ total_scans: number; created_at: string | null } | null>(
        { total_scans: 12, created_at: '2024-01-15T00:00:00Z' }
    );
    const [showLogoutModal, setShowLogoutModal] = useState(false);

    useEffect(() => {
        if (user) setName(user.name);
    }, [user]);

    const handleSave = async () => {
        if (saving || !name.trim()) return;
        setSaving(true);
        setSuccess(false);
        clearError();
        try {
            await updateUser({ name: name.trim() });
            setSuccess(true);
            setTimeout(() => setSuccess(false), 3000);
        } catch {
            // error is set in store
        } finally {
            setSaving(false);
        }
    };

    if (!user) return null;

    const providerLabel = user.provider === 'google' ? 'Google' : user.provider === 'github' ? 'GitHub' : user.provider;
    const memberSince = user.created_at
        ? new Date(user.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
        : 'Unknown';

    return (
        <AppShell>
            <div style={{ maxWidth: 720, margin: '0 auto' }}>
                {/* Header */}
                <div className="animate-fade-in" style={{ marginBottom: 32 }}>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Settings style={{ width: 14, height: 14 }} /> Settings
                        </div>
                    </div>
                    <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                        Account Settings
                    </h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                        Manage your profile and account preferences
                    </p>
                </div>

                {/* Profile Section */}
                <div className="card animate-fade-in-up" style={{ padding: 28, marginBottom: 16 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <User style={{ width: 18, height: 18 }} /> Profile Information
                    </h2>

                    <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', marginBottom: 24 }}>
                        {/* Avatar */}
                        {safeImageUrl(user.avatar_url) ? (
                            <img
                                src={safeImageUrl(user.avatar_url)!}
                                alt={user.name}
                                style={{
                                    width: 64, height: 64,
                                    borderRadius: 'var(--radius-md)',
                                    border: '1.5px solid var(--border-primary)',
                                    flexShrink: 0,
                                }}
                            />
                        ) : (
                            <div style={{
                                width: 64, height: 64,
                                borderRadius: 'var(--radius-md)',
                                border: '1.5px solid var(--border-primary)',
                                background: 'var(--brand-primary)',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                fontWeight: 800, fontSize: 24,
                                flexShrink: 0,
                            }}>
                                {user.name.charAt(0).toUpperCase()}
                            </div>
                        )}

                        <div style={{ flex: 1 }}>
                            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                                Display Name
                            </p>
                            <input
                                type="text"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                style={{
                                    width: '100%',
                                    padding: '10px 14px',
                                    fontSize: 14,
                                    fontWeight: 500,
                                    color: 'var(--text-primary)',
                                    background: 'var(--bg-primary)',
                                    border: '1.5px solid var(--border-primary)',
                                    borderRadius: 'var(--radius-md)',
                                    outline: 'none',
                                    transition: 'border-color 0.15s ease',
                                }}
                                onFocus={(e) => (e.target.style.borderColor = 'var(--brand-primary-dark)')}
                                onBlur={(e) => (e.target.style.borderColor = 'var(--border-primary)')}
                                placeholder="Your display name"
                            />
                        </div>
                    </div>

                    {/* Read-only fields */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" style={{ marginBottom: 20 }}>
                        <div style={{
                            padding: '12px 14px',
                            border: '1px solid var(--border-light)',
                            borderRadius: 'var(--radius-md)',
                            background: 'var(--bg-secondary)',
                        }}>
                            <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
                                <Mail style={{ width: 12, height: 12, color: 'var(--text-tertiary)' }} />
                                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Email</span>
                            </div>
                            <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{user.email}</p>
                        </div>
                        <div style={{
                            padding: '12px 14px',
                            border: '1px solid var(--border-light)',
                            borderRadius: 'var(--radius-md)',
                            background: 'var(--bg-secondary)',
                        }}>
                            <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
                                <Shield style={{ width: 12, height: 12, color: 'var(--text-tertiary)' }} />
                                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Provider</span>
                            </div>
                            <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{providerLabel}</p>
                        </div>
                    </div>

                    {/* Success / Error messages */}
                    {success && (
                        <div style={{
                            padding: '10px 14px',
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid #16A34A',
                            background: '#F0FFF4',
                            display: 'flex', alignItems: 'center', gap: 8,
                            marginBottom: 16,
                            fontSize: 13, fontWeight: 500, color: '#16A34A',
                        }}>
                            <CheckCircle style={{ width: 16, height: 16 }} /> Profile updated successfully
                        </div>
                    )}
                    {error && (
                        <div style={{
                            padding: '10px 14px',
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid #DC2626',
                            background: '#FFF5F5',
                            display: 'flex', alignItems: 'center', gap: 8,
                            marginBottom: 16,
                            fontSize: 13, fontWeight: 500, color: '#DC2626',
                        }}>
                            <AlertCircle style={{ width: 16, height: 16 }} /> {error}
                        </div>
                    )}

                    {/* Save button */}
                    <button
                        onClick={handleSave}
                        disabled={saving || name.trim() === user.name}
                        className="btn btn-primary"
                        style={{
                            padding: '10px 24px',
                            fontSize: 13,
                            opacity: (saving || name.trim() === user.name) ? 0.6 : 1,
                            display: 'flex', alignItems: 'center', gap: 6,
                        }}
                    >
                        {saving ? (
                            <><Loader2 style={{ width: 14, height: 14, animation: 'spin 0.8s linear infinite' }} /> Saving...</>
                        ) : (
                            <><Save style={{ width: 14, height: 14 }} /> Update Profile</>
                        )}
                    </button>
                </div>

                {/* Account Info Section */}
                <div className="card animate-fade-in-up" style={{ padding: 28, marginBottom: 16, animationDelay: '0.1s' }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <BarChart3 style={{ width: 18, height: 18 }} /> Account Info
                    </h2>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div style={{
                            padding: '16px 14px',
                            border: '1.5px solid var(--border-primary)',
                            borderRadius: 'var(--radius-md)',
                            textAlign: 'center',
                        }}>
                            <Calendar style={{ width: 20, height: 20, color: 'var(--text-tertiary)', margin: '0 auto 8px' }} />
                            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                                Member Since
                            </p>
                            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                                {memberSince}
                            </p>
                        </div>

                        <div style={{
                            padding: '16px 14px',
                            border: '1.5px solid var(--border-primary)',
                            borderRadius: 'var(--radius-md)',
                            textAlign: 'center',
                        }}>
                            <BarChart3 style={{ width: 20, height: 20, color: 'var(--text-tertiary)', margin: '0 auto 8px' }} />
                            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                                Total Scans
                            </p>
                            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                                {stats?.total_scans ?? '—'}
                            </p>
                        </div>

                        <div style={{
                            padding: '16px 14px',
                            border: '1.5px solid var(--border-primary)',
                            borderRadius: 'var(--radius-md)',
                            textAlign: 'center',
                        }}>
                            <Shield style={{ width: 20, height: 20, color: 'var(--text-tertiary)', margin: '0 auto 8px' }} />
                            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                                Auth Provider
                            </p>
                            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                                {providerLabel} OAuth
                            </p>
                        </div>
                    </div>
                </div>

                {/* Security Section */}
                <div className="card animate-fade-in-up" style={{ padding: 28, animationDelay: '0.2s' }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Shield style={{ width: 18, height: 18 }} /> Security
                    </h2>

                    <div style={{
                        padding: '16px 20px',
                        border: '1.5px solid var(--border-primary)',
                        borderRadius: 'var(--radius-md)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                    }}>
                        <div>
                            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                                Sign Out
                            </p>
                            <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                                End your current session and return to the landing page.
                            </p>
                        </div>
                        <button
                            onClick={() => setShowLogoutModal(true)}
                            className="btn btn-secondary"
                            style={{
                                padding: '8px 16px',
                                fontSize: 12,
                                display: 'flex', alignItems: 'center', gap: 6,
                                flexShrink: 0,
                            }}
                        >
                            <LogOut style={{ width: 14, height: 14 }} />
                            Sign Out
                        </button>
                    </div>
                </div>
            </div>

            <LogoutModal isOpen={showLogoutModal} onClose={() => setShowLogoutModal(false)} />
        </AppShell>
    );
}
