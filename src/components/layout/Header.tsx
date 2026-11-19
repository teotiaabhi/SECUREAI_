'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuthStore } from '@/store/authStore';
import { LogoutModal } from '@/components/auth/LogoutModal';
import { safeImageUrl } from '@/api/apiClient';
import type { UserRole } from '@/store/authStore';
import {
    LayoutDashboard,
    ScanSearch,
    Shield,
    History,
    GitBranch,
    FileCheck,
    Server,
    LogOut,
    User,
    Terminal,
    Settings,
} from 'lucide-react';

interface NavItem {
    href: string;
    label: string;
    icon: React.ComponentType<{ style?: React.CSSProperties }>;
    roles?: UserRole[];
}

const navItems: NavItem[] = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/scan', label: 'Scan', icon: ScanSearch },
    { href: '/results', label: 'Results', icon: Shield },
    { href: '/history', label: 'History', icon: History },
    { href: '/cicd', label: 'CI/CD', icon: GitBranch },
    { href: '/compliance', label: 'Compliance', icon: FileCheck, roles: ['admin', 'auditor'] },
    { href: '/admin', label: 'Admin', icon: Server, roles: ['admin'] },
];

export function Header() {
    const { isAuthenticated, user, hasRole } = useAuthStore();
    const pathname = usePathname();
    const [showLogoutModal, setShowLogoutModal] = useState(false);

    const visibleNavItems = navItems.filter(
        (item) => !item.roles || hasRole(item.roles),
    );

    return (
        <>
            <header className="sticky top-0 z-50">
                {/* Yellow accent stripe */}
                <div style={{ height: 4, background: 'var(--brand-primary)' }} />

                <div
                    style={{
                        background: 'var(--bg-primary)',
                        borderBottom: '1.5px solid var(--border-primary)',
                    }}
                >
                    <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
                        {/* Logo */}
                        <Link href="/" className="flex items-center gap-3 group" style={{ textDecoration: 'none' }}>
                            <div
                                style={{
                                    width: 36,
                                    height: 36,
                                    background: 'var(--brand-primary)',
                                    border: '1.5px solid var(--border-primary)',
                                    borderRadius: 'var(--radius-md)',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    fontWeight: 800,
                                    fontSize: 14,
                                    color: 'var(--text-primary)',
                                }}
                            >
                                <Terminal style={{ width: 18, height: 18 }} />
                            </div>
                            <span style={{ fontWeight: 700, fontSize: 16, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                                SecureAI
                            </span>
                        </Link>

                        {/* Nav Links */}
                        {isAuthenticated && (
                            <nav className="hidden md:flex items-center gap-1">
                                {visibleNavItems.map((item) => {
                                    const isActive = pathname === item.href;
                                    const Icon = item.icon;
                                    return (
                                        <Link
                                            key={item.href}
                                            href={item.href}
                                            style={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: 6,
                                                padding: '6px 14px',
                                                borderRadius: 'var(--radius-md)',
                                                fontSize: 13,
                                                fontWeight: isActive ? 600 : 500,
                                                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                                                background: isActive ? 'var(--brand-primary-light)' : 'transparent',
                                                border: isActive ? '1.5px solid var(--border-primary)' : '1.5px solid transparent',
                                                textDecoration: 'none',
                                                transition: 'all 0.15s ease',
                                            }}
                                        >
                                            <Icon style={{ width: 16, height: 16 }} />
                                            {item.label}
                                        </Link>
                                    );
                                })}
                            </nav>
                        )}

                        {/* Right side */}
                        <div className="flex items-center gap-2">
                            {isAuthenticated && user ? (
                                <div className="flex items-center gap-2">
                                    {/* User avatar + name */}
                                    <Link
                                        href="/settings"
                                        className="flex items-center gap-2"
                                        style={{ textDecoration: 'none', cursor: 'pointer' }}
                                        title="Settings"
                                    >
                                        {safeImageUrl(user.avatar_url) ? (
                                            <img
                                                src={safeImageUrl(user.avatar_url)!}
                                                alt={user.name}
                                                style={{
                                                    width: 32,
                                                    height: 32,
                                                    borderRadius: 'var(--radius-md)',
                                                    border: '1.5px solid var(--border-primary)',
                                                }}
                                            />
                                        ) : (
                                            <div
                                                style={{
                                                    width: 32,
                                                    height: 32,
                                                    borderRadius: 'var(--radius-md)',
                                                    border: '1.5px solid var(--border-primary)',
                                                    background: 'var(--brand-primary)',
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    justifyContent: 'center',
                                                    fontWeight: 700,
                                                    fontSize: 13,
                                                }}
                                            >
                                                {user.name.charAt(0).toUpperCase()}
                                            </div>
                                        )}
                                        <span className="hidden sm:block" style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                                            {user.name}
                                        </span>
                                    </Link>

                                    {/* Settings button */}
                                    <Link
                                        href="/settings"
                                        style={{
                                            width: 32,
                                            height: 32,
                                            borderRadius: 'var(--radius-md)',
                                            border: `1.5px solid ${pathname === '/settings' ? 'var(--border-primary)' : 'var(--border-light)'}`,
                                            background: pathname === '/settings' ? 'var(--brand-primary-light)' : 'var(--bg-primary)',
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            cursor: 'pointer',
                                            transition: 'all 0.15s ease',
                                            color: 'var(--text-tertiary)',
                                        }}
                                        title="Settings"
                                    >
                                        <Settings style={{ width: 14, height: 14 }} />
                                    </Link>

                                    {/* Logout button */}
                                    <button
                                        onClick={() => setShowLogoutModal(true)}
                                        style={{
                                            width: 32,
                                            height: 32,
                                            borderRadius: 'var(--radius-md)',
                                            border: '1.5px solid var(--border-light)',
                                            background: 'var(--bg-primary)',
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            cursor: 'pointer',
                                            transition: 'all 0.15s ease',
                                            color: 'var(--text-tertiary)',
                                        }}
                                        title="Sign out"
                                    >
                                        <LogOut style={{ width: 14, height: 14 }} />
                                    </button>
                                </div>
                            ) : (
                                <Link
                                    href="/login"
                                    className="btn btn-primary"
                                    style={{ padding: '6px 16px', fontSize: 13 }}
                                >
                                    <User style={{ width: 14, height: 14 }} />
                                    Sign In
                                </Link>
                            )}
                        </div>
                    </div>
                </div>
            </header>

            {/* Logout confirmation modal */}
            <LogoutModal isOpen={showLogoutModal} onClose={() => setShowLogoutModal(false)} />
        </>
    );
}
