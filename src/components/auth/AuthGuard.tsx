'use client';
import React, { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuthStore, type UserRole } from '@/store/authStore';

interface AuthGuardProps {
    children: React.ReactNode;
    requiredRole?: UserRole | UserRole[];
    requiredPermission?: string;
}

export function AuthGuard({ children, requiredRole }: AuthGuardProps) {
    const router = useRouter();
    const pathname = usePathname();
    const { isAuthenticated, authChecked, checkAuth, hasRole } = useAuthStore();

    useEffect(() => {
        if (!authChecked) {
            checkAuth();
        }
    }, [authChecked, checkAuth]);

    useEffect(() => {
        if (authChecked && !isAuthenticated) {
            router.replace(`/login?next=${encodeURIComponent(pathname)}`);
        }
    }, [authChecked, isAuthenticated, router, pathname]);

    if (!authChecked) {
        return (
            <div style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div className="animate-pulse" style={{ color: 'var(--text-tertiary)', fontSize: 14 }}>
                    Checking session…
                </div>
            </div>
        );
    }

    if (!isAuthenticated) {
        return null;
    }

    if (requiredRole && !hasRole(requiredRole)) {
        router.replace('/dashboard');
        return null;
    }

    return <>{children}</>;
}
