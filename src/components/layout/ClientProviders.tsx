'use client';

import React, { useEffect } from 'react';
import { ApiEventInterceptor } from '@/components/auth/ApiEventInterceptor';
import { useAuthStore } from '@/store/authStore';

/**
 * ClientProviders — wraps the app with client-side providers.
 * Mounted inside the root layout (a server component).
 */
export function ClientProviders({ children }: { children: React.ReactNode }) {
    const checkAuth = useAuthStore((s) => s.checkAuth);
    const authChecked = useAuthStore((s) => s.authChecked);

    // Verify session once on initial load so Header/landing page reflect real auth state
    useEffect(() => {
        if (!authChecked) {
            checkAuth();
        }
    }, [authChecked, checkAuth]);

    // Disable React DevTools in production to prevent state inspection
    useEffect(() => {
        if (process.env.NODE_ENV === 'production') {
            const w = window as unknown as Record<string, unknown>;
            if (typeof w.__REACT_DEVTOOLS_GLOBAL_HOOK__ === 'object' && w.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
                const hook = w.__REACT_DEVTOOLS_GLOBAL_HOOK__ as Record<string, unknown>;
                hook.inject = () => {};
            }
        }
    }, []);

    return (
        <>
            <ApiEventInterceptor />
            {children}
        </>
    );
}
