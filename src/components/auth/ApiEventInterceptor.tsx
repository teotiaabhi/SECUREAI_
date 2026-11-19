'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { onApiEvent } from '@/api/apiClient';
import { useAuthStore } from '@/store/authStore';

/** Reacts to 401 events from the API client by clearing auth state and redirecting to login. */
export function ApiEventInterceptor() {
    const router = useRouter();

    useEffect(() => {
        return onApiEvent('auth_expired', () => {
            useAuthStore.setState({ isAuthenticated: false, user: null, repos: [], selectedRepo: null, authChecked: true });
            router.replace('/login');
        });
    }, [router]);

    return null;
}
