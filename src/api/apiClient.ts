/**
 * Centralized API Client — Production-grade fetch wrapper.
 *
 * Features:
 *   - Automatic token injection via HTTP-only cookies (credentials: 'include')
 *   - Centralized error handling with status-specific behavior
 *   - 401 → auto-logout via auth store
 *   - 403 → permission denied event
 *   - 429 → rate limit warning
 *   - AbortController timeout on every request
 *   - Retry strategy for idempotent GET requests
 *   - CSRF-safe: cookies + SameSite enforcement
 */

import { parseApiError, parseNetworkError, type AppError } from '@/lib/errors';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '/api/v1';
export const AUTH_BASE = API_BASE.replace('/api/v1', '') || '';

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 2;
const RETRY_BACKOFF_MS = 1_000;

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

interface RequestOptions {
  method?: HttpMethod;
  body?: unknown;
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
  signal?: AbortSignal;
}

/** Event emitter for cross-cutting concerns (auth expiry, rate limits, tier blocks). */
type ApiEventType = 'auth_expired' | 'forbidden' | 'rate_limited' | 'tier_exceeded' | 'server_error';
type ApiEventHandler = (error: AppError) => void;

const eventHandlers: Partial<Record<ApiEventType, ApiEventHandler[]>> = {};

export function onApiEvent(event: ApiEventType, handler: ApiEventHandler): () => void {
  if (!eventHandlers[event]) eventHandlers[event] = [];
  eventHandlers[event]!.push(handler);
  return () => {
    eventHandlers[event] = eventHandlers[event]!.filter((h) => h !== handler);
  };
}

function emitApiEvent(event: ApiEventType, error: AppError) {
  eventHandlers[event]?.forEach((h) => {
    try { h(error); } catch { /* swallow handler errors */ }
  });
}

/** UUID v4 format validation (prevents IDOR via malformed IDs). */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidUUID(id: string): boolean {
  return UUID_RE.test(id);
}

export function requireValidUUID(id: string, label = 'ID'): void {
  if (!isValidUUID(id)) {
    throw {
      message: `Invalid ${label} format.`,
      status: 400,
      code: 'INVALID_UUID',
      isAuthError: false,
    } as AppError;
  }
}

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Silent token refresh on 401 ────────────────────────────────
let _refreshPromise: Promise<boolean> | null = null;

/**
 * Attempt to refresh the access token using the refresh_token cookie.
 * Deduplicates concurrent refresh calls so only one request is in-flight.
 * Returns true if refresh succeeded, false otherwise.
 */
async function tryRefreshToken(): Promise<boolean> {
  if (_refreshPromise) return _refreshPromise;

  _refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      return res.ok;
    } catch {
      return false;
    } finally {
      _refreshPromise = null;
    }
  })();

  return _refreshPromise;
}

/**
 * Core request function. All API calls flow through here.
 */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, headers: extraHeaders, timeout = REQUEST_TIMEOUT_MS, signal } = options;
  const maxRetries = method === 'GET' ? (options.retries ?? MAX_RETRIES) : 0;
  // Allow 1 extra attempt for transparent token refresh on 401
  const maxAttempts = maxRetries + 2; // base + retries + 1 refresh retry

  const url = `${API_BASE}${path}`;
  const headers: Record<string, string> = { ...extraHeaders };

  let requestBody: BodyInit | undefined;
  if (body instanceof FormData) {
    requestBody = body;
    // Let browser set Content-Type with boundary
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    requestBody = JSON.stringify(body);
  }

  let lastError: AppError | undefined;
  let didRefresh = false;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    // Link external signal
    if (signal) {
      if (signal.aborted) { clearTimeout(timeoutId); break; }
      signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    try {
      const res = await fetch(url, {
        method,
        headers,
        body: requestBody,
        credentials: 'include',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        if (res.status === 204) return {} as T;
        return await res.json();
      }

      // Parse error
      const appError = await parseApiError(res);

      // Status-specific side-effects
      switch (res.status) {
        case 401: {
          // Try silent token refresh once before giving up
          // Skip refresh for the refresh endpoint itself to avoid infinite loop
          if (!didRefresh && !path.includes('/auth/refresh')) {
            const refreshed = await tryRefreshToken();
            if (refreshed) {
              didRefresh = true;
              continue; // retry with new cookie
            }
          }
          emitApiEvent('auth_expired', appError);
          throw appError;
        }
        case 402:
          emitApiEvent('tier_exceeded', appError);
          throw appError;
        case 403:
          emitApiEvent('forbidden', appError);
          throw appError;
        case 429:
          emitApiEvent('rate_limited', appError);
          throw appError;
        case 500:
        case 502:
        case 503:
          emitApiEvent('server_error', appError);
          lastError = appError;
          // Retry on server errors for GET requests
          if (attempt < maxRetries) {
            await sleep(RETRY_BACKOFF_MS * (attempt + 1));
            continue;
          }
          throw appError;
        default:
          throw appError;
      }
    } catch (err) {
      clearTimeout(timeoutId);
      // Already an AppError
      if (err && typeof err === 'object' && 'code' in err && 'isAuthError' in err) {
        throw err;
      }
      // Network / abort error
      lastError = parseNetworkError(err);
      if (attempt < maxRetries) {
        await sleep(RETRY_BACKOFF_MS * (attempt + 1));
        continue;
      }
      throw lastError;
    }
  }

  throw lastError || parseNetworkError(new Error('Request failed'));
}

// Convenience methods
export const apiGet = <T>(path: string, opts?: Omit<RequestOptions, 'method'>) =>
  apiRequest<T>(path, { ...opts, method: 'GET' });

export const apiPost = <T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
  apiRequest<T>(path, { ...opts, method: 'POST', body });

export const apiPut = <T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
  apiRequest<T>(path, { ...opts, method: 'PUT', body });

export const apiDelete = <T>(path: string, opts?: Omit<RequestOptions, 'method'>) =>
  apiRequest<T>(path, { ...opts, method: 'DELETE' });

/**
 * Validate an image URL to prevent XSS via data: URIs or javascript: protocols.
 * Only allows https:, http: (dev), and relative URLs.
 */
export function safeImageUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url, 'https://placeholder.invalid');
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return url;
    return null;
  } catch {
    // Relative URL — safe
    if (url.startsWith('/')) return url;
    return null;
  }
}
