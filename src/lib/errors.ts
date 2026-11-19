/**
 * Centralized Error Handler
 * Maps HTTP status codes to user-friendly messages.
 * Never exposes backend stack traces.
 */

export interface AppError {
    message: string;
    status: number;
    code: string;
    isAuthError: boolean;
}

const ERROR_MAP: Record<number, { message: string; code: string }> = {
    400: { message: 'Invalid request. Please check your input and try again.', code: 'BAD_REQUEST' },
    401: { message: 'Session expired. Please sign in again.', code: 'SESSION_EXPIRED' },
    402: { message: 'This scan exceeds your plan limits. Upgrade or reduce the scan size.', code: 'TIER_EXCEEDED' },
    403: { message: 'Access denied. You do not have permission for this action.', code: 'ACCESS_DENIED' },
    404: { message: 'Resource not found.', code: 'NOT_FOUND' },
    409: { message: 'Conflict. This resource already exists.', code: 'CONFLICT' },
    413: { message: 'File too large. Please reduce file size and try again.', code: 'FILE_TOO_LARGE' },
    422: { message: 'Invalid data format. Please check your input.', code: 'VALIDATION_ERROR' },
    429: { message: 'Too many requests. Please wait a moment and try again.', code: 'RATE_LIMITED' },
    500: { message: 'Internal server error. Please try again later.', code: 'SERVER_ERROR' },
    502: { message: 'Service temporarily unavailable. Please try again later.', code: 'BAD_GATEWAY' },
    503: { message: 'Service under maintenance. Please try again later.', code: 'SERVICE_UNAVAILABLE' },
};

/**
 * Parse an HTTP response into a user-friendly AppError.
 * Extracts `detail` from JSON body if available, falls back to standard message.
 */
export async function parseApiError(res: Response): Promise<AppError> {
    const mapped = ERROR_MAP[res.status] || {
        message: 'An unexpected error occurred.',
        code: 'UNKNOWN',
    };

    // Try to extract a cleaner message from the response body
    let serverMessage: string | undefined;
    try {
        const body = await res.json();
        const detail = body.detail;
        if (typeof detail === 'string' && detail.length < 300) {
            serverMessage = detail;
        } else if (detail && typeof detail === 'object' && typeof detail.message === 'string' && detail.message.length < 300) {
            serverMessage = detail.message;
        }
    } catch {
        // Body not JSON — use mapped message
    }

    return {
        message: serverMessage || mapped.message,
        status: res.status,
        code: mapped.code,
        isAuthError: res.status === 401 || res.status === 403,
    };
}

/**
 * Handle network-level errors (no response received).
 */
export function parseNetworkError(err: unknown): AppError {
    if (err instanceof DOMException && err.name === 'AbortError') {
        return {
            message: 'Request timed out. Please check your connection and try again.',
            status: 0,
            code: 'TIMEOUT',
            isAuthError: false,
        };
    }

    return {
        message: 'Network error. Please check your internet connection.',
        status: 0,
        code: 'NETWORK_ERROR',
        isAuthError: false,
    };
}
