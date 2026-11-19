import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === 'development';

const apiOrigin = process.env.NEXT_PUBLIC_API_URL
  ? new URL(process.env.NEXT_PUBLIC_API_URL).origin
  : '';

const connectSrcOrigins = [
  "'self'",
  apiOrigin,
  'https://api.github.com',
  ...(isDev ? ['http://localhost:5000'] : []),
].filter(Boolean).join(' ');

const scriptSrc = isDev
  ? "script-src 'self' 'unsafe-eval' 'unsafe-inline'"
  : "script-src 'self'";

const securityHeaders = [
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block',
  },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      scriptSrc,
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https: blob:",
      `connect-src ${connectSrcOrigins}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; '),
  },
];

const nextConfig: NextConfig = {
  // Disable strict mode double-rendering in dev for faster UI
  reactStrictMode: false,
  // Remove X-Powered-By header
  poweredByHeader: false,
  // Enable gzip compression
  compress: true,
  // Keep proxy connections alive to reduce connection churn with the backend
  httpAgentOptions: { keepAlive: true },
  experimental: {
    // Match backend's 500MB ZIP upload limit — default proxy buffer is only 10MB
    proxyClientMaxBodySize: '500mb',
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
  async rewrites() {
    // Proxy /api/v1/* and /auth/* to the backend so cookies stay same-origin
    const backendUrl = process.env.NEXT_PUBLIC_API_URL
      ? new URL(process.env.NEXT_PUBLIC_API_URL).origin
      : 'http://localhost:5000';
    return [
      {
        source: '/api/v1/:path*',
        destination: `${backendUrl}/api/v1/:path*`,
      },
      {
        source: '/auth/:path*',
        destination: `${backendUrl}/auth/:path*`,
      },
    ];
  },
};

export default nextConfig;
