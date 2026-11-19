'use client';

import React from 'react';
import Link from 'next/link';
import { useAuthStore } from '@/store/authStore';
import { AUTH_BASE } from '@/api';
import {
  Shield, Cpu, Lock, Eye, Github, ArrowRight, Terminal,
  Layers, Zap, Code, FileSearch, Upload, Database, Key,
  BookOpen, ChevronRight, CheckCircle, Server, Globe,
} from 'lucide-react';
import { PlansSection } from '@/components/landing/PlansSection';

/* ============================================================= */
/*  DATA                                                          */
/* ============================================================= */

const howItWorks = [
  { step: '01', title: 'Connect or Upload', desc: 'Connect your repository or upload your code.', icon: Upload },
  { step: '02', title: 'Chunked Analysis', desc: 'We break your project into structured chunks.', icon: Layers },
  { step: '03', title: 'Rule Engine', desc: 'Rule engine detects common vulnerabilities.', icon: Code },
  { step: '04', title: 'AI Reasoning', desc: 'AI models perform deep security reasoning.', icon: Cpu },
  { step: '05', title: 'Security Report', desc: 'Receive detailed security intelligence report.', icon: Shield },
];

const features = [
  { icon: Cpu, title: 'Hybrid Rule + AI Engine', desc: 'Combines deterministic pattern matching with intelligent AI reasoning for maximum detection accuracy.' },
  { icon: FileSearch, title: 'Full-Stack Detection', desc: 'Scans frontend, backend, API, config files, and dependencies in a single sweep.' },
  { icon: Lock, title: 'Secure & Private Processing', desc: 'Code is encrypted in transit, analyzed in memory, and never permanently stored.' },
  { icon: Github, title: 'GitHub Integration', desc: 'Connect your GitHub repos directly. Scan any branch with one click.' },
  { icon: Shield, title: 'Severity & Risk Scoring', desc: 'Each vulnerability is scored by severity, confidence, and exploitability with OWASP mapping.' },
  { icon: BookOpen, title: 'Structured Security Reports', desc: 'Get actionable reports with remediation guidance, exploit examples, and secure rewrites.' },
];

const securityPoints = [
  { icon: Database, title: 'No Permanent Code Storage', desc: 'Source code is analyzed in-memory and discarded. Only structured scan results are saved.' },
  { icon: Shield, title: 'Authentication Required', desc: 'All scanning operations require OAuth authentication. No anonymous access.' },
  { icon: Server, title: 'Secure Database', desc: 'Scan results are stored in encrypted, production-grade PostgreSQL with connection pooling.' },
  { icon: Key, title: 'Encrypted Tokens', desc: 'OAuth tokens are encrypted at rest using AES-256 encryption.' },
];

const languages = [
  { name: 'JavaScript / TypeScript', emoji: '⚡' },
  { name: 'Python', emoji: '🐍' },
  { name: 'Node.js', emoji: '🟢' },
  { name: 'PHP', emoji: '🐘' },
  { name: 'SQL', emoji: '🗃️' },
  { name: 'Config Files', emoji: '⚙️' },
];

const categories = [
  'Injection (SQL, NoSQL, Command)',
  'Broken Authentication',
  'Access Control Issues',
  'Cross-Site Scripting (XSS)',
  'Secret Exposure',
  'Dependency Risk',
];

/* ============================================================= */
/*  COMPONENT                                                      */
/* ============================================================= */

export default function LandingPage() {
  const { isAuthenticated } = useAuthStore();

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)' }}>
      {/* ─── Header ─── */}
      <header>
        <div style={{ height: 4, background: 'var(--brand-primary)' }} />
        <div style={{ borderBottom: '1.5px solid var(--border-primary)' }}>
          <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-3" style={{ textDecoration: 'none' }}>
              <div style={{
                width: 36, height: 36,
                background: 'var(--brand-primary)',
                border: '1.5px solid var(--border-primary)',
                borderRadius: 'var(--radius-md)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Terminal style={{ width: 18, height: 18 }} />
              </div>
              <span style={{ fontWeight: 700, fontSize: 16, color: 'var(--text-primary)' }}>SecureAI</span>
            </Link>

            <div className="flex items-center gap-3">
              {isAuthenticated ? (
                <Link href="/dashboard" className="btn btn-primary" style={{ padding: '6px 16px', fontSize: 13 }}>
                  Go to Dashboard <ArrowRight style={{ width: 14, height: 14 }} />
                </Link>
              ) : (
                <Link href="/login" className="btn btn-primary" style={{ padding: '6px 16px', fontSize: 13 }}>
                  Sign In <ArrowRight style={{ width: 14, height: 14 }} />
                </Link>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* ─── A. Hero Section ─── */}
      <section className="bg-dots" style={{ paddingTop: 80, paddingBottom: 80 }}>
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            {/* Left */}
            <div className="animate-fade-in-up">
              <div className="flex items-center gap-2 mb-6">
                <span className="highlight-box" style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <Zap style={{ width: 12, height: 12 }} /> AI-Powered
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>v2.0 — Hybrid Engine</span>
              </div>

              <h1 style={{ fontSize: 44, fontWeight: 800, lineHeight: 1.12, letterSpacing: '-0.03em', color: 'var(--text-primary)', marginBottom: 20 }}>
                AI Full-Stack{'\n'}
                <span style={{ position: 'relative', display: 'inline-block' }}>
                  Security Intelligence
                  <svg style={{ position: 'absolute', bottom: -4, left: 0, width: '100%', height: 12 }} viewBox="0 0 300 12" preserveAspectRatio="none">
                    <path d="M0,8 Q75,0 150,8 T300,8" fill="none" stroke="#F5C842" strokeWidth="3" />
                  </svg>
                </span>{' '}
                Platform
              </h1>

              <p style={{ fontSize: 16, color: 'var(--text-secondary)', lineHeight: 1.7, maxWidth: 480, marginBottom: 32 }}>
                Secure your entire codebase using hybrid rule-based and AI reasoning. Detect vulnerabilities across your full stack.
              </p>

              <div className="flex items-center gap-3 flex-wrap">
                {isAuthenticated ? (
                  <Link href="/dashboard" className="btn btn-primary" style={{ padding: '12px 28px', fontSize: 15 }}>
                    <Shield style={{ width: 18, height: 18 }} /> Go to Dashboard
                  </Link>
                ) : (
                  <Link href="/login" className="btn btn-primary" style={{ padding: '12px 28px', fontSize: 15 }}>
                    <Github style={{ width: 18, height: 18 }} /> Get Started
                  </Link>
                )}
              </div>
            </div>

            {/* Right — Terminal preview */}
            <div className="animate-fade-in-up" style={{ animationDelay: '0.15s' }}>
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{
                  background: 'var(--brand-primary)',
                  borderBottom: '1.5px solid var(--border-primary)',
                  padding: '10px 16px',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', border: '1.5px solid var(--border-primary)', background: '#ff5f57' }} />
                    <div style={{ width: 10, height: 10, borderRadius: '50%', border: '1.5px solid var(--border-primary)', background: '#febc2e' }} />
                    <div style={{ width: 10, height: 10, borderRadius: '50%', border: '1.5px solid var(--border-primary)', background: '#28c840' }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginLeft: 8 }}>secureai-scan.sh</span>
                </div>
                <div style={{ padding: 20, background: 'var(--bg-code)', fontFamily: "var(--font-mono), 'JetBrains Mono', monospace", fontSize: 13, lineHeight: 2 }}>
                  <div style={{ color: 'var(--text-tertiary)' }}>$ secureai scan --depth deep</div>
                  <div style={{ color: 'var(--text-secondary)' }}><span style={{ color: '#16A34A' }}>✓</span> Analyzing 127 files...</div>
                  <div style={{ color: 'var(--text-secondary)' }}><span style={{ color: '#16A34A' }}>✓</span> AI reasoning engine active</div>
                  <div style={{ color: 'var(--text-secondary)' }}><span style={{ color: '#D97706' }}>⚠</span> Found 3 vulnerabilities</div>
                  <div style={{ color: 'var(--text-secondary)' }}><span style={{ color: '#DC2626' }}>●</span> SQL Injection — auth.ts:42</div>
                  <div style={{ color: 'var(--text-secondary)' }}><span style={{ color: '#EA580C' }}>●</span> XSS — form.tsx:18</div>
                  <div style={{ color: 'var(--text-secondary)' }}><span style={{ color: '#2563EB' }}>●</span> Info exposure — config.yml:7</div>
                  <div style={{ marginTop: 8, color: '#16A34A', fontWeight: 600 }}>Security Score: 78/100 (Grade B)</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="wavy-separator" />

      {/* ─── B. How It Works ─── */}
      <section style={{ padding: '64px 0' }}>
        <div className="max-w-7xl mx-auto px-6">
          <div style={{ textAlign: 'center', marginBottom: 48 }}>
            <span className="highlight-box" style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4, marginBottom: 12 }}>
              <BookOpen style={{ width: 12, height: 12 }} /> How It Works
            </span>
            <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
              Five Steps to Secure Code
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)', maxWidth: 560, margin: '0 auto' }}>
              From upload to actionable report — our hybrid engine handles everything.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 640, margin: '0 auto' }}>
            {howItWorks.map((s, i) => {
              const Icon = s.icon;
              return (
                <div
                  key={i}
                  className="card"
                  style={{
                    padding: '20px 24px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 20,
                  }}
                >
                  <div style={{
                    width: 44, height: 44,
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--brand-primary)',
                    border: '1.5px solid var(--border-primary)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                    fontWeight: 800, fontSize: 14,
                  }}>
                    <Icon style={{ width: 20, height: 20 }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div className="flex items-center gap-2" style={{ marginBottom: 2 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--brand-primary-dark)', background: 'var(--brand-primary-light)', padding: '2px 8px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-primary)' }}>
                        Step {s.step}
                      </span>
                      <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{s.title}</span>
                    </div>
                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2 }}>{s.desc}</p>
                  </div>
                  <ChevronRight style={{ width: 16, height: 16, color: 'var(--text-tertiary)', flexShrink: 0 }} />
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <div className="wavy-separator" />

      {/* ─── C. Features ─── */}
      <section style={{ padding: '64px 0' }}>
        <div className="max-w-7xl mx-auto px-6">
          <div style={{ textAlign: 'center', marginBottom: 48 }}>
            <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
              Platform Features
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
              Built for developers who take security seriously.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((f, i) => {
              const Icon = f.icon;
              return (
                <div key={i} className="card" style={{ padding: 24 }}>
                  <div style={{
                    width: 44, height: 44,
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--brand-primary)',
                    border: '1.5px solid var(--border-primary)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginBottom: 16,
                  }}>
                    <Icon style={{ width: 22, height: 22 }} />
                  </div>
                  <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>{f.title}</h3>
                  <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{f.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <div className="wavy-separator" />

      {/* ─── D. Security & Privacy ─── */}
      <section style={{ padding: '64px 0' }}>
        <div className="max-w-7xl mx-auto px-6">
          <div style={{ textAlign: 'center', marginBottom: 48 }}>
            <span className="highlight-box" style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4, marginBottom: 12 }}>
              <Lock style={{ width: 12, height: 12 }} /> Security & Privacy
            </span>
            <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
              Your Code is Safe With Us
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)', maxWidth: 560, margin: '0 auto' }}>
              We take data security seriously. Here&apos;s how we protect your source code.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5" style={{ maxWidth: 800, margin: '0 auto' }}>
            {securityPoints.map((s, i) => {
              const Icon = s.icon;
              return (
                <div key={i} className="card" style={{ padding: 24 }}>
                  <div className="flex items-center gap-3" style={{ marginBottom: 12 }}>
                    <div style={{
                      width: 36, height: 36,
                      borderRadius: 'var(--radius-md)',
                      background: 'var(--brand-primary-light)',
                      border: '1.5px solid var(--border-primary)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <Icon style={{ width: 18, height: 18 }} />
                    </div>
                    <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{s.title}</h3>
                  </div>
                  <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{s.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <div className="wavy-separator" />

      {/* ─── Plans & Limits ─── */}
      <PlansSection />

      <div className="wavy-separator" />

      {/* ─── E. Technical Docs ─── */}
      <section style={{ padding: '64px 0' }}>
        <div className="max-w-7xl mx-auto px-6">
          <div style={{ textAlign: 'center', marginBottom: 48 }}>
            <span className="highlight-box" style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4, marginBottom: 12 }}>
              <Code style={{ width: 12, height: 12 }} /> Technical Docs
            </span>
            <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
              What We Scan
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6" style={{ maxWidth: 800, margin: '0 auto' }}>
            {/* Supported Languages */}
            <div className="card" style={{ padding: 24 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Globe style={{ width: 16, height: 16 }} /> Supported Languages
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {languages.map((l, i) => (
                  <div
                    key={i}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-light)',
                      fontSize: 13,
                      fontWeight: 500,
                      color: 'var(--text-primary)',
                    }}
                  >
                    <span style={{ fontSize: 16 }}>{l.emoji}</span>
                    {l.name}
                  </div>
                ))}
              </div>
            </div>

            {/* Detection Categories */}
            <div className="card" style={{ padding: 24 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield style={{ width: 16, height: 16 }} /> Detection Categories
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {categories.map((c, i) => (
                  <div
                    key={i}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-light)',
                      fontSize: 13,
                      fontWeight: 500,
                      color: 'var(--text-primary)',
                    }}
                  >
                    <CheckCircle style={{ width: 14, height: 14, color: '#16A34A', flexShrink: 0 }} />
                    {c}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="wavy-separator" />

      {/* ─── CTA ─── */}
      <section style={{ padding: '64px 0' }}>
        <div className="max-w-7xl mx-auto px-6">
          <div className="card-accent" style={{ padding: '48px 32px', textAlign: 'center' }}>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
              Ready to Secure Your Code?
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 24, maxWidth: 480, margin: '0 auto 24px' }}>
              Sign in to start scanning. Detection is fast, reports are actionable, and your code stays private.
            </p>
            <div className="flex items-center justify-center gap-3 flex-wrap">
              {isAuthenticated ? (
                <Link href="/scan" className="btn btn-dark" style={{ padding: '12px 28px', fontSize: 15 }}>
                  <Shield style={{ width: 18, height: 18 }} /> Start Scanning
                </Link>
              ) : (
                <>
                  <a href={`${AUTH_BASE}/auth/google`} className="btn btn-dark" style={{ padding: '12px 28px', fontSize: 15, textDecoration: 'none' }}>
                    Sign in with Google
                  </a>
                  <a href={`${AUTH_BASE}/auth/github`} className="btn btn-secondary" style={{ padding: '12px 28px', fontSize: 15, textDecoration: 'none' }}>
                    <Github style={{ width: 18, height: 18 }} /> Sign in with GitHub
                  </a>
                </>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* ─── Footer ─── */}
      <footer style={{ borderTop: '1.5px solid var(--border-primary)', padding: '24px 0' }}>
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
            © 2026 SecureAI. Your code is never stored.
          </span>
          <div className="flex items-center gap-2">
            <span className="pill" style={{ fontSize: 11, padding: '4px 10px' }}>
              <Eye style={{ width: 12, height: 12 }} /> Privacy-First
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
