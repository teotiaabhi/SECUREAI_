'use client';

import React, { useState } from 'react';
import { Vulnerability } from '@/store/scanStore';
import { Badge } from '@/components/ui/Badge';
import { Copy, Check, Shield, Code, Wrench, BookOpen, AlertTriangle, ChevronRight } from 'lucide-react';

interface SecureFixPanelProps {
    vulnerability: Vulnerability;
    remediationFix: {
        vulnerableCode: string;
        secureFix: string;
        fixExplanation: string;
        securityPrinciple: string;
        bestPractice: string;
        confidence: number;
    } | null;
}

export function SecureFixPanel({ vulnerability, remediationFix }: SecureFixPanelProps) {
    const [copiedField, setCopiedField] = useState<string | null>(null);

    const copyToClipboard = (text: string, field: string) => {
        navigator.clipboard.writeText(text);
        setCopiedField(field);
        setTimeout(() => setCopiedField(null), 2000);
    };

    const CopyButton = ({ text, field }: { text: string; field: string }) => (
        <button
            onClick={() => copyToClipboard(text, field)}
            style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '4px 10px', fontSize: 11, fontWeight: 600,
                background: copiedField === field ? 'rgba(22, 163, 74, 0.1)' : 'var(--bg-secondary)',
                border: `1px solid ${copiedField === field ? '#16A34A' : 'var(--border-light)'}`,
                borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                color: copiedField === field ? '#16A34A' : 'var(--text-secondary)',
                transition: 'all 0.15s ease',
            }}
        >
            {copiedField === field
                ? <><Check style={{ width: 12, height: 12 }} /> Copied</>
                : <><Copy style={{ width: 12, height: 12 }} /> Copy</>
            }
        </button>
    );

    // If no enrichment data, show basic remediation from the vulnerability
    if (!remediationFix) {
        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {vulnerability.securePatch && (
                    <div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                                <Wrench style={{ width: 14, height: 14, color: '#16A34A' }} /> Remediation
                            </h4>
                            <CopyButton text={vulnerability.securePatch} field="patch" />
                        </div>
                        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>{vulnerability.securePatch}</p>
                    </div>
                )}
                {vulnerability.exploitExample && (
                    <div>
                        <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                            <AlertTriangle style={{ width: 14, height: 14, color: 'var(--severity-high)' }} /> Exploit Example
                        </h4>
                        <div className="code-block" style={{ padding: 16 }}>
                            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                {vulnerability.exploitExample}
                            </pre>
                        </div>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Fix confidence */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield style={{ width: 16, height: 16, color: '#16A34A' }} />
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>Fix Confidence:</span>
                <Badge variant={remediationFix.confidence >= 80 ? 'low' : remediationFix.confidence >= 50 ? 'medium' : 'high'}>
                    {remediationFix.confidence}%
                </Badge>
            </div>

            {/* Vulnerable Code */}
            <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--severity-critical)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <AlertTriangle style={{ width: 14, height: 14 }} /> Vulnerable Code
                    </h4>
                    <CopyButton text={remediationFix.vulnerableCode} field="vuln" />
                </div>
                <div className="code-block" style={{ padding: 16, borderColor: 'var(--severity-critical)' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-primary)' }}>
                        {remediationFix.vulnerableCode}
                    </pre>
                </div>
            </div>

            {/* Arrow */}
            <div style={{ display: 'flex', justifyContent: 'center' }}>
                <div style={{
                    display: 'flex', alignItems: 'center', gap: 6, padding: '6px 16px',
                    background: 'rgba(22, 163, 74, 0.1)', borderRadius: 999,
                    border: '1px solid rgba(22, 163, 74, 0.3)',
                }}>
                    <ChevronRight style={{ width: 14, height: 14, color: '#16A34A' }} />
                    <span style={{ fontSize: 11, fontWeight: 700, color: '#16A34A', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Secure Fix
                    </span>
                    <ChevronRight style={{ width: 14, height: 14, color: '#16A34A' }} />
                </div>
            </div>

            {/* Secure Fix */}
            <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <h4 style={{ fontSize: 13, fontWeight: 700, color: '#16A34A', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Code style={{ width: 14, height: 14 }} /> Secure Code
                    </h4>
                    <CopyButton text={remediationFix.secureFix} field="fix" />
                </div>
                <div className="code-block" style={{ padding: 16, borderColor: '#16A34A' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-primary)' }}>
                        {remediationFix.secureFix}
                    </pre>
                </div>
            </div>

            {/* Explanation */}
            <div style={{ padding: 16, borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)', border: '1.5px solid var(--border-light)' }}>
                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <BookOpen style={{ width: 14, height: 14 }} /> Fix Explanation
                </h4>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>{remediationFix.fixExplanation}</p>
            </div>

            {/* Security Principle & Best Practice */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'rgba(37, 99, 235, 0.05)', border: '1px solid rgba(37, 99, 235, 0.2)' }}>
                    <p style={{ fontSize: 10, fontWeight: 700, color: '#2563EB', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                        Security Principle
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{remediationFix.securityPrinciple}</p>
                </div>
                <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'rgba(124, 58, 237, 0.05)', border: '1px solid rgba(124, 58, 237, 0.2)' }}>
                    <p style={{ fontSize: 10, fontWeight: 700, color: '#7C3AED', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                        Best Practice
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{remediationFix.bestPractice}</p>
                </div>
            </div>
        </div>
    );
}
