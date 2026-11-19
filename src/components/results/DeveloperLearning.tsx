'use client';

import React from 'react';
import { AlertTriangle, BookOpen, Shield, Bug, ExternalLink, Lightbulb, Target, Zap } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import type { SeverityLevel } from '@/types/security';

interface DeveloperExplanation {
    ruleId: string;
    vulnerabilityType: string;
    severity: string;
    whyDangerous: string;
    realWorldExploit: string;
    attackerScenario: string;
    secureFix: string;
    secureCodeExample: string;
    commonMistakes: string[];
    references: string[];
    severityGuidance: string;
    detectionLayerInfo: string;
}

interface DeveloperLearningProps {
    explanation: DeveloperExplanation | null;
    vulnerabilityType: string;
    severity: SeverityLevel;
}

export function DeveloperLearning({ explanation, vulnerabilityType, severity }: DeveloperLearningProps) {
    if (!explanation) {
        return (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-tertiary)' }}>
                <BookOpen style={{ width: 32, height: 32, margin: '0 auto 12px', opacity: 0.5 }} />
                <p style={{ fontSize: 13, fontWeight: 500 }}>Learning content not available for this vulnerability.</p>
                <p style={{ fontSize: 12, marginTop: 4 }}>Enrichment data will be generated when the backend supports it.</p>
            </div>
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <BookOpen style={{ width: 18, height: 18, color: 'var(--brand-primary-dark)' }} />
                <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>
                    Security Learning: {vulnerabilityType}
                </span>
                <Badge variant={severity}>{severity}</Badge>
            </div>

            {/* Why This Is Dangerous */}
            <Section
                icon={<AlertTriangle style={{ width: 14, height: 14, color: 'var(--severity-critical)' }} />}
                title="Why This Is Dangerous"
                color="var(--severity-critical)"
            >
                <p style={textStyle}>{explanation.whyDangerous}</p>
            </Section>

            {/* Real-World Exploit */}
            <Section
                icon={<Zap style={{ width: 14, height: 14, color: 'var(--severity-high)' }} />}
                title="Real-World Exploit"
                color="var(--severity-high)"
            >
                <p style={textStyle}>{explanation.realWorldExploit}</p>
            </Section>

            {/* Attacker Scenario */}
            <Section
                icon={<Target style={{ width: 14, height: 14, color: 'var(--severity-medium)' }} />}
                title="How an Attacker Would Exploit This"
                color="var(--severity-medium)"
            >
                <p style={textStyle}>{explanation.attackerScenario}</p>
            </Section>

            {/* Secure Fix Guidance */}
            <Section
                icon={<Shield style={{ width: 14, height: 14, color: '#16A34A' }} />}
                title="Secure Fix"
                color="#16A34A"
            >
                <p style={textStyle}>{explanation.secureFix}</p>
                {explanation.secureCodeExample && (
                    <div className="code-block" style={{ padding: 14, marginTop: 8 }}>
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12 }}>
                            {explanation.secureCodeExample}
                        </pre>
                    </div>
                )}
            </Section>

            {/* Common Mistakes */}
            {explanation.commonMistakes.length > 0 && (
                <Section
                    icon={<Bug style={{ width: 14, height: 14, color: 'var(--severity-medium)' }} />}
                    title="Common Mistakes"
                    color="var(--severity-medium)"
                >
                    <ul style={{ margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {explanation.commonMistakes.map((mistake, i) => (
                            <li key={i} style={{ ...textStyle, listStyleType: 'disc' }}>{mistake}</li>
                        ))}
                    </ul>
                </Section>
            )}

            {/* Severity Guidance */}
            <Section
                icon={<Lightbulb style={{ width: 14, height: 14, color: 'var(--brand-primary-dark)' }} />}
                title="Severity Context"
                color="var(--brand-primary-dark)"
            >
                <p style={textStyle}>{explanation.severityGuidance}</p>
                {explanation.detectionLayerInfo && (
                    <p style={{ ...textStyle, marginTop: 6, fontStyle: 'italic' }}>
                        Detection: {explanation.detectionLayerInfo}
                    </p>
                )}
            </Section>

            {/* References */}
            {explanation.references.length > 0 && (
                <div>
                    <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <ExternalLink style={{ width: 14, height: 14 }} /> References
                    </h4>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {explanation.references.map((ref, i) => (
                            <span key={i} style={{
                                display: 'inline-flex', alignItems: 'center', gap: 4,
                                padding: '4px 10px', fontSize: 11, fontWeight: 500,
                                background: 'var(--bg-tertiary)', border: '1px solid var(--border-light)',
                                borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)',
                            }}>
                                {ref}
                            </span>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

const textStyle: React.CSSProperties = {
    fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0,
};

function Section({ icon, title, color, children }: {
    icon: React.ReactNode; title: string; color: string; children: React.ReactNode;
}) {
    return (
        <div style={{
            padding: 16, borderRadius: 'var(--radius-md)',
            background: 'var(--bg-secondary)', border: '1.5px solid var(--border-light)',
            borderLeft: `3px solid ${color}`,
        }}>
            <h4 style={{
                fontSize: 13, fontWeight: 700, color: 'var(--text-primary)',
                display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10,
            }}>
                {icon} {title}
            </h4>
            {children}
        </div>
    );
}
