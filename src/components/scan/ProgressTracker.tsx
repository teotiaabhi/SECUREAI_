'use client';

import React, { useEffect } from 'react';
import { useScanStore, ScanPhase } from '@/store/scanStore';
import { ProgressBar } from '@/components/ui/ProgressBar';
import {
    Upload, Search, Brain, FileText, CheckCircle2, XCircle,
    AlertTriangle, Clock, FileCode, Layers
} from 'lucide-react';

const phases: { id: ScanPhase; label: string; icon: React.ReactNode }[] = [
    { id: 'uploading', label: 'Upload', icon: <Upload style={{ width: 16, height: 16 }} /> },
    { id: 'analyzing', label: 'Analyze', icon: <Search style={{ width: 16, height: 16 }} /> },
    { id: 'ai_reasoning', label: 'AI Reason', icon: <Brain style={{ width: 16, height: 16 }} /> },
    { id: 'generating_report', label: 'Report', icon: <FileText style={{ width: 16, height: 16 }} /> },
];

interface ProgressTrackerProps {
    onComplete: () => void;
}

export function ProgressTracker({ onComplete }: ProgressTrackerProps) {
    const { progress, cancelScan, error } = useScanStore();
    const completedRef = React.useRef(false);

    useEffect(() => {
        if (progress.phase === 'complete' && !completedRef.current) {
            completedRef.current = true;
            const timer = setTimeout(onComplete, 500);
            return () => clearTimeout(timer);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [progress.phase]);

    const currentPhaseIdx = phases.findIndex((p) => p.id === progress.phase);

    return (
        <div className="card animate-fade-in-up" style={{ padding: 28 }}>
            {/* Header */}
            <div className="flex items-center justify-between" style={{ marginBottom: 24 }}>
                <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
                    {progress.phase === 'complete' ? '✓ Scan Complete' :
                        progress.phase === 'cancelled' ? 'Scan Cancelled' :
                            progress.phase === 'failed' ? '✕ Scan Failed' :
                                'Security Scan in Progress'}
                </h3>
                {progress.phase !== 'complete' && progress.phase !== 'cancelled' && progress.phase !== 'failed' && (
                    <button
                        onClick={cancelScan}
                        className="btn btn-secondary"
                        style={{ padding: '6px 16px', fontSize: 12, color: 'var(--severity-critical)', borderColor: 'var(--severity-critical)' }}
                    >
                        Cancel
                    </button>
                )}
            </div>

            {/* Error */}
            {error && (
                <div
                    style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '12px 16px', marginBottom: 20,
                        borderRadius: 'var(--radius-md)',
                        background: 'var(--severity-critical-bg)',
                        border: '1px solid var(--severity-critical)',
                    }}
                >
                    <XCircle style={{ width: 16, height: 16, color: 'var(--severity-critical)', flexShrink: 0 }} />
                    <p style={{ fontSize: 13, color: 'var(--severity-critical)' }}>{error}</p>
                </div>
            )}

            {/* CI Pipeline Steps */}
            <div className="flex items-center justify-between" style={{ marginBottom: 24 }}>
                {phases.map((phase, i) => {
                    const isActive = phase.id === progress.phase;
                    const isComplete = currentPhaseIdx > i || progress.phase === 'complete';
                    return (
                        <React.Fragment key={phase.id}>
                            <div
                                style={{
                                    display: 'flex', alignItems: 'center', gap: 8,
                                    padding: '8px 16px',
                                    borderRadius: 'var(--radius-md)',
                                    border: `1.5px solid ${isComplete ? 'var(--grade-a)' : isActive ? 'var(--brand-primary)' : 'var(--border-light)'}`,
                                    background: isComplete ? '#F0FDF4' : isActive ? 'var(--brand-primary)' : 'var(--bg-secondary)',
                                    color: isComplete ? 'var(--grade-a)' : isActive ? 'var(--text-primary)' : 'var(--text-tertiary)',
                                    transition: 'all 0.3s ease',
                                }}
                            >
                                {isComplete ? <CheckCircle2 style={{ width: 16, height: 16 }} /> : phase.icon}
                                <span className="hidden sm:inline" style={{ fontSize: 12, fontWeight: 600 }}>{phase.label}</span>
                            </div>
                            {i < phases.length - 1 && (
                                <div
                                    style={{
                                        flex: 1, height: 2, margin: '0 8px',
                                        borderRadius: 999,
                                        background: isComplete ? 'var(--grade-a)' : 'var(--border-light)',
                                        transition: 'background 0.3s ease',
                                    }}
                                />
                            )}
                        </React.Fragment>
                    );
                })}
            </div>

            {/* Progress Bar */}
            <div style={{ marginBottom: 20 }}>
                <ProgressBar value={progress.percent} label="Overall Progress" />
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                    { icon: <FileCode style={{ width: 14, height: 14 }} />, label: 'CURRENT FILE', value: progress.currentFile || '—' },
                    { icon: <Layers style={{ width: 14, height: 14 }} />, label: 'CHUNKS', value: `${progress.chunksProcessed} / ${progress.totalChunks || '—'}` },
                    { icon: <Clock style={{ width: 14, height: 14 }} />, label: 'ETA', value: progress.estimatedTimeRemaining > 0 ? `${progress.estimatedTimeRemaining}s` : '—' },
                    { icon: <AlertTriangle style={{ width: 14, height: 14, color: 'var(--severity-high)' }} />, label: 'VULNS FOUND', value: `${progress.liveVulnCount}`, highlight: true },
                ].map((stat, i) => (
                    <div
                        key={i}
                        style={{
                            padding: 12,
                            borderRadius: 'var(--radius-md)',
                            background: 'var(--bg-secondary)',
                            border: '1.5px solid var(--border-light)',
                        }}
                    >
                        <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
                            <span style={{ color: 'var(--text-tertiary)' }}>{stat.icon}</span>
                            <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.05em' }}>{stat.label}</span>
                        </div>
                        <p
                            style={{
                                fontSize: 12, fontWeight: 600,
                                color: stat.highlight ? 'var(--severity-high)' : 'var(--text-primary)',
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            }}
                        >
                            {stat.value}
                        </p>
                    </div>
                ))}
            </div>
        </div>
    );
}
