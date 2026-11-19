'use client';

import React, { Suspense, useState, useEffect, useCallback, useRef } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { useScanStore, Vulnerability } from '@/store/scanStore';
import { ExecutiveSummary } from '@/components/results/ExecutiveSummary';
import { VulnerabilityTable } from '@/components/results/VulnerabilityTable';
import { VulnerabilityDetailPanel } from '@/components/results/VulnerabilityDetailPanel';
import { VulnerabilityCodeViewer } from '@/components/results/VulnerabilityCodeViewer';
import { ChartsSection } from '@/components/results/ChartsSection';
import { RepoRiskIntelligence } from '@/components/results/RepoRiskIntelligence';
import { ExploitChainGraph } from '@/components/results/ExploitChainGraph';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Skeleton';
import { Tabs } from '@/components/ui/Tabs';
import { useRouter, useSearchParams } from 'next/navigation';
import { Shield, Download, RefreshCw, AlertCircle, FileJson, FileSpreadsheet, ChevronDown, GitBranch, BarChart3, List } from 'lucide-react';
import { exportAsJSON, exportAsCSV } from '@/lib/exportReport';

function ResultsContent() {
    const { result, error, fetchResult, fetchReport, reportData } = useScanStore();
    const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
    const [codeViewerVuln, setCodeViewerVuln] = useState<Vulnerability | null>(null);
    const [loading, setLoading] = useState(false);
    const [exportOpen, setExportOpen] = useState(false);
    const [resultsTab, setResultsTab] = useState('vulnerabilities');
    const exportRef = useRef<HTMLDivElement>(null);
    const fetchedIdRef = useRef<string | null>(null);
    const router = useRouter();
    const searchParams = useSearchParams();

    // Detect exploit chains
    const hasChains = result?.vulnerabilities.some((v) => v.exploitChainName) ?? false;

    // Close export dropdown on outside click
    useEffect(() => {
        function handleClickOutside(e: MouseEvent) {
            if (exportRef.current && !exportRef.current.contains(e.target as Node)) {
                setExportOpen(false);
            }
        }
        if (exportOpen) document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [exportOpen]);

    useEffect(() => {
        const scanId = searchParams.get('id');
        if (scanId && scanId !== fetchedIdRef.current) {
            fetchedIdRef.current = scanId;
            setLoading(true);
            fetchResult(scanId).finally(() => setLoading(false));
            fetchReport(scanId);
        }
    }, [searchParams, fetchResult, fetchReport]);

    if (loading) {
        return (
            <AppShell>
                <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
                    <Skeleton className="h-8 w-64" />
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <Skeleton className="h-32" count={4} />
                    </div>
                    <Skeleton className="h-64" />
                </div>
            </AppShell>
        );
    }

    if (error) {
        return (
            <AppShell>
                <div style={{ maxWidth: 600, margin: '0 auto' }}>
                    <div className="card" style={{ padding: 40, textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                        <AlertCircle style={{ width: 48, height: 48, color: 'var(--severity-critical)' }} />
                        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Failed to Load Results</h2>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>{error}</p>
                        <button onClick={() => router.push('/scan')} className="btn btn-primary">
                            Start a New Scan
                        </button>
                    </div>
                </div>
            </AppShell>
        );
    }

    if (!result) {
        return (
            <AppShell>
                <EmptyState
                    icon="scan"
                    title="No Scan Results"
                    description="Run a security scan to see your results here."
                    action={
                        <button onClick={() => router.push('/scan')} className="btn btn-primary">
                            Start a Scan
                        </button>
                    }
                />
            </AppShell>
        );
    }

    return (
        <AppShell>
            <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
                {/* Header */}
                <div className="flex items-center justify-between animate-fade-in">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                <Shield style={{ width: 14, height: 14 }} /> Results
                            </div>
                        </div>
                        <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>Scan Results</h1>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                            Repository: <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{result.repoName}</span>
                            <span style={{ color: 'var(--text-tertiary)' }}> · {new Date(result.timestamp).toLocaleDateString()} · {result.duration}s</span>
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <button onClick={() => router.push('/scan')} className="btn btn-secondary" style={{ fontSize: 12, padding: '6px 14px' }}>
                            <RefreshCw style={{ width: 14, height: 14 }} /> New Scan
                        </button>
                        <div ref={exportRef} style={{ position: 'relative' }}>
                            <button
                                onClick={() => setExportOpen(!exportOpen)}
                                className="btn btn-secondary"
                                style={{ fontSize: 12, padding: '6px 14px' }}
                            >
                                <Download style={{ width: 14, height: 14 }} /> Export
                                <ChevronDown style={{ width: 12, height: 12, marginLeft: 2 }} />
                            </button>
                            {exportOpen && (
                                <div
                                    style={{
                                        position: 'absolute', right: 0, top: '100%', marginTop: 4,
                                        background: 'var(--bg-card)', border: '1.5px solid var(--border-primary)',
                                        borderRadius: 'var(--radius-md)', boxShadow: 'var(--shadow-md)',
                                        minWidth: 160, zIndex: 9999, overflow: 'hidden',
                                    }}
                                >
                                    <button
                                        onClick={() => { exportAsJSON(result); setExportOpen(false); }}
                                        style={{
                                            width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                                            padding: '10px 14px', fontSize: 12, fontWeight: 500,
                                            color: 'var(--text-primary)', background: 'transparent',
                                            border: 'none', cursor: 'pointer', textAlign: 'left',
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                    >
                                        <FileJson style={{ width: 14, height: 14, color: 'var(--brand-primary)' }} />
                                        Export as JSON
                                    </button>
                                    <button
                                        onClick={() => { exportAsCSV(result); setExportOpen(false); }}
                                        style={{
                                            width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                                            padding: '10px 14px', fontSize: 12, fontWeight: 500,
                                            color: 'var(--text-primary)', background: 'transparent',
                                            border: 'none', cursor: 'pointer', textAlign: 'left',
                                            borderTop: '1px solid var(--border-light)',
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                    >
                                        <FileSpreadsheet style={{ width: 14, height: 14, color: '#16A34A' }} />
                                        Export as CSV
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                <ExecutiveSummary result={result} />
                <ChartsSection result={result} />
                <RepoRiskIntelligence result={result} />

                {/* Report Analytics */}
                {reportData && (
                    <div className="card animate-fade-in" style={{ padding: 20 }}>
                        <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>Report Analytics</h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                            {reportData.executiveSummary && (
                                <div className="sm:col-span-2 lg:col-span-3" style={{ padding: 14, borderRadius: 'var(--radius-md)', background: 'var(--brand-primary-light)', border: '1.5px solid var(--brand-primary)' }}>
                                    <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4, opacity: 0.7 }}>Executive Summary</p>
                                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>{reportData.executiveSummary}</p>
                                </div>
                            )}
                            {Object.keys(reportData.owaspDistribution).length > 0 && (
                                <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)', border: '1px solid var(--border-light)' }}>
                                    <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>OWASP Distribution</p>
                                    {Object.entries(reportData.owaspDistribution).sort(([, a], [, b]) => b - a).slice(0, 5).map(([key, count]) => (
                                        <div key={key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '70%' }}>{key}</span>
                                            <span style={{ fontWeight: 600 }}>{count}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                            {Object.keys(reportData.cweDistribution).length > 0 && (
                                <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)', border: '1px solid var(--border-light)' }}>
                                    <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>CWE Distribution</p>
                                    {Object.entries(reportData.cweDistribution).sort(([, a], [, b]) => b - a).slice(0, 5).map(([key, count]) => (
                                        <div key={key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                                            <span>{key}</span>
                                            <span style={{ fontWeight: 600 }}>{count}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                            {reportData.fileRiskRanking.length > 0 && (
                                <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)', border: '1px solid var(--border-light)' }}>
                                    <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Highest Risk Files</p>
                                    {reportData.fileRiskRanking.slice(0, 5).map((f, i) => (
                                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '60%' }}>{f.file}</span>
                                            <span style={{ fontWeight: 600 }}>{f.vulnCount} vulns</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* Vulnerability Breakdown with Tabs */}
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Vulnerability Breakdown</h2>
                        {hasChains && (
                            <button
                                onClick={() => router.push(`/exploit-graph?id=${result.id}`)}
                                className="btn btn-secondary"
                                style={{ fontSize: 12, padding: '6px 14px' }}
                            >
                                <GitBranch style={{ width: 14, height: 14 }} /> View Attack Graph
                            </button>
                        )}
                    </div>

                    {/* Sub-tabs for vulnerabilities vs chains */}
                    {hasChains && (
                        <div style={{ marginBottom: 12 }}>
                            <Tabs
                                items={[
                                    { id: 'vulnerabilities', label: 'All Vulnerabilities', icon: <List style={{ width: 14, height: 14 }} /> },
                                    { id: 'chains', label: 'Exploit Chains', icon: <GitBranch style={{ width: 14, height: 14 }} /> },
                                ]}
                                activeTab={resultsTab}
                                onChange={setResultsTab}
                            />
                        </div>
                    )}
                    {resultsTab === 'vulnerabilities' ? (
                        <VulnerabilityTable
                            vulnerabilities={result.vulnerabilities}
                            onViewDetails={setSelectedVuln}
                            onViewCode={setCodeViewerVuln}
                        />
                    ) : (
                        <ExploitChainGraph
                            vulnerabilities={result.vulnerabilities}
                            onSelectVulnerability={setSelectedVuln}
                        />
                    )}
                </div>

                <VulnerabilityDetailPanel
                    vulnerability={selectedVuln}
                    isOpen={!!selectedVuln}
                    onClose={() => setSelectedVuln(null)}
                    scanId={result.id}
                    onViewCode={(v) => { setSelectedVuln(null); setCodeViewerVuln(v); }}
                />

                {codeViewerVuln && (
                    <VulnerabilityCodeViewer
                        isOpen={!!codeViewerVuln}
                        onClose={() => setCodeViewerVuln(null)}
                        scanId={result.id}
                        fileName={codeViewerVuln.file}
                        detectionId={codeViewerVuln.id}
                        fallbackLine={codeViewerVuln.line}
                    />
                )}
            </div>
        </AppShell>
    );
}

export default function ResultsPage() {
    return (
        <AuthGuard>
            <Suspense fallback={<AppShell><div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400 }}>Loading results...</div></AppShell>}>
                <ResultsContent />
            </Suspense>
        </AuthGuard>
    );
}
