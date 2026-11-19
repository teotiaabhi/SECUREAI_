'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Tabs } from '@/components/ui/Tabs';
import { FileUploader } from '@/components/scan/FileUploader';
import { CodePasteEditor } from '@/components/scan/CodePasteEditor';
import { ScanConfigPanel } from '@/components/scan/ScanConfigPanel';
import { ProgressTracker } from '@/components/scan/ProgressTracker';
import { UsageSummaryCard } from '@/components/scan/UsageSummary';
import { RepoSelector } from '@/components/auth/RepoSelector';
import { AppShell } from '@/components/layout/AppShell';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { useScanStore } from '@/store/scanStore';
import { useAuthStore } from '@/store/authStore';
import { GITHUB_LOGIN_URL } from '@/api/auth';

import { useRouter } from 'next/navigation';
import { Code, FileUp, Files, FolderArchive, Github, Play, ArrowRight, AlertCircle, ScanSearch } from 'lucide-react';

const tabItems = [
    { id: 'paste', label: 'Paste Code', icon: <Code style={{ width: 16, height: 16 }} /> },
    { id: 'single', label: 'Upload File', icon: <FileUp style={{ width: 16, height: 16 }} /> },
    { id: 'multiple', label: 'Multiple Files', icon: <Files style={{ width: 16, height: 16 }} /> },
    { id: 'zip', label: 'Upload ZIP', icon: <FolderArchive style={{ width: 16, height: 16 }} /> },
    { id: 'github', label: 'GitHub Repo', icon: <Github style={{ width: 16, height: 16 }} /> },
];

export default function ScanPage() {
    return (
        <AuthGuard>
            <ScanContent />
        </AuthGuard>
    );
}

function ScanContent() {
    const [activeTab, setActiveTab] = useState('paste');
    const [showRepoSelector, setShowRepoSelector] = useState(false);
    const [scanning, setScanning] = useState(false);
    const [selectedRepoName, setSelectedRepoName] = useState('');
    const [selectedBranch] = useState('main');
    const [pastedCode, setPastedCode] = useState('');
    const [pastedLanguage, setPastedLanguage] = useState('TypeScript');
    const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
    const { startPasteScan, startUploadScan, startGitHubScan, progress, error, activeScanId } = useScanStore();
    const { user } = useAuthStore();
    const githubConnected = Boolean(user?.githubConnected);
    const router = useRouter();
    const quotaExhausted = false;

    const handleStartScan = async () => {
        setScanning(true);
        if (activeTab === 'paste' && pastedCode.trim()) {
            await startPasteScan(pastedCode, 'paste.txt', pastedLanguage.toLowerCase());
        } else if ((activeTab === 'single' || activeTab === 'multiple' || activeTab === 'zip') && uploadedFiles.length > 0) {
            await startUploadScan(uploadedFiles);
        } else if (activeTab === 'github' && selectedRepoName) {
            await startGitHubScan(selectedRepoName, selectedBranch);
        } else {
            setScanning(false);
            return;
        }
    };

    const handleScanComplete = useCallback(() => {
        router.push(activeScanId ? `/results?id=${activeScanId}` : '/results');
    }, [router, activeScanId]);

    const handleRawFiles = (fileList: FileList) => {
        setUploadedFiles(Array.from(fileList));
    };

    if (scanning) {
        return (
            <AppShell>
                <div style={{ maxWidth: 720, margin: '0 auto' }}>
                    <ProgressTracker onComplete={handleScanComplete} />
                    {progress.phase === 'failed' && (
                        <div style={{ marginTop: 16, textAlign: 'center' }}>
                            <button
                                onClick={() => setScanning(false)}
                                className="btn btn-secondary"
                            >
                                Back to Scan Setup
                            </button>
                        </div>
                    )}
                </div>
            </AppShell>
        );
    }

    const canStartScan =
        !quotaExhausted &&
        ((activeTab === 'paste' && pastedCode.trim().length > 10) ||
        ((activeTab === 'single' || activeTab === 'multiple' || activeTab === 'zip') && uploadedFiles.length > 0) ||
        (activeTab === 'github' && githubConnected && !!selectedRepoName));

    return (
        <AppShell>
            <div style={{ maxWidth: 1100, margin: '0 auto' }}>
                {/* Header */}
                <div className="animate-fade-in" style={{ marginBottom: 24 }}>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="highlight-box" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                            <ScanSearch style={{ width: 14, height: 14 }} /> New Scan
                        </div>
                    </div>
                    <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                        Security Scan
                    </h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                        Upload your code or connect a repository to begin AI-powered security analysis.
                    </p>
                </div>

                {/* Error */}
                {error && (
                    <div
                        className="animate-fade-in"
                        style={{
                            marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10,
                            padding: '12px 16px', borderRadius: 'var(--radius-md)',
                            background: 'var(--severity-critical-bg)', border: '1px solid var(--severity-critical)',
                        }}
                    >
                        <AlertCircle style={{ width: 16, height: 16, color: 'var(--severity-critical)', flexShrink: 0 }} />
                        <p style={{ fontSize: 13, color: 'var(--severity-critical)' }}>{error}</p>
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Input Section */}
                    <div className="lg:col-span-2">
                        <div className="card" style={{ overflow: 'hidden' }}>
                            <Tabs items={tabItems} activeTab={activeTab} onChange={setActiveTab} />
                            <div style={{ padding: 20 }}>
                                {activeTab === 'paste' && (
                                    <CodePasteEditor onCodeChange={(code, lang) => { setPastedCode(code); setPastedLanguage(lang); }} />
                                )}
                                {activeTab === 'single' && <FileUploader onFilesSelected={() => { }} onRawFiles={handleRawFiles} />}
                                {activeTab === 'multiple' && <FileUploader multiple onFilesSelected={() => { }} onRawFiles={handleRawFiles} />}
                                {activeTab === 'zip' && <FileUploader acceptZip onFilesSelected={() => { }} onRawFiles={handleRawFiles} />}
                                {activeTab === 'github' && (
                                    <div style={{ textAlign: 'center', padding: '40px 0' }}>
                                        {!githubConnected ? (
                                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                                                <div
                                                    style={{
                                                        width: 56, height: 56,
                                                        borderRadius: 'var(--radius-lg)',
                                                        background: 'var(--bg-tertiary)',
                                                        border: '1.5px solid var(--border-light)',
                                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                    }}
                                                >
                                                    <Github style={{ width: 28, height: 28, color: 'var(--text-tertiary)' }} />
                                                </div>
                                                <div>
                                                    <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Connect Your GitHub Account</p>
                                                    <p style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4, maxWidth: 360 }}>
                                                        You signed in with {user?.provider === 'google' ? 'Google' : 'a different provider'}. Authorize GitHub to scan your repositories directly.
                                                    </p>
                                                </div>
                                                <a href={GITHUB_LOGIN_URL} className="btn btn-dark" style={{ fontSize: 13, textDecoration: 'none' }}>
                                                    <Github style={{ width: 16, height: 16 }} /> Connect GitHub
                                                </a>
                                            </div>
                                        ) : selectedRepoName ? (
                                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                                                <div className="pill" style={{ background: 'var(--brand-primary-light)' }}>
                                                    <Github style={{ width: 16, height: 16 }} />
                                                    <span style={{ fontWeight: 600 }}>{selectedRepoName}</span>
                                                </div>
                                                <p style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>Repository connected and ready for scanning</p>
                                                <button
                                                    onClick={() => setShowRepoSelector(true)}
                                                    style={{ fontSize: 12, color: 'var(--text-secondary)', textDecoration: 'underline', background: 'none', border: 'none', cursor: 'pointer' }}
                                                >
                                                    Change repository
                                                </button>
                                            </div>
                                        ) : (
                                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                                                <div
                                                    style={{
                                                        width: 56, height: 56,
                                                        borderRadius: 'var(--radius-lg)',
                                                        background: 'var(--bg-tertiary)',
                                                        border: '1.5px solid var(--border-light)',
                                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                    }}
                                                >
                                                    <Github style={{ width: 28, height: 28, color: 'var(--text-tertiary)' }} />
                                                </div>
                                                <div>
                                                    <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Connect a GitHub Repository</p>
                                                    <p style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>Select a repository from your GitHub account</p>
                                                </div>
                                                <button
                                                    onClick={() => setShowRepoSelector(true)}
                                                    className="btn btn-dark"
                                                    style={{ fontSize: 13 }}
                                                >
                                                    <Github style={{ width: 16, height: 16 }} /> Select Repository
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>

                    </div>

                    {/* Config Panel + Usage */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <div className="card" style={{ padding: 20 }}>
                            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
                                Scan Configuration
                            </h3>
                            <ScanConfigPanel />
                        </div>

                        <UsageSummaryCard />

                        {quotaExhausted && (
                            <div
                                style={{
                                    display: 'flex', alignItems: 'center', gap: 10,
                                    padding: '12px 16px', borderRadius: 'var(--radius-md)',
                                    background: 'var(--severity-critical-bg)', border: '1px solid var(--severity-critical)',
                                }}
                            >
                                <AlertCircle style={{ width: 16, height: 16, color: 'var(--severity-critical)', flexShrink: 0 }} />
                                <p style={{ fontSize: 13, color: 'var(--severity-critical)' }}>Daily scan limit reached.</p>
                            </div>
                        )}

                        {null}

                        <button
                            onClick={handleStartScan}
                            disabled={!canStartScan}
                            className="btn btn-primary"
                            style={{
                                width: '100%',
                                padding: '14px 24px',
                                fontSize: 15,
                                opacity: canStartScan ? 1 : 0.5,
                                cursor: canStartScan ? 'pointer' : 'not-allowed',
                            }}
                        >
                            <Play style={{ width: 18, height: 18 }} /> Start Security Scan <ArrowRight style={{ width: 16, height: 16 }} />
                        </button>
                    </div>
                </div>
            </div>

            <RepoSelector
                isOpen={showRepoSelector}
                onClose={() => setShowRepoSelector(false)}
                onSelect={(name) => { setSelectedRepoName(name); setShowRepoSelector(false); }}
            />
        </AppShell>
    );
}
