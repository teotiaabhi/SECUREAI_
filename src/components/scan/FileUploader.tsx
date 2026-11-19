'use client';

import React, { useCallback, useState } from 'react';
import { Upload, FileCode, AlertCircle, X } from 'lucide-react';

interface UploadedFile {
    id: string;
    name: string;
    size: number;
    language: string;
    content: string;
    errors: string[];
}

interface FileUploaderProps {
    multiple?: boolean;
    acceptZip?: boolean;
    onFilesSelected: (files: UploadedFile[]) => void;
    onRawFiles?: (files: FileList) => void;
}

const langMap: Record<string, string> = {
    ts: 'TypeScript', tsx: 'TypeScript React', js: 'JavaScript', jsx: 'JavaScript React',
    py: 'Python', java: 'Java', go: 'Go', rs: 'Rust', rb: 'Ruby', php: 'PHP',
    cs: 'C#', cpp: 'C++', c: 'C', swift: 'Swift', kt: 'Kotlin',
    yaml: 'YAML', yml: 'YAML', json: 'JSON', xml: 'XML', html: 'HTML', css: 'CSS',
    sql: 'SQL', sh: 'Shell', dockerfile: 'Dockerfile', tf: 'HCL', env: 'Environment',
};

function detectLanguage(filename: string): string {
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    return langMap[ext] || 'Unknown';
}

function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const MAX_ZIP_SIZE = 500 * 1024 * 1024;

export function FileUploader({ multiple = false, acceptZip = false, onFilesSelected, onRawFiles }: FileUploaderProps) {
    const [dragActive, setDragActive] = useState(false);
    const [files, setFiles] = useState<UploadedFile[]>([]);

    const processFiles = useCallback((fileList: FileList) => {
        const newFiles: UploadedFile[] = [];
        Array.from(fileList).forEach((file) => {
            const errors: string[] = [];
            const isZip = file.name.endsWith('.zip');
            const sizeLimit = isZip ? MAX_ZIP_SIZE : MAX_FILE_SIZE;
            const limitLabel = isZip ? '500MB' : '5MB';
            if (file.size > sizeLimit) errors.push(`File exceeds ${limitLabel} limit`);
            if (!acceptZip && file.name.endsWith('.zip')) errors.push('ZIP files not accepted in this mode');

            newFiles.push({
                id: `${file.name}-${Date.now()}-${Math.random()}`,
                name: file.name,
                size: file.size,
                language: file.name.endsWith('.zip') ? 'ZIP Archive' : detectLanguage(file.name),
                content: '',
                errors,
            });
        });
        setFiles((prev) => [...prev, ...newFiles]);
        onFilesSelected(newFiles);
        if (onRawFiles) onRawFiles(fileList);
    }, [acceptZip, onFilesSelected, onRawFiles]);

    const removeFile = (id: string) => {
        setFiles((prev) => prev.filter((f) => f.id !== id));
    };

    const accept = '.ts,.tsx,.js,.jsx,.py,.java,.go,.rs,.json,.yaml,.yml,.xml,.html,.css,.sql,.sh,.tf,.rb,.php,.cs,.cpp,.c,.swift,.kt' + (acceptZip ? ',.zip' : '');

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Drop Zone */}
            <div
                onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
                onDragLeave={() => setDragActive(false)}
                onDrop={(e) => { e.preventDefault(); setDragActive(false); if (e.dataTransfer.files) processFiles(e.dataTransfer.files); }}
                style={{
                    position: 'relative',
                    border: `2px dashed ${dragActive ? 'var(--brand-primary)' : 'var(--border-primary)'}`,
                    borderRadius: 'var(--radius-lg)',
                    padding: 40,
                    textAlign: 'center',
                    cursor: 'pointer',
                    background: dragActive ? 'var(--brand-primary-light)' : 'var(--bg-secondary)',
                    transition: 'all 0.15s ease',
                }}
            >
                <input
                    type="file"
                    multiple={multiple}
                    accept={accept}
                    onChange={(e) => { if (e.target.files) processFiles(e.target.files); }}
                    style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: 0, cursor: 'pointer' }}
                />
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                    <div
                        style={{
                            width: 52, height: 52,
                            borderRadius: 'var(--radius-md)',
                            background: 'var(--brand-primary)',
                            border: '1.5px solid var(--border-primary)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}
                    >
                        <Upload style={{ width: 24, height: 24 }} />
                    </div>
                    <div>
                        <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                            Drop {acceptZip ? 'files or ZIP archive' : multiple ? 'files' : 'a file'} here
                        </p>
                        <p style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>or click to browse · Max 500MB for ZIP, 5MB per file</p>
                    </div>
                </div>
            </div>

            {/* File List */}
            {files.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {files.map((file) => (
                        <div
                            key={file.id}
                            className="animate-fade-in"
                            style={{
                                display: 'flex', alignItems: 'center', gap: 12,
                                padding: 12,
                                borderRadius: 'var(--radius-md)',
                                background: 'var(--bg-secondary)',
                                border: '1.5px solid var(--border-primary)',
                            }}
                        >
                            <div
                                style={{
                                    width: 36, height: 36,
                                    borderRadius: 'var(--radius-sm)',
                                    background: 'var(--brand-primary-light)',
                                    border: '1px solid var(--border-light)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    flexShrink: 0,
                                }}
                            >
                                <FileCode style={{ width: 16, height: 16, color: 'var(--text-secondary)' }} />
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                                <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</p>
                                <div className="flex items-center gap-2" style={{ marginTop: 2 }}>
                                    <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{file.language}</span>
                                    <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>·</span>
                                    <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{formatSize(file.size)}</span>
                                </div>
                            </div>
                            {file.errors.length > 0 && (
                                <div className="flex items-center gap-1" style={{ color: 'var(--severity-critical)' }}>
                                    <AlertCircle style={{ width: 14, height: 14 }} />
                                    <span style={{ fontSize: 11, fontWeight: 600 }}>{file.errors[0]}</span>
                                </div>
                            )}
                            <button
                                onClick={() => removeFile(file.id)}
                                style={{
                                    width: 28, height: 28,
                                    borderRadius: 'var(--radius-sm)',
                                    border: '1px solid var(--border-light)',
                                    background: 'var(--bg-primary)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    cursor: 'pointer',
                                    color: 'var(--text-tertiary)',
                                    transition: 'all 0.15s ease',
                                }}
                            >
                                <X style={{ width: 14, height: 14 }} />
                            </button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
