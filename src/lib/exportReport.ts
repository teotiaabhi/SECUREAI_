/**
 * Export utilities — Generate downloadable reports from scan results.
 *
 * Supports JSON and CSV export formats.
 */

import type { ScanResult, Vulnerability } from '@/store/scanStore';

/* ── JSON Export ──────────────────────────────────────────── */

export function exportAsJSON(result: ScanResult): void {
    const report = {
        report_generated: new Date().toISOString(),
        scan_id: result.id,
        repository: result.repoName,
        scan_date: result.timestamp,
        duration_seconds: result.duration,
        summary: {
            security_score: result.securityScore,
            grade: result.grade,
            confidence_score: result.confidenceScore,
            total_files: result.totalFiles,
            total_vulnerabilities: result.totalVulnerabilities,
            severity_breakdown: {
                critical: result.critical,
                high: result.high,
                medium: result.medium,
                low: result.low,
                info: result.info,
            },
        },
        vulnerabilities: result.vulnerabilities.map((v) => ({
            id: v.id,
            type: v.type,
            name: v.name,
            severity: v.severity,
            confidence: v.confidence,
            file: v.file,
            line: v.line,
            status: v.status,
            impact: v.impact || '',
            exploit_example: v.exploitExample || '',
            secure_patch: v.securePatch || '',
            owasp_reference: v.owaspRef || '',
            category: v.category || '',
        })),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: 'application/json',
    });
    _downloadBlob(blob, `security-report-${_sanitizeFilename(result.repoName)}-${_dateSlug()}.json`);
}

/* ── CSV Export ───────────────────────────────────────────── */

export function exportAsCSV(result: ScanResult): void {
    const headers = [
        'ID', 'Type', 'Severity', 'Confidence', 'File', 'Line',
        'Status', 'Category', 'OWASP', 'Impact',
    ];

    const rows = result.vulnerabilities.map((v) => [
        v.id,
        _csvEscape(v.type),
        v.severity,
        String(v.confidence),
        _csvEscape(v.file),
        String(v.line ?? ''),
        v.status,
        _csvEscape(v.category || ''),
        _csvEscape(v.owaspRef || ''),
        _csvEscape(v.impact || ''),
    ]);

    const csv = [
        `# Security Scan Report — ${result.repoName}`,
        `# Date: ${new Date(result.timestamp).toLocaleString()}`,
        `# Score: ${result.securityScore}/100 (Grade ${result.grade})`,
        `# Total Vulnerabilities: ${result.totalVulnerabilities}`,
        '',
        headers.join(','),
        ...rows.map((row) => row.join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    _downloadBlob(blob, `security-report-${_sanitizeFilename(result.repoName)}-${_dateSlug()}.csv`);
}

/* ── Helpers ──────────────────────────────────────────────── */

function _downloadBlob(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();

    // Cleanup
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

function _sanitizeFilename(name: string): string {
    return name
        .replace(/[^a-zA-Z0-9._-]/g, '-')
        .replace(/-+/g, '-')
        .toLowerCase()
        .slice(0, 60);
}

function _dateSlug(): string {
    const d = new Date();
    return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
}

function _csvEscape(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
        return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
}
