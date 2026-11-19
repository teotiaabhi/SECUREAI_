'use client';

import React, { useState } from 'react';
import { Code } from 'lucide-react';

interface CodePasteEditorProps {
    onCodeChange: (code: string, language: string) => void;
}

const languages = [
    'TypeScript', 'JavaScript', 'Python', 'Java', 'Go', 'Rust', 'C#', 'C++', 'PHP', 'Ruby', 'Swift', 'Kotlin', 'SQL', 'Shell', 'YAML', 'JSON', 'HTML',
];

export function CodePasteEditor({ onCodeChange }: CodePasteEditorProps) {
    const [code, setCode] = useState('');
    const [language, setLanguage] = useState('TypeScript');

    const handleChange = (value: string) => {
        setCode(value);
        onCodeChange(value, language);
    };

    const lineCount = code.split('\n').length;
    const charCount = code.length;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Language Selector */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <div
                        style={{
                            width: 28, height: 28,
                            borderRadius: 'var(--radius-sm)',
                            background: 'var(--brand-primary)',
                            border: '1.5px solid var(--border-primary)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}
                    >
                        <Code style={{ width: 14, height: 14 }} />
                    </div>
                    <select
                        value={language}
                        onChange={(e) => { setLanguage(e.target.value); onCodeChange(code, e.target.value); }}
                        className="select"
                        style={{ padding: '6px 12px', fontSize: 13 }}
                    >
                        {languages.map((l) => <option key={l} value={l}>{l}</option>)}
                    </select>
                </div>
                <div className="flex items-center gap-3" style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                    <span>{lineCount} lines</span>
                    <span>·</span>
                    <span>{charCount.toLocaleString()} chars</span>
                </div>
            </div>

            {/* Editor */}
            <div
                style={{
                    borderRadius: 'var(--radius-md)',
                    overflow: 'hidden',
                    border: '1.5px solid var(--border-primary)',
                }}
            >
                <div style={{ display: 'flex' }}>
                    {/* Line Numbers */}
                    <div
                        style={{
                            padding: '16px 12px',
                            background: 'var(--bg-tertiary)',
                            textAlign: 'right',
                            userSelect: 'none',
                            borderRight: '1.5px solid var(--border-primary)',
                        }}
                    >
                        {code.split('\n').map((_, i) => (
                            <div key={i} style={{ fontSize: 12, color: 'var(--text-tertiary)', lineHeight: '24px', fontFamily: "'JetBrains Mono', monospace" }}>{i + 1}</div>
                        ))}
                        {code === '' && <div style={{ fontSize: 12, color: 'var(--text-tertiary)', lineHeight: '24px', fontFamily: "'JetBrains Mono', monospace" }}>1</div>}
                    </div>
                    {/* Code Area */}
                    <textarea
                        value={code}
                        onChange={(e) => handleChange(e.target.value)}
                        placeholder="Paste your code here for security analysis..."
                        spellCheck={false}
                        style={{
                            flex: 1,
                            padding: 16,
                            background: 'var(--bg-code)',
                            fontSize: 13,
                            color: 'var(--text-primary)',
                            fontFamily: "'JetBrains Mono', monospace",
                            lineHeight: '24px',
                            resize: 'none',
                            outline: 'none',
                            border: 'none',
                            minHeight: 300,
                        }}
                    />
                </div>
            </div>
        </div>
    );
}
