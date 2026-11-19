'use client';

import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
    isOpen: boolean;
    onClose: () => void;
    title?: string;
    children: React.ReactNode;
    maxWidth?: number;
}

export function Modal({ isOpen, onClose, title, children, maxWidth = 640 }: ModalProps) {
    const overlayRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (isOpen) {
            document.body.style.overflow = 'hidden';
        } else {
            document.body.style.overflow = '';
        }
        return () => { document.body.style.overflow = ''; };
    }, [isOpen]);

    useEffect(() => {
        const handleEsc = (e: KeyboardEvent) => {
            if (e.key === 'Escape') onClose();
        };
        if (isOpen) window.addEventListener('keydown', handleEsc);
        return () => window.removeEventListener('keydown', handleEsc);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    return (
        <div
            ref={overlayRef}
            onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
            style={{
                position: 'fixed', inset: 0, zIndex: 100,
                background: 'rgba(0,0,0,0.4)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: 24,
            }}
        >
            <div
                className="card animate-scale-in"
                style={{
                    width: '100%',
                    maxWidth,
                    maxHeight: '90vh',
                    overflow: 'auto',
                }}
            >
                {title && (
                    <div
                        style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px 24px',
                            borderBottom: '1.5px solid var(--border-primary)',
                            background: 'var(--brand-primary-light)',
                        }}
                    >
                        <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</h3>
                        <button
                            onClick={onClose}
                            style={{
                                width: 32, height: 32,
                                borderRadius: 'var(--radius-md)',
                                border: '1.5px solid var(--border-primary)',
                                background: 'var(--bg-primary)',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                cursor: 'pointer',
                                color: 'var(--text-secondary)',
                            }}
                        >
                            <X style={{ width: 16, height: 16 }} />
                        </button>
                    </div>
                )}
                <div style={{ padding: 24 }}>
                    {children}
                </div>
            </div>
        </div>
    );
}
