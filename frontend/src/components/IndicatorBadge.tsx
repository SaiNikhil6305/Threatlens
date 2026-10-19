import React from 'react';
import { IndicatorType } from '../types';

interface IndicatorBadgeProps {
  type: IndicatorType | string;
  size?: 'sm' | 'md';
}

export const IndicatorBadge: React.FC<IndicatorBadgeProps> = ({ type, size = 'md' }) => {
  const norm = (type || 'unknown').toLowerCase();

  const labels: Record<string, { label: string; color: string; border: string }> = {
    ipv4: { label: 'IPv4', color: 'bg-blue-50/80 text-blue-700', border: 'border-blue-200' },
    domain: { label: 'Domain', color: 'bg-indigo-50/80 text-indigo-700', border: 'border-indigo-200' },
    url: { label: 'URL', color: 'bg-purple-50/80 text-purple-700', border: 'border-purple-200' },
    email: { label: 'Email', color: 'bg-cyan-50/80 text-cyan-700', border: 'border-cyan-200' },
    sha256: { label: 'SHA-256', color: 'bg-rose-50/80 text-rose-700', border: 'border-rose-200' },
    sha1: { label: 'SHA-1', color: 'bg-pink-50/80 text-pink-700', border: 'border-pink-200' },
    md5: { label: 'MD5', color: 'bg-fuchsia-50/80 text-fuchsia-700', border: 'border-fuchsia-200' },
    cve: { label: 'CVE', color: 'bg-amber-50/80 text-amber-800', border: 'border-amber-200' },
  };

  const item = labels[norm] || { label: type.toUpperCase(), color: 'bg-slate-50 text-slate-700', border: 'border-slate-200' };
  const sizeClass = size === 'sm' ? 'text-[9px] px-1.5 py-0.5' : 'text-[10px] px-2 py-0.5';

  return (
    <span className={`inline-flex items-center rounded border font-mono font-bold uppercase tracking-wider shadow-2xs ${item.color} ${item.border} ${sizeClass}`}>
      {item.label}
    </span>
  );
};
