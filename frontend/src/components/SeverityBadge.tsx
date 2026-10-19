import React from 'react';
import { SeverityLevel } from '../types';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showDot = true,
}) => {
  const norm = (severity || 'Informational').toLowerCase();

  const config: Record<string, { bg: string; text: string; border: string; dot: string; pulse: boolean }> = {
    critical: {
      bg: 'bg-red-50/90',
      text: 'text-red-700',
      border: 'border-red-200/90',
      dot: 'bg-red-600',
      pulse: true,
    },
    high: {
      bg: 'bg-orange-50/90',
      text: 'text-orange-700',
      border: 'border-orange-200/90',
      dot: 'bg-orange-600',
      pulse: true,
    },
    medium: {
      bg: 'bg-amber-50/90',
      text: 'text-amber-800',
      border: 'border-amber-200/90',
      dot: 'bg-amber-600',
      pulse: false,
    },
    low: {
      bg: 'bg-emerald-50/90',
      text: 'text-emerald-700',
      border: 'border-emerald-200/90',
      dot: 'bg-emerald-600',
      pulse: false,
    },
    informational: {
      bg: 'bg-slate-50/90',
      text: 'text-slate-700',
      border: 'border-slate-200/90',
      dot: 'bg-slate-500',
      pulse: false,
    },
  };

  const style = config[norm] || config.informational;

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 font-medium tracking-wide',
    md: 'text-xs px-2.5 py-1 font-medium',
    lg: 'text-sm px-3.5 py-1.5 font-semibold',
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border shadow-2xs ${style.bg} ${style.text} ${style.border} ${sizeClasses} select-none`}
    >
      {showDot && (
        <span className="relative flex h-2 w-2">
          {style.pulse && (
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${style.dot}`} />
          )}
          <span className={`relative inline-flex rounded-full h-2 w-2 ${style.dot}`} />
        </span>
      )}
      <span className="uppercase tracking-wider font-semibold text-[10px]">{severity}</span>
    </span>
  );
};
