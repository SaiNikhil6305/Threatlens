import React from 'react';
import { X, ExternalLink, ShieldCheck } from 'lucide-react';
import { IndicatorBadge } from './IndicatorBadge';

interface EvidenceModalProps {
  isOpen: boolean;
  title: string;
  indicatorValue?: string;
  indicatorType?: string;
  snippet?: string;
  onClose: () => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  isOpen,
  title,
  indicatorValue,
  indicatorType,
  snippet,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg rounded-lg bg-surface border border-border shadow-xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-accent" />
            <span className="text-sm font-semibold text-charcoal-900">{title}</span>
          </div>
          <button
            onClick={onClose}
            className="text-charcoal-400 hover:text-charcoal-600 rounded p-1"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {indicatorValue && (
            <div>
              <div className="text-xs font-medium text-charcoal-500 uppercase tracking-wider mb-1">
                Extracted Indicator
              </div>
              <div className="flex items-center gap-2">
                {indicatorType && <IndicatorBadge type={indicatorType} />}
                <span className="font-mono text-xs font-semibold text-charcoal-900 bg-surface-subtle px-2 py-1 rounded border border-border">
                  {indicatorValue}
                </span>
              </div>
            </div>
          )}

          <div>
            <div className="text-xs font-medium text-charcoal-500 uppercase tracking-wider mb-1">
              Surrounding Context & Evidence Snippet
            </div>
            <div className="font-mono text-xs leading-relaxed text-charcoal-800 bg-slate-900 text-slate-100 p-3.5 rounded border border-slate-800 whitespace-pre-wrap break-all max-h-60 overflow-y-auto">
              {snippet || 'No specific snippet recorded.'}
            </div>
          </div>
        </div>

        <div className="flex justify-end bg-surface-subtle px-5 py-3 border-t border-border">
          <button
            onClick={onClose}
            className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-charcoal-700 hover:bg-surface-subtle transition"
          >
            Close Evidence Panel
          </button>
        </div>
      </div>
    </div>
  );
};
