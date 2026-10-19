import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

interface ConfirmationModalProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  isDestructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  isOpen,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  isDestructive = true,
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="w-full max-w-md rounded-lg bg-surface border border-border shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex items-center gap-2 text-charcoal-900 font-semibold text-sm">
            {isDestructive && <AlertTriangle className="h-4 w-4 text-severity-critical" />}
            {title}
          </div>
          <button
            onClick={onCancel}
            className="text-charcoal-400 hover:text-charcoal-600 rounded p-1"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 text-sm text-charcoal-600">
          {message}
        </div>

        <div className="flex items-center justify-end gap-2 bg-surface-subtle px-5 py-3 border-t border-border">
          <button
            onClick={onCancel}
            className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-charcoal-700 hover:bg-surface-subtle transition"
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            className={`rounded-md px-3.5 py-1.5 text-xs font-medium text-white transition ${
              isDestructive ? 'bg-red-600 hover:bg-red-700' : 'bg-navy-900 hover:bg-navy-800'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
};
