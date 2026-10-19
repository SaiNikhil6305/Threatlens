import React from 'react';
import { LucideIcon, ShieldAlert } from 'lucide-react';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = ShieldAlert,
  title,
  description,
  actionText,
  onAction,
}) => {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-surface py-12 px-6 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-subtle text-charcoal-500 mb-4">
        <Icon className="h-6 w-6" />
      </div>
      <h3 className="text-sm font-semibold text-charcoal-900">{title}</h3>
      <p className="mt-1 text-sm text-charcoal-500 max-w-sm">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="mt-4 inline-flex items-center gap-2 rounded-md bg-navy-900 px-3.5 py-2 text-xs font-medium text-white shadow-sm hover:bg-navy-800 transition"
        >
          {actionText}
        </button>
      )}
    </div>
  );
};
