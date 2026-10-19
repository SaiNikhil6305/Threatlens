import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  message = 'Processing intelligence data...',
  size = 'md',
}) => {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-6 w-6',
    lg: 'h-8 w-8',
  }[size];

  return (
    <div className="flex flex-col items-center justify-center py-12 text-center text-charcoal-600">
      <Loader2 className={`animate-spin text-accent ${sizeClasses} mb-3`} />
      <p className="text-sm font-medium text-charcoal-700">{message}</p>
      <p className="text-xs text-charcoal-400 mt-1">Extracting indicators & computing explainable assessments</p>
    </div>
  );
};
