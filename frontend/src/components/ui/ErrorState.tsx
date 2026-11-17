import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Connection Error',
  message,
  onRetry,
  className = '',
}) => {
  return (
    <div
      className={`rounded-lg border border-[var(--color-danger)]/30 bg-[var(--color-surface)] p-6 text-center ${className}`}
      role="alert"
    >
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-[var(--color-danger)]/10 text-[var(--color-danger)] mb-4">
        <AlertCircle className="h-6 w-6" />
      </div>
      <h3 className="text-base font-semibold text-[var(--color-text-primary)] mb-1">{title}</h3>
      <p className="text-sm text-[var(--color-text-secondary)] mb-4 max-w-md mx-auto">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-[var(--color-surface-raised)] hover:bg-[var(--color-border)] text-sm font-medium text-[var(--color-text-primary)] border border-[var(--color-border)] transition-colors cursor-pointer"
        >
          <RefreshCw className="h-4 w-4" />
          <span>Retry Connection</span>
        </button>
      )}
    </div>
  );
};

