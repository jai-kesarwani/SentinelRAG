import React from 'react';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  label?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  className = '',
  label = 'Loading...',
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4 border-2',
    md: 'w-6 h-6 border-2',
    lg: 'w-8 h-8 border-3',
  }[size];

  return (
    <div className={`inline-flex items-center gap-2 text-[var(--color-text-secondary)] ${className}`} role="status">
      <div
        className={`${sizeClasses} rounded-full border-t-[var(--color-accent)] border-r-[var(--color-accent)]/20 border-b-[var(--color-accent)]/20 border-l-[var(--color-accent)]/20 animate-spin`}
        aria-hidden="true"
      />
      {label && <span className="text-sm font-medium">{label}</span>}
    </div>
  );
};

