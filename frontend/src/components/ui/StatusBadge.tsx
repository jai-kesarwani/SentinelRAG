import React from 'react';
import type { ServiceHealthState } from '../../types';

interface StatusBadgeProps {
  status: ServiceHealthState;
  showText?: boolean;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  showText = true,
  className = '',
}) => {
  const config = {
    healthy: {
      dotColor: 'bg-[var(--color-success)]',
      textColor: 'text-[var(--color-success)]',
      bgColor: 'bg-[var(--color-success)]/10',
      borderColor: 'border-[var(--color-success)]/30',
      label: 'Operational',
    },
    degraded: {
      dotColor: 'bg-[var(--color-warning)]',
      textColor: 'text-[var(--color-warning)]',
      bgColor: 'bg-[var(--color-warning)]/10',
      borderColor: 'border-[var(--color-warning)]/30',
      label: 'Degraded',
    },
    unhealthy: {
      dotColor: 'bg-[var(--color-danger)]',
      textColor: 'text-[var(--color-danger)]',
      bgColor: 'bg-[var(--color-danger)]/10',
      borderColor: 'border-[var(--color-danger)]/30',
      label: 'Offline',
    },
    unknown: {
      dotColor: 'bg-[var(--color-text-secondary)]',
      textColor: 'text-[var(--color-text-secondary)]',
      bgColor: 'bg-[var(--color-text-secondary)]/10',
      borderColor: 'border-[var(--color-text-secondary)]/30',
      label: 'Unknown',
    },
  }[status] || {
    dotColor: 'bg-[var(--color-text-secondary)]',
    textColor: 'text-[var(--color-text-secondary)]',
    bgColor: 'bg-[var(--color-text-secondary)]/10',
    borderColor: 'border-[var(--color-text-secondary)]/30',
    label: status,
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${config.bgColor} ${config.borderColor} ${config.textColor} ${className}`}
      role="status"
    >
      <span className={`w-2 h-2 rounded-full ${config.dotColor} animate-pulse`} aria-hidden="true" />
      {showText && <span>{config.label}</span>}
    </span>
  );
};

