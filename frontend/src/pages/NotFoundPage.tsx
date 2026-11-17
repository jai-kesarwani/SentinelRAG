import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] border border-[var(--color-border)] text-[var(--color-accent)] mb-6">
        <ShieldAlert className="h-8 w-8" />
      </div>
      <h2 className="text-3xl font-bold tracking-tight text-[var(--color-text-primary)]">
        404 — Resource Not Found
      </h2>
      <p className="text-sm text-[var(--color-text-secondary)] mt-2 max-w-md">
        The route you requested does not exist or has not been deployed in this phase.
      </p>
      <div className="mt-6">
        <Link
          to="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--color-accent)] text-[var(--color-bg)] font-semibold text-sm hover:bg-[var(--color-accent-hover)] transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Dashboard</span>
        </Link>
      </div>
    </div>
  );
};

