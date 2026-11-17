import React from 'react';
import {
  Server,
  Database,
  Layers,
  RefreshCw,
  Clock,
  Cpu,
} from 'lucide-react';
import { useHealth } from '../hooks/useHealth';
import { StatusBadge } from '../components/ui/StatusBadge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { ErrorState } from '../components/ui/ErrorState';

export const DashboardPage: React.FC = () => {
  const {
    app,
    database,
    vectorStore,
    isLoading,
    isRefreshing,
    lastUpdated,
    error,
    refetch,
  } = useHealth(15000);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] text-center">
        <LoadingSpinner size="lg" label="Connecting to SentinelRAG Services..." />
        <p className="text-xs text-[var(--color-text-secondary)] mt-3">
          Verifying backend, MongoDB, and ChromaDB connectivity
        </p>
      </div>
    );
  }

  if (error && !app) {
    return (
      <div className="max-w-xl mx-auto my-12">
        <ErrorState
          title="Backend Unreachable"
          message={`Unable to connect to SentinelRAG backend API. Ensure FastAPI is running on ${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}. Details: ${error}`}
          onRetry={refetch}
        />
      </div>
    );
  }

  const formatTime = (date: Date | null) => {
    if (!date) return 'Never';
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <div className="space-y-8">
      {/* Overview Banner */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 md:p-8 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-[var(--color-accent)]/10 text-[var(--color-accent)] text-xs font-mono font-medium mb-2 border border-[var(--color-accent)]/20">
              <Cpu className="w-3.5 h-3.5" />
              <span>PHASE 1: FOUNDATION & SETUP</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[var(--color-text-primary)]">
              SentinelRAG Control Center
            </h2>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1 max-w-2xl">
              Secure Retrieval-Augmented Generation Agent with integrated adversarial defense and real-time infrastructure telemetry.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={refetch}
              disabled={isRefreshing}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--color-surface-raised)] hover:bg-[var(--color-border)] text-sm font-medium text-[var(--color-text-primary)] border border-[var(--color-border)] transition-colors cursor-pointer disabled:opacity-60"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-[var(--color-accent)]' : ''}`} />
              <span>{isRefreshing ? 'Refreshing...' : 'Refresh Status'}</span>
            </button>
          </div>
        </div>

        {/* Status subline */}
        <div className="flex flex-wrap items-center gap-6 mt-6 pt-6 border-t border-[var(--color-border)] text-xs text-[var(--color-text-secondary)] font-mono">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4" />
            <span>Last Checked: {formatTime(lastUpdated)}</span>
          </div>
          <div className="flex items-center gap-2">
            <span>Poll Interval: 15s</span>
          </div>
          <div className="flex items-center gap-2">
            <span>Environment: {app?.environment || 'unknown'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span>API Version: {app?.version || '0.1.0'}</span>
          </div>
        </div>
      </div>

      {/* Infrastructure Telemetry Grid */}
      <section aria-labelledby="telemetry-heading">
        <div className="flex items-center justify-between mb-4">
          <h3 id="telemetry-heading" className="text-sm font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
            Infrastructure Telemetry
          </h3>
          <span className="text-xs text-[var(--color-text-secondary)]">
            Live backend telemetry (No simulated metrics)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* 1. FastAPI Card */}
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 hover:border-[var(--color-border)]/80 transition-colors">
            <div className="flex items-start justify-between">
              <div className="p-2 rounded-lg bg-[var(--color-accent)]/10 text-[var(--color-accent)]">
                <Server className="w-5 h-5" />
              </div>
              <StatusBadge status={app?.status || 'unknown'} />
            </div>
            <div className="mt-4">
              <h4 className="text-base font-semibold text-[var(--color-text-primary)]">
                API Application Server
              </h4>
              <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                FastAPI Modular Monolith
              </p>
            </div>
            <div className="mt-4 pt-4 border-t border-[var(--color-border)]/60 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Status:</span>
                <span className="text-[var(--color-text-primary)] font-semibold">{app?.status?.toUpperCase() || 'UNREACHABLE'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Engine:</span>
                <span className="text-[var(--color-text-primary)]">Python 3.12 / Uvicorn</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Version:</span>
                <span className="text-[var(--color-text-primary)]">{app?.version || '0.1.0'}</span>
              </div>
            </div>
          </div>

          {/* 2. MongoDB Card */}
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 hover:border-[var(--color-border)]/80 transition-colors">
            <div className="flex items-start justify-between">
              <div className="p-2 rounded-lg bg-[var(--color-success)]/10 text-[var(--color-success)]">
                <Database className="w-5 h-5" />
              </div>
              <StatusBadge status={database?.status || 'unknown'} />
            </div>
            <div className="mt-4">
              <h4 className="text-base font-semibold text-[var(--color-text-primary)]">
                MongoDB Document Store
              </h4>
              <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                Async Motor Driver
              </p>
            </div>
            <div className="mt-4 pt-4 border-t border-[var(--color-border)]/60 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Ping Latency:</span>
                <span className="text-[var(--color-text-primary)]">
                  {database?.latency_ms !== null && database?.latency_ms !== undefined
                    ? `${database.latency_ms} ms`
                    : 'N/A'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Target Database:</span>
                <span className="text-[var(--color-text-primary)]">sentinelrag</span>
              </div>
              {database?.error && (
                <div className="text-[var(--color-danger)] text-[11px] truncate" title={database.error}>
                  Error: {database.error}
                </div>
              )}
            </div>
          </div>

          {/* 3. ChromaDB Card */}
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 hover:border-[var(--color-border)]/80 transition-colors">
            <div className="flex items-start justify-between">
              <div className="p-2 rounded-lg bg-[var(--color-accent)]/10 text-[var(--color-accent)]">
                <Layers className="w-5 h-5" />
              </div>
              <StatusBadge status={vectorStore?.status || 'unknown'} />
            </div>
            <div className="mt-4">
              <h4 className="text-base font-semibold text-[var(--color-text-primary)]">
                ChromaDB Vector Store
              </h4>
              <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                Local Persistent Storage
              </p>
            </div>
            <div className="mt-4 pt-4 border-t border-[var(--color-border)]/60 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Collections:</span>
                <span className="text-[var(--color-text-primary)]">
                  {vectorStore?.collections ? vectorStore.collections.length : 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Check Latency:</span>
                <span className="text-[var(--color-text-primary)]">
                  {vectorStore?.latency_ms !== null && vectorStore?.latency_ms !== undefined
                    ? `${vectorStore.latency_ms} ms`
                    : 'N/A'}
                </span>
              </div>
              {vectorStore?.error && (
                <div className="text-[var(--color-danger)] text-[11px] truncate" title={vectorStore.error}>
                  Error: {vectorStore.error}
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Architecture Modules (Roadmap placeholders) */}
      <section aria-labelledby="roadmap-heading">
        <h3 id="roadmap-heading" className="text-sm font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-4">
          Upcoming Pipeline Modules
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="rounded-xl border border-[var(--color-border)]/60 bg-[var(--color-surface)]/40 p-5 opacity-75">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
              <span className="font-mono text-[var(--color-accent)]">PHASE 3</span>
              <span>Document Pipeline</span>
            </div>
            <h4 className="text-base font-semibold text-[var(--color-text-primary)] mt-2">
              Ingestion & Security Scan
            </h4>
            <p className="text-xs text-[var(--color-text-secondary)] mt-1">
              PyMuPDF extraction, token chunking, and deterministic injection risk screening.
            </p>
          </div>

          <div className="rounded-xl border border-[var(--color-border)]/60 bg-[var(--color-surface)]/40 p-5 opacity-75">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
              <span className="font-mono text-[var(--color-accent)]">PHASE 4 & 6</span>
              <span>RAG Engine</span>
            </div>
            <h4 className="text-base font-semibold text-[var(--color-text-primary)] mt-2">
              Secure Retrieval & Generation
            </h4>
            <p className="text-xs text-[var(--color-text-secondary)] mt-1">
              Owner-scoped vector retrieval, untrusted context boundaries, and output validation.
            </p>
          </div>

          <div className="rounded-xl border border-[var(--color-border)]/60 bg-[var(--color-surface)]/40 p-5 opacity-75">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
              <span className="font-mono text-[var(--color-accent)]">PHASE 7</span>
              <span>Adversarial Testing</span>
            </div>
            <h4 className="text-base font-semibold text-[var(--color-text-primary)] mt-2">
              Attack Simulator Lab
            </h4>
            <p className="text-xs text-[var(--color-text-secondary)] mt-1">
              Safe execution sandbox with synthetic canaries, ASR metrics, and defense benchmarking.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};
