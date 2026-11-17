import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  FileWarning,
  Eye,
  RefreshCw,
  Search,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  X,
  Lock,
  Layers,
  Sparkles,
} from 'lucide-react';
import { securityCenterApi } from '../services/api';
import type {
  SecurityOverviewMetrics,
  SecurityActivityData,
  ThreatDistributionData,
  SimulationAnalyticsData,
  SecurityEventDetail,
} from '../types';

export function SecurityCenterPage() {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d' | '90d'>('7d');

  // Dashboard Data States
  const [overview, setOverview] = useState<SecurityOverviewMetrics | null>(null);
  const [activity, setActivity] = useState<SecurityActivityData | null>(null);
  const [threatDist, setThreatDist] = useState<ThreatDistributionData | null>(null);
  const [simAnalytics, setSimAnalytics] = useState<SimulationAnalyticsData | null>(null);

  // Events Explorer States
  const [events, setEvents] = useState<SecurityEventDetail[]>([]);
  const [totalEventsCount, setTotalEventsCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(0);
  const pageSize = 15;

  // Filters
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterDecision, setFilterDecision] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modals & Loaders
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingEvents, setIsLoadingEvents] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const daysMap = { '24h': 1, '7d': 7, '30d': 30, '90d': 90 };

  // Load all analytics when timeRange changes
  useEffect(() => {
    loadAllAnalytics();
  }, [timeRange]);

  // Reload events when filters or pagination change
  useEffect(() => {
    loadEvents();
  }, [timeRange, filterCategory, filterSeverity, filterDecision, currentPage]);

  const loadAllAnalytics = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    const days = daysMap[timeRange];
    try {
      const [ovRes, actRes, distRes, simRes] = await Promise.all([
        securityCenterApi.getOverview(days),
        securityCenterApi.getActivity(timeRange),
        securityCenterApi.getThreatDistribution(days),
        securityCenterApi.getSimulationAnalytics(),
      ]);
      setOverview(ovRes.data);
      setActivity(actRes.data);
      setThreatDist(distRes.data);
      setSimAnalytics(simRes.data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load security analytics telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  const loadEvents = async () => {
    setIsLoadingEvents(true);
    try {
      const res = await securityCenterApi.listEvents({
        category: filterCategory !== 'all' ? filterCategory : undefined,
        severity: filterSeverity !== 'all' ? filterSeverity : undefined,
        decision: filterDecision !== 'all' ? filterDecision : undefined,
        search: searchQuery.trim() || undefined,
        days: daysMap[timeRange],
        limit: pageSize,
        skip: currentPage * pageSize,
      });
      setEvents(res.data.events);
      setTotalEventsCount(res.data.total);
    } catch (err: any) {
      console.error('Failed to load security events', err);
    } finally {
      setIsLoadingEvents(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCurrentPage(0);
    loadEvents();
  };

  // Helper for severity pills
  const renderSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-rose-500/20 text-rose-400 border border-rose-500/30">
            Critical
          </span>
        );
      case 'high':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-amber-500/20 text-amber-400 border border-amber-500/30">
            High
          </span>
        );
      case 'medium':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
            Medium
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-blue-500/20 text-blue-400 border border-blue-500/30">
            Low
          </span>
        );
    }
  };

  // Helper for decision badges
  const renderDecisionBadge = (decision: string) => {
    switch (decision.toLowerCase()) {
      case 'block':
      case 'quarantined':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-3 h-3" />
            {decision.toUpperCase()}
          </span>
        );
      case 'sanitize':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Sparkles className="w-3 h-3" />
            SANITIZED
          </span>
        );
      case 'review':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3 h-3" />
            REVIEW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3 h-3" />
            ALLOW
          </span>
        );
    }
  };

  // Calculate max count for activity bar scaling
  const maxActivityCount = Math.max(1, ...(activity?.timeline.map((t) => t.count) || [1]));

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* ------------------------------------------------------------- */}
      {/* SECTION 1: HEADER & TIME RANGE SELECTOR */}
      {/* ------------------------------------------------------------- */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Security Center</h1>
              <p className="text-xs text-zinc-400">
                Real-time threat monitoring, security gateway audits, and adversarial simulation analytics
              </p>
            </div>
          </div>
        </div>

        {/* Time-Range Selector */}
        <div className="flex items-center gap-1 bg-zinc-900 border border-zinc-800 p-1 rounded-xl">
          {(['24h', '7d', '30d', '90d'] as const).map((r) => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold uppercase transition-all ${
                timeRange === r
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {r}
            </button>
          ))}
          <button
            onClick={() => {
              loadAllAnalytics();
              loadEvents();
            }}
            title="Refresh telemetry"
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors ml-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-indigo-400' : ''}`} />
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="flex items-center justify-between p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-rose-400 hover:text-rose-200">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* SECTION 2: OVERVIEW KPI CARDS */}
      {/* ------------------------------------------------------------- */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Security Events</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {overview?.total_events ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Real incident telemetry
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Blocked Queries</span>
            <Lock className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400">
            {overview?.blocked_queries ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Pre-retrieval / Pre-LLM
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Document Threats</span>
            <FileWarning className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400">
            {overview?.document_threats_detected ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Quarantined / under review
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Output Interventions</span>
            <Sparkles className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-indigo-400">
            {overview?.output_interventions ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Canaries & sanitized keys
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Simulated Attacks</span>
            <Layers className="w-4 h-4 text-zinc-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-zinc-200">
            {overview?.total_simulations ?? 0} runs
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            {overview?.simulated_attacks_prevented ?? 0} prevented
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Sim. Breaches</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400">
            {overview?.simulated_attacks_succeeded ?? 0}
          </div>
          <div className="text-[11px] text-emerald-400 mt-0.5 font-medium">
            {overview?.simulation_block_rate_percent ?? 0}% Lab Block Rate
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 3: ACTIVITY TIMELINE & THREAT DISTRIBUTION */}
      {/* ------------------------------------------------------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart (2 Cols) */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Security Activity Timeline</h3>
              <p className="text-xs text-zinc-400">Event occurrences across {timeRange}</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-zinc-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-500" /> Critical
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500" /> High
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-indigo-500" /> Medium/Low
              </span>
            </div>
          </div>

          {/* Timeline Visual Bars */}
          <div className="h-44 flex items-end gap-1.5 pt-4 pb-2">
            {activity?.timeline && activity.timeline.length > 0 ? (
              activity.timeline.map((bucket, idx) => {
                const heightPercent = Math.max(8, (bucket.count / maxActivityCount) * 100);
                const hasCritical = bucket.critical > 0;
                const hasHigh = bucket.high > 0;
                return (
                  <div
                    key={idx}
                    className="flex-1 flex flex-col items-center justify-end h-full group relative"
                  >
                    {/* Tooltip on hover */}
                    <div className="absolute -top-12 hidden group-hover:flex flex-col items-center z-20 pointer-events-none">
                      <div className="px-2 py-1 rounded bg-zinc-950 border border-zinc-800 text-[10px] text-zinc-200 whitespace-nowrap shadow-xl">
                        <span className="font-bold">{bucket.label}</span>: {bucket.count} event{bucket.count !== 1 ? 's' : ''}
                      </div>
                    </div>

                    <div
                      style={{ height: `${bucket.count > 0 ? heightPercent : 4}%` }}
                      className={`w-full rounded-t transition-all ${
                        bucket.count === 0
                          ? 'bg-zinc-800/40'
                          : hasCritical
                          ? 'bg-rose-500 hover:bg-rose-400'
                          : hasHigh
                          ? 'bg-amber-500 hover:bg-amber-400'
                          : 'bg-indigo-500 hover:bg-indigo-400'
                      }`}
                    />
                    <span className="text-[9px] text-zinc-500 mt-1 truncate max-w-[32px]">
                      {bucket.label}
                    </span>
                  </div>
                );
              })
            ) : (
              <div className="w-full h-full flex items-center justify-center text-xs text-zinc-500">
                No activity recorded in the selected time range.
              </div>
            )}
          </div>
        </div>

        {/* Threat Distribution (1 Col) */}
        <div className="p-5 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm space-y-4">
          <div className="border-b border-zinc-800 pb-3">
            <h3 className="text-sm font-semibold text-white">Threat Categories</h3>
            <p className="text-xs text-zinc-400">Distribution by attack vector</p>
          </div>

          <div className="space-y-3 max-h-[190px] overflow-y-auto pr-1">
            {threatDist?.categories && threatDist.categories.length > 0 ? (
              threatDist.categories.map((cat, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-300 font-medium">{cat.label}</span>
                    <span className="text-zinc-400 font-mono">
                      {cat.count} ({cat.percentage}%)
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      style={{ width: `${cat.percentage}%` }}
                      className="h-full bg-indigo-500 rounded-full"
                    />
                  </div>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-xs text-zinc-500">
                No threats detected in this period.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 4: CONTROLLED ATTACK SIMULATION PERFORMANCE */}
      {/* ------------------------------------------------------------- */}
      <div className="p-5 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                Controlled Environment
              </span>
              <h3 className="text-sm font-semibold text-white">Attack Simulator Lab Performance</h3>
            </div>
            <p className="text-xs text-zinc-400 mt-0.5">
              Synthetic adversarial test results evaluating Security Gateway enforcement
            </p>
          </div>
          <Link
            to="/simulator"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-indigo-400 border border-zinc-700 transition-colors w-fit"
          >
            Open Attack Simulator
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-1">
          <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-center">
            <span className="text-[11px] text-zinc-400">Total Executed</span>
            <div className="text-lg font-bold text-white mt-1">
              {simAnalytics?.total_executed ?? 0}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-center">
            <span className="text-[11px] text-emerald-400">Blocked</span>
            <div className="text-lg font-bold text-emerald-400 mt-1">
              {simAnalytics?.blocked ?? 0}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-center">
            <span className="text-[11px] text-amber-400">Detected (Allowed)</span>
            <div className="text-lg font-bold text-amber-400 mt-1">
              {simAnalytics?.detected_not_blocked ?? 0}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-center">
            <span className="text-[11px] text-rose-400">Succeeded</span>
            <div className="text-lg font-bold text-rose-400 mt-1">
              {simAnalytics?.attack_succeeded ?? 0}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 text-center">
            <span className="text-[11px] text-zinc-400">Block Rate</span>
            <div className="text-lg font-bold text-emerald-400 mt-1">
              {simAnalytics?.block_rate_percent ?? 0}%
            </div>
          </div>
        </div>

        {/* Categories tested in simulator */}
        {simAnalytics?.categories && simAnalytics.categories.length > 0 && (
          <div className="pt-2">
            <h4 className="text-xs font-semibold text-zinc-300 mb-2">Simulated Attack Breakdown by Category</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2.5">
              {simAnalytics.categories.map((c, i) => (
                <div key={i} className="p-2.5 rounded-xl bg-zinc-950/70 border border-zinc-850 text-xs space-y-1">
                  <div className="flex items-center justify-between text-zinc-300 font-medium">
                    <span className="truncate max-w-[140px]">{c.label}</span>
                    <span className="text-emerald-400 font-mono">{c.block_rate_percent}%</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-zinc-500">
                    <span>{c.blocked}/{c.total} blocked</span>
                    {c.attack_succeeded > 0 && (
                      <span className="text-rose-400">{c.attack_succeeded} breached</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 5 & 6: SECURITY EVENT EXPLORER */}
      {/* ------------------------------------------------------------- */}
      <div className="rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm overflow-hidden space-y-4 p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-white">Security Event Explorer</h3>
            <p className="text-xs text-zinc-400">Search and audit live security incidents and policy decisions</p>
          </div>
          <span className="text-xs text-zinc-500 font-mono">
            {totalEventsCount} Total Incidents Logged
          </span>
        </div>

        {/* Filter Controls Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2.5 text-xs">
          {/* Category Filter */}
          <select
            value={filterCategory}
            onChange={(e) => {
              setFilterCategory(e.target.value);
              setCurrentPage(0);
            }}
            className="p-2 rounded-xl bg-zinc-950 border border-zinc-800 text-zinc-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Categories</option>
            <option value="prompt_injection">Prompt Injection</option>
            <option value="document_security">Document Security</option>
            <option value="cross_tenant_access">Cross-Tenant Access</option>
            <option value="credential_leakage">Canary & Credentials</option>
            <option value="output_security">Output Security</option>
          </select>

          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => {
              setFilterSeverity(e.target.value);
              setCurrentPage(0);
            }}
            className="p-2 rounded-xl bg-zinc-950 border border-zinc-800 text-zinc-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Decision Filter */}
          <select
            value={filterDecision}
            onChange={(e) => {
              setFilterDecision(e.target.value);
              setCurrentPage(0);
            }}
            className="p-2 rounded-xl bg-zinc-950 border border-zinc-800 text-zinc-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Decisions</option>
            <option value="block">Blocked</option>
            <option value="quarantined">Quarantined</option>
            <option value="sanitize">Sanitized</option>
            <option value="review">Review</option>
            <option value="allow">Allowed</option>
          </select>

          {/* Search Box */}
          <form onSubmit={handleSearchSubmit} className="md:col-span-2 flex items-center gap-1.5">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-zinc-500" />
              <input
                type="text"
                placeholder="Search reason code or resource ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-2 rounded-xl bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold"
            >
              Search
            </button>
          </form>
        </div>

        {/* Events Table */}
        <div className="overflow-x-auto rounded-xl border border-zinc-800">
          <table className="w-full text-left text-xs text-zinc-300">
            <thead className="bg-zinc-950 text-zinc-400 uppercase text-[10px] font-mono border-b border-zinc-800">
              <tr>
                <th className="py-2.5 px-3.5">Event Type</th>
                <th className="py-2.5 px-3.5">Severity</th>
                <th className="py-2.5 px-3.5">Decision</th>
                <th className="py-2.5 px-3.5">Reason Code</th>
                <th className="py-2.5 px-3.5">Resource</th>
                <th className="py-2.5 px-3.5">Timestamp</th>
                <th className="py-2.5 px-3.5 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70">
              {isLoadingEvents ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-zinc-500">
                    <RefreshCw className="w-4 h-4 animate-spin text-indigo-400 inline mr-2" />
                    Loading events...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-zinc-500">
                    No security events match the selected criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-zinc-850/40 transition-colors">
                    <td className="py-2.5 px-3.5 font-mono text-zinc-200">{ev.event_type}</td>
                    <td className="py-2.5 px-3.5">{renderSeverityBadge(ev.severity)}</td>
                    <td className="py-2.5 px-3.5">{renderDecisionBadge(ev.decision)}</td>
                    <td className="py-2.5 px-3.5 font-mono text-[11px] text-zinc-400">{ev.reason_code}</td>
                    <td className="py-2.5 px-3.5 text-zinc-400 text-[11px]">
                      {ev.resource_type}: <span className="font-mono text-zinc-300">{ev.resource_id ? ev.resource_id.slice(0, 10) + '...' : 'none'}</span>
                    </td>
                    <td className="py-2.5 px-3.5 text-zinc-500 text-[11px]">
                      {new Date(ev.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3.5 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="p-1 rounded-lg text-indigo-400 hover:text-indigo-300 hover:bg-zinc-800 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="flex items-center justify-between text-xs text-zinc-500 pt-1">
          <span>
            Showing {events.length > 0 ? currentPage * pageSize + 1 : 0} to{' '}
            {Math.min((currentPage + 1) * pageSize, totalEventsCount)} of {totalEventsCount} incidents
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage((p) => Math.max(0, p - 1))}
              disabled={currentPage === 0}
              className="p-1.5 rounded-lg border border-zinc-800 text-zinc-400 hover:text-white disabled:opacity-30 disabled:pointer-events-none"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span className="px-2 font-mono">Page {currentPage + 1}</span>
            <button
              onClick={() => setCurrentPage((p) => p + 1)}
              disabled={(currentPage + 1) * pageSize >= totalEventsCount}
              className="p-1.5 rounded-lg border border-zinc-800 text-zinc-400 hover:text-white disabled:opacity-30 disabled:pointer-events-none"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* EVENT DETAIL INSPECTION MODAL */}
      {/* ------------------------------------------------------------- */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-3xl max-w-xl w-full p-6 space-y-4 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-zinc-500">Event ID: {selectedEvent.id}</span>
                  {renderSeverityBadge(selectedEvent.severity)}
                </div>
                <h3 className="text-base font-bold text-white mt-1">
                  {selectedEvent.event_type}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500">Policy Decision</span>
                <div className="mt-1">{renderDecisionBadge(selectedEvent.decision)}</div>
              </div>
              <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500">Reason Code</span>
                <div className="mt-1 font-mono text-zinc-200 font-semibold">{selectedEvent.reason_code}</div>
              </div>
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-zinc-400 font-medium">Detector Information</span>
              <div className="p-2.5 rounded-xl bg-zinc-950 border border-zinc-800/80 font-mono text-zinc-300 flex justify-between">
                <span>{selectedEvent.detector?.name || 'sentinel_security_gateway'}</span>
                <span className="text-zinc-500">v{selectedEvent.detector?.version || '1.0.0'}</span>
              </div>
            </div>

            {selectedEvent.resource_id && (
              <div className="space-y-1 text-xs">
                <span className="text-zinc-400 font-medium">Target Resource ({selectedEvent.resource_type})</span>
                <div className="p-2.5 rounded-xl bg-zinc-950 border border-zinc-800/80 font-mono text-zinc-300">
                  {selectedEvent.resource_id}
                </div>
              </div>
            )}

            {selectedEvent.safe_metadata && Object.keys(selectedEvent.safe_metadata).length > 0 && (
              <div className="space-y-1 text-xs">
                <span className="text-zinc-400 font-medium">Audit Metadata (Redacted / Safe)</span>
                <pre className="p-3 rounded-xl bg-zinc-950 border border-zinc-800/80 font-mono text-[11px] text-zinc-400 whitespace-pre-wrap overflow-x-auto">
                  {JSON.stringify(selectedEvent.safe_metadata, null, 2)}
                </pre>
              </div>
            )}

            <div className="pt-2 border-t border-zinc-800 flex items-center justify-between text-xs text-zinc-500">
              <span>Timestamp: {new Date(selectedEvent.created_at).toLocaleString()}</span>
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

