import { useState, useEffect } from 'react';
import {
  FlaskConical,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Trash2,
  CheckSquare,
  Square,
  Layers,
  X,
  History,
  Activity,
  AlertOctagon,
} from 'lucide-react';
import { simulatorApi } from '../services/api';
import type {
  AttackScenario,
  ScenarioExecutionResult,
  SimulationRun,
  SimulationStats,
  SimulationVerdict,
} from '../types';

const CATEGORIES = [
  { id: 'all', label: 'All Scenarios' },
  { id: 'direct_prompt_injection', label: 'Direct Injection' },
  { id: 'system_prompt_extraction', label: 'System Extraction' },
  { id: 'indirect_prompt_injection', label: 'Indirect Injection' },
  { id: 'data_exfiltration', label: 'Data Exfiltration' },
  { id: 'cross_tenant_access', label: 'Cross-Tenant Access' },
  { id: 'obfuscated_injection', label: 'Obfuscated Attacks' },
  { id: 'credential_canary_leakage', label: 'Canary & Credentials' },
  { id: 'malicious_output', label: 'Malicious Output' },
];

export function SimulatorPage() {
  const [activeTab, setActiveTab] = useState<'catalog' | 'history'>('catalog');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [selectedScenarioIds, setSelectedScenarioIds] = useState<Set<string>>(new Set());
  const [stats, setStats] = useState<SimulationStats | null>(null);
  const [runs, setRuns] = useState<SimulationRun[]>([]);

  const [isLoadingScenarios, setIsLoadingScenarios] = useState(true);
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionRun, setExecutionRun] = useState<SimulationRun | null>(null);
  const [selectedResult, setSelectedResult] = useState<ScenarioExecutionResult | null>(null);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Load scenarios and stats on mount
  useEffect(() => {
    loadScenarios();
    loadStats();
  }, []);

  // Reload scenarios when category filter changes
  useEffect(() => {
    loadScenarios(selectedCategory);
  }, [selectedCategory]);

  // Load history runs when switching to history tab
  useEffect(() => {
    if (activeTab === 'history') {
      loadHistory();
    }
  }, [activeTab]);

  const loadScenarios = async (category?: string) => {
    setIsLoadingScenarios(true);
    setErrorMsg(null);
    try {
      const res = await simulatorApi.listScenarios(category);
      setScenarios(res.data.scenarios);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load attack scenario catalog.');
    } finally {
      setIsLoadingScenarios(false);
    }
  };

  const loadStats = async () => {
    try {
      const res = await simulatorApi.getStats();
      setStats(res.data);
    } catch (err: any) {
      console.error('Failed to load simulator stats', err);
    }
  };

  const loadHistory = async () => {
    setErrorMsg(null);
    try {
      const res = await simulatorApi.listRuns();
      setRuns(res.data.runs);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load simulation history.');
    }
  };

  const toggleSelectScenario = (id: string) => {
    setSelectedScenarioIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const selectAllFiltered = () => {
    setSelectedScenarioIds(new Set(scenarios.map((s) => s.scenario_id)));
  };

  const deselectAll = () => {
    setSelectedScenarioIds(new Set());
  };

  // Run simulation batch
  const handleExecute = async (scenarioIds?: string[], category?: string) => {
    setIsExecuting(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const payload: { scenario_ids?: string[]; category?: string } = {};
      if (scenarioIds && scenarioIds.length > 0) {
        payload.scenario_ids = scenarioIds;
      } else if (category && category !== 'all') {
        payload.category = category;
      }
      const res = await simulatorApi.createRun(payload);
      setExecutionRun(res.data);
      setSuccessMsg(
        `Simulation completed: ${res.data.summary.blocked}/${res.data.summary.total_executed} attacks prevented (${res.data.summary.block_rate_percent}% block rate).`
      );
      loadStats();
    } catch (err: any) {
      setErrorMsg(err.message || 'Simulation execution failed.');
    } finally {
      setIsExecuting(false);
    }
  };

  // Delete run
  const handleDeleteRun = async (runId: string) => {
    try {
      await simulatorApi.deleteRun(runId);
      setRuns((prev) => prev.filter((r) => r.id !== runId));
      if (executionRun?.id === runId) {
        setExecutionRun(null);
      }
      loadStats();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete simulation run.');
    }
  };

  // Helper for verdict styling and icons
  const renderVerdictBadge = (verdict: SimulationVerdict | string) => {
    switch (verdict) {
      case 'blocked':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3.5 h-3.5" />
            Blocked
          </span>
        );
      case 'detected_not_blocked':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3.5 h-3.5" />
            Detected Not Blocked
          </span>
        );
      case 'attack_succeeded':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-3.5 h-3.5" />
            Attack Succeeded
          </span>
        );
      case 'error':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
            <XCircle className="w-3.5 h-3.5" />
            Error
          </span>
        );
      case 'inconclusive':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
            <HelpCircle className="w-3.5 h-3.5" />
            Inconclusive
          </span>
        );
    }
  };

  const renderSeverityPill = (severity: string) => {
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

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner / Metrics Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Total Executions</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {stats?.total_executed ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Across {stats?.total_runs ?? 0} simulation runs
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Attacks Prevented</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400">
            {stats?.blocked ?? 0}
          </div>
          <div className="text-[11px] text-emerald-500/80 mt-0.5 font-medium">
            {stats?.block_rate_percent ?? 0}% Overall Block Rate
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Detected (Permitted)</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400">
            {stats?.detected_not_blocked ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Flagged but allowed by policy
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Attack Succeeded</span>
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400">
            {stats?.attack_succeeded ?? 0}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Bypassed gateway controls
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Inconclusive / Error</span>
            <HelpCircle className="w-4 h-4 text-zinc-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-zinc-300">
            {(stats?.inconclusive ?? 0) + (stats?.error ?? 0)}
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5">
            Execution anomalies
          </div>
        </div>
      </div>

      {/* Notifications */}
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

      {successMsg && (
        <div className="flex items-center justify-between p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Main Tabs Navigation */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTab('catalog')}
            className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-medium transition-all ${
              activeTab === 'catalog'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Attack Scenario Library
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-medium transition-all ${
              activeTab === 'history'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Simulation History
          </button>
        </div>

        {activeTab === 'catalog' && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExecute(undefined, selectedCategory)}
              disabled={isExecuting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700/80 transition-all disabled:opacity-50"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isExecuting ? 'animate-spin' : ''}`} />
              Run All Filtered ({scenarios.length})
            </button>
            <button
              onClick={() => handleExecute(Array.from(selectedScenarioIds))}
              disabled={isExecuting || selectedScenarioIds.size === 0}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow-md shadow-indigo-500/20 transition-all disabled:opacity-50 disabled:shadow-none"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Run Selected ({selectedScenarioIds.size})
            </button>
          </div>
        )}
      </div>

      {/* Tab 1: Attack Scenario Library & Execution */}
      {activeTab === 'catalog' && (
        <div className="space-y-6">
          {/* Category Filter Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
            {CATEGORIES.map((cat) => (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                  selectedCategory === cat.id
                    ? 'bg-zinc-800 text-white border border-zinc-700 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>

          {/* Selection Utilities Bar */}
          <div className="flex items-center justify-between text-xs text-zinc-400 bg-zinc-900/60 p-2.5 rounded-xl border border-zinc-800/80">
            <div className="flex items-center gap-3">
              <button
                onClick={selectAllFiltered}
                className="inline-flex items-center gap-1 text-zinc-300 hover:text-white"
              >
                <CheckSquare className="w-3.5 h-3.5 text-indigo-400" />
                Select All
              </button>
              <button
                onClick={deselectAll}
                className="inline-flex items-center gap-1 text-zinc-400 hover:text-zinc-200"
              >
                <Square className="w-3.5 h-3.5" />
                Deselect All
              </button>
              <span className="text-zinc-500">|</span>
              <span>
                {selectedScenarioIds.size} of {scenarios.length} scenarios selected
              </span>
            </div>
            {isExecuting && (
              <div className="flex items-center gap-2 text-indigo-400 font-medium">
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                Executing adversarial tests against Security Gateway...
              </div>
            )}
          </div>

          {/* Active Run Results Drawer (if available) */}
          {executionRun && (
            <div className="p-5 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-4">
              <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                    <FlaskConical className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Active Simulation Execution Results
                    </h3>
                    <p className="text-xs text-zinc-400">
                      Run ID: <span className="font-mono text-zinc-300">{executionRun.id}</span> • {executionRun.duration_ms} ms total
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
                    {executionRun.summary.blocked} / {executionRun.summary.total_executed} Blocked ({executionRun.summary.block_rate_percent}%)
                  </span>
                  <button
                    onClick={() => setExecutionRun(null)}
                    className="p-1 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Results Grid / List */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[380px] overflow-y-auto pr-1">
                {executionRun.results.map((res, idx) => (
                  <div
                    key={idx}
                    onClick={() => setSelectedResult(res)}
                    className="p-3.5 rounded-xl bg-zinc-950/80 border border-zinc-800/90 hover:border-zinc-700/80 cursor-pointer transition-all space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-zinc-200 truncate max-w-[200px]">
                        {res.scenario_name}
                      </span>
                      {renderVerdictBadge(res.verdict)}
                    </div>
                    <p className="text-[11px] text-zinc-400 line-clamp-1 italic">
                      "{res.input_payload_summary}"
                    </p>
                    <div className="flex items-center justify-between text-[10px] text-zinc-500 pt-1 border-t border-zinc-850">
                      <span>Gateway: <span className="font-mono uppercase text-zinc-300">{res.actual_decision}</span></span>
                      <span>{res.duration_ms} ms</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scenario Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {isLoadingScenarios ? (
              <div className="col-span-full py-12 text-center text-xs text-zinc-500 flex items-center justify-center gap-2">
                <RotateCcw className="w-4 h-4 animate-spin text-indigo-400" />
                Loading attack scenarios...
              </div>
            ) : scenarios.length === 0 ? (
              <div className="col-span-full py-12 text-center text-xs text-zinc-500">
                No attack scenarios found for the selected category.
              </div>
            ) : (
              scenarios.map((scen) => {
                const isSelected = selectedScenarioIds.has(scen.scenario_id);
                return (
                  <div
                    key={scen.scenario_id}
                    className={`rounded-2xl p-4 transition-all flex flex-col justify-between border ${
                      isSelected
                        ? 'bg-zinc-900 border-indigo-500/50 shadow-md shadow-indigo-500/5'
                        : 'bg-zinc-900/70 border-zinc-800/80 hover:border-zinc-700'
                    }`}
                  >
                    <div>
                      {/* Card Header */}
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => toggleSelectScenario(scen.scenario_id)}
                            className="text-zinc-400 hover:text-white"
                          >
                            {isSelected ? (
                              <CheckSquare className="w-4 h-4 text-indigo-400" />
                            ) : (
                              <Square className="w-4 h-4 text-zinc-600" />
                            )}
                          </button>
                          <span className="text-[11px] font-mono text-zinc-400 font-medium">
                            {scen.scenario_id}
                          </span>
                        </div>
                        {renderSeverityPill(scen.severity)}
                      </div>

                      {/* Card Title & Description */}
                      <h4 className="text-sm font-semibold text-white mt-2.5">
                        {scen.name}
                      </h4>
                      <p className="text-xs text-zinc-400 mt-1 line-clamp-2 leading-relaxed">
                        {scen.description}
                      </p>

                      {/* Expected Behavior Snippet */}
                      <div className="mt-3 p-2.5 rounded-xl bg-zinc-950/60 border border-zinc-850 text-[11px] text-zinc-400">
                        <span className="font-semibold text-zinc-300">Expected: </span>
                        {scen.expected_behavior}
                      </div>
                    </div>

                    {/* Action Footer */}
                    <div className="mt-4 pt-3 border-t border-zinc-800/80 flex items-center justify-between">
                      <span className="text-[10px] uppercase font-mono text-zinc-500">
                        {scen.attack_type.replace('_', ' ')}
                      </span>
                      <button
                        onClick={() => handleExecute([scen.scenario_id])}
                        disabled={isExecuting}
                        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors disabled:opacity-50"
                      >
                        <Play className="w-3 h-3 fill-current text-indigo-400" />
                        Simulate
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Simulation History */}
      {activeTab === 'history' && (
        <div className="rounded-2xl bg-zinc-900 border border-zinc-800 shadow-sm overflow-hidden">
          <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Past Simulation Executions</h3>
            <span className="text-xs text-zinc-400">{runs.length} runs recorded</span>
          </div>

          {runs.length === 0 ? (
            <div className="py-12 text-center text-xs text-zinc-500">
              No simulation history recorded yet. Execute a simulation to audit results.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-zinc-300">
                <thead className="bg-zinc-950 text-zinc-400 uppercase text-[10px] font-mono border-b border-zinc-800">
                  <tr>
                    <th className="py-3 px-4">Run ID</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Scenarios</th>
                    <th className="py-3 px-4">Prevented</th>
                    <th className="py-3 px-4">Block Rate</th>
                    <th className="py-3 px-4">Duration</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/70">
                  {runs.map((run) => (
                    <tr key={run.id} className="hover:bg-zinc-850/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-medium text-white">{run.id}</td>
                      <td className="py-3 px-4 text-zinc-400">
                        {new Date(run.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4">{run.scenarios_count} tests</td>
                      <td className="py-3 px-4">
                        <span className="text-emerald-400 font-semibold">{run.summary.blocked}</span> / {run.summary.total_executed}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          {run.summary.block_rate_percent}%
                        </span>
                      </td>
                      <td className="py-3 px-4 text-zinc-400">{run.duration_ms} ms</td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => {
                            setExecutionRun(run);
                            setActiveTab('catalog');
                          }}
                          className="px-2.5 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium"
                        >
                          View Results
                        </button>
                        <button
                          onClick={() => handleDeleteRun(run.id)}
                          className="p-1 rounded-lg text-rose-400 hover:bg-rose-500/10"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Execution Result Detail Modal */}
      {selectedResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-3xl max-w-xl w-full p-6 space-y-4 shadow-2xl relative">
            <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-zinc-400">{selectedResult.scenario_id}</span>
                  {renderSeverityPill(selectedResult.severity)}
                </div>
                <h3 className="text-base font-bold text-white mt-1">
                  {selectedResult.scenario_name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedResult(null)}
                className="p-1 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Verdict Callout */}
            <div className="p-3.5 rounded-2xl bg-zinc-950 border border-zinc-800 flex items-center justify-between">
              <div>
                <span className="text-xs text-zinc-400 font-medium">Evaluation Verdict</span>
                <div className="mt-1">{renderVerdictBadge(selectedResult.verdict)}</div>
              </div>
              <div className="text-right">
                <span className="text-xs text-zinc-400 font-medium">Gateway Decision</span>
                <div className="mt-1 font-mono uppercase text-xs font-bold text-zinc-200">
                  {selectedResult.actual_decision}
                </div>
              </div>
            </div>

            {/* Reason Explanation */}
            <div className="space-y-1">
              <span className="text-xs font-semibold text-zinc-300">Enforcement Reason</span>
              <p className="text-xs text-zinc-400 leading-relaxed bg-zinc-950/60 p-3 rounded-xl border border-zinc-800/80">
                {selectedResult.verdict_reason}
              </p>
            </div>

            {/* Input Payload */}
            <div className="space-y-1">
              <span className="text-xs font-semibold text-zinc-300">Sanitized Attack Input</span>
              <pre className="text-xs font-mono text-zinc-400 bg-zinc-950 p-3 rounded-xl border border-zinc-800/80 overflow-x-auto whitespace-pre-wrap">
                {selectedResult.input_payload_summary}
              </pre>
            </div>

            {/* Signals Detected */}
            {selectedResult.signals_detected && selectedResult.signals_detected.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-zinc-300">
                  Intercepted Threat Signals ({selectedResult.signals_detected.length})
                </span>
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {selectedResult.signals_detected.map((sig, sIdx) => (
                    <div
                      key={sIdx}
                      className="p-2.5 rounded-xl bg-zinc-950/90 border border-zinc-800/80 text-xs text-zinc-300 flex items-center justify-between"
                    >
                      <span className="font-mono text-indigo-400 font-medium">
                        {sig.pattern_name || sig.type || 'Detection Signal'}
                      </span>
                      <span className="text-zinc-500 text-[10px] font-mono uppercase">
                        {sig.severity || 'high'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Modal Footer */}
            <div className="pt-2 border-t border-zinc-800 flex items-center justify-between text-xs text-zinc-500">
              <span>Latency: {selectedResult.duration_ms} ms</span>
              <button
                onClick={() => setSelectedResult(null)}
                className="px-4 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-medium transition-colors"
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
