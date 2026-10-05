import React, { useEffect, useState } from 'react';
import {
  Cpu,
  ShieldAlert,
  ShieldCheck,
  Clock,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Search,
  Filter,
  Sliders,
  Info,
  Lock,
} from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../hooks/useAuth';
import { useWebSocket } from '../hooks/useWebSocket';
import { PreventionStatus, PreventionAction } from '../types';

export const PreventionPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const { subscribe } = useWebSocket();

  const [status, setStatus] = useState<PreventionStatus | null>(null);
  const [actions, setActions] = useState<PreventionAction[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [actionFilter, setActionFilter] = useState('ALL');
  const [searchTarget, setSearchTarget] = useState('');

  // Policy Edit Modal
  const [policyModalOpen, setPolicyModalOpen] = useState(false);
  const [editEnabled, setEditEnabled] = useState(true);
  const [editThreshold, setEditThreshold] = useState(80);
  const [editDuration, setEditDuration] = useState(60);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);

  const fetchPreventionData = async () => {
    try {
      setLoading(true);
      const [statusRes, actionsRes] = await Promise.all([
        api.getPreventionStatus(),
        api.listPreventionActions({ limit: 100 }),
      ]);
      setStatus(statusRes);
      setActions(actionsRes);
      setEditEnabled(statusRes.enabled);
      setEditThreshold(statusRes.auto_block_threshold);
      setEditDuration(statusRes.default_block_duration_minutes);
    } catch (err) {
      console.error('Failed to load prevention data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPreventionData();

    // Subscribe to real-time prevention actions
    const unsub = subscribe('prevention_action.created', (envelope) => {
      setActions((prev) => [envelope.data, ...prev.slice(0, 99)]);
      // Refresh status counts
      api.getPreventionStatus().then(setStatus).catch(console.error);
    });

    return () => {
      unsub();
    };
  }, [subscribe]);

  const handleUpdatePolicies = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingPolicy(true);
    setPolicyError(null);
    try {
      await api.updatePreventionPolicies({
        enabled: editEnabled,
        auto_block_threshold: Number(editThreshold),
        default_block_duration_minutes: Number(editDuration),
      });
      setPolicyModalOpen(false);
      fetchPreventionData();
    } catch (err: any) {
      setPolicyError(err.message || 'Failed to update policy');
    } finally {
      setSavingPolicy(false);
    }
  };

  const filteredActions = actions.filter((act) => {
    if (actionFilter !== 'ALL' && act.action !== actionFilter) return false;
    if (searchTarget && !act.target.toLowerCase().includes(searchTarget.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Cpu className="h-5 w-5 text-cyan-400" />
            Automated Prevention Engine
          </h2>
          <p className="text-xs text-cyber-muted">
            Modular intrusion prevention architecture, safety allowlists, and auditable mock enforcement.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isAdmin && (
            <button
              onClick={() => setPolicyModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/30 hover:bg-cyan-600/50 border border-cyan-500/40 text-cyan-200 text-xs font-semibold transition"
            >
              <Sliders className="h-4 w-4 text-cyan-400" />
              <span>Configure Policy</span>
            </button>
          )}

          <button
            onClick={fetchPreventionData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card hover:bg-cyber-surface border border-cyber-border text-slate-300 text-xs font-medium transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Safety Notice Banner */}
      <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-4 backdrop-blur">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div className="text-xs space-y-1">
            <h4 className="font-semibold text-cyan-300 flex items-center gap-2">
              SAFE LAB DEMO PRESERVATION GUARANTEE
              <span className="text-[10px] bg-cyan-900/60 text-cyan-200 px-2 py-0.5 rounded-full font-mono">
                NON-DESTRUCTIVE
              </span>
            </h4>
            <p className="text-slate-300 leading-relaxed">
              Host operating system firewall rules (iptables / Windows Defender Firewall) are <strong className="text-white">permanently disabled</strong> to protect your host connectivity. Automated prevention executes using <span className="font-mono text-cyan-300">MockPreventionProvider</span>, recording full auditable block decisions, expiry timers, and threat rationales in the database only when all safety criteria pass.
            </p>
          </div>
        </div>
      </div>

      {/* Engine Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Status */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Engine State</span>
          <div className="mt-2 flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                status?.enabled ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
              }`}
            ></span>
            <span className="text-lg font-bold text-white uppercase">
              {status?.enabled ? 'Active / Enabled' : 'Disabled'}
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            Automated policy evaluation for high-confidence threats
          </p>
        </div>

        {/* Active Provider */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Provider Adapter</span>
          <div className="mt-2 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-cyan-400" />
            <span className="text-lg font-bold text-white capitalize font-mono">
              {status?.provider || 'Mock'} Provider
            </span>
          </div>
          <div className="mt-2 text-[11px] text-amber-400 flex items-center gap-1 font-mono">
            <span>Real Firewall: DISABLED</span>
          </div>
        </div>

        {/* Auto Block Threshold */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Auto-Block Trigger Threshold</span>
          <div className="mt-2 flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-rose-400" />
            <span className="text-2xl font-bold font-mono text-rose-400">
              Score &ge; {status?.auto_block_threshold ?? 80}
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            Eligible strictly for CRITICAL severity incidents
          </p>
        </div>

        {/* Active Blocks / Lease */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Active Policy Leases</span>
          <div className="mt-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-cyan-400" />
              <span className="text-2xl font-bold font-mono text-cyan-300">
                {status?.active_blocks_count ?? 0}
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {status?.default_block_duration_minutes ?? 60}m TTL
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            Whitelisted Exemptions: <span className="text-emerald-400 font-mono font-semibold">{status?.whitelisted_count ?? 0}</span>
          </p>
        </div>
      </div>

      {/* Prevention Policy Matrix */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card p-5">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
          <Info className="h-4 w-4 text-cyan-400" />
          Multi-Tier Automated Response Policy Matrix
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* LOW */}
          <div className="rounded-lg border border-slate-800 bg-cyber-surface/40 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400">LOW THREAT</span>
              <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded">
                0 - 29 PTS
              </span>
            </div>
            <div className="mt-3 text-xs font-semibold text-slate-200">LOG_ONLY</div>
            <p className="mt-1 text-[11px] text-slate-400">
              Telemetry recorded in raw security events table. No active response triggered.
            </p>
          </div>

          {/* MEDIUM */}
          <div className="rounded-lg border border-slate-800 bg-cyber-surface/40 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-amber-400">MEDIUM THREAT</span>
              <span className="text-[10px] font-mono bg-amber-500/10 text-amber-400 px-2 py-0.5 rounded">
                30 - 59 PTS
              </span>
            </div>
            <div className="mt-3 text-xs font-semibold text-slate-200">ALERT_ONLY</div>
            <p className="mt-1 text-[11px] text-slate-400">
              Correlation engine creates or updates incident dossier. Analyst notification dispatched.
            </p>
          </div>

          {/* HIGH */}
          <div className="rounded-lg border border-slate-800 bg-cyber-surface/40 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-orange-400">HIGH THREAT</span>
              <span className="text-[10px] font-mono bg-orange-500/10 text-orange-400 px-2 py-0.5 rounded">
                60 - 79 PTS
              </span>
            </div>
            <div className="mt-3 text-xs font-semibold text-slate-200">MONITOR_ONLY</div>
            <p className="mt-1 text-[11px] text-slate-400">
              High-priority SOC dashboard alert. Manual analyst review recommended.
            </p>
          </div>

          {/* CRITICAL */}
          <div className="rounded-lg border border-rose-500/40 bg-rose-950/15 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-rose-400">CRITICAL THREAT</span>
              <span className="text-[10px] font-mono bg-rose-500/20 text-rose-300 px-2 py-0.5 rounded">
                80 - 100 PTS
              </span>
            </div>
            <div className="mt-3 text-xs font-semibold text-rose-200">
              AUTOMATED MOCK BLOCK
            </div>
            <p className="mt-1 text-[11px] text-slate-300">
              Mock provider executes timed software block if allowlist and safety checks pass.
            </p>
          </div>
        </div>
      </div>

      {/* Prevention Action Audit Ledger */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden">
        {/* Table Controls */}
        <div className="p-4 border-b border-cyber-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Prevention Decision & Audit Ledger ({filteredActions.length})
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative">
              <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchTarget}
                onChange={(e) => setSearchTarget(e.target.value)}
                placeholder="Search target IP..."
                className="pl-8 pr-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Filter */}
            <div className="flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 text-slate-400" />
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="py-1.5 px-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Actions</option>
                <option value="BLOCK">BLOCK</option>
                <option value="UNBLOCK">UNBLOCK</option>
                <option value="ALLOWLIST">ALLOWLIST</option>
              </select>
            </div>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-surface/60 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-cyber-border">
              <tr>
                <th className="py-3 px-4">Action ID</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Incident</th>
                <th className="py-3 px-4">Reason</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4">Provider</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {filteredActions.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    <Cpu className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <p className="text-xs">No prevention actions recorded in audit ledger.</p>
                  </td>
                </tr>
              ) : (
                filteredActions.map((act) => (
                  <tr key={act.id} className="hover:bg-cyber-surface/30 transition">
                    <td className="py-3 px-4 font-mono text-cyan-400">#{act.id}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                          act.action === 'BLOCK'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : act.action === 'UNBLOCK'
                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}
                      >
                        {act.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-slate-200">
                      {act.target}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {act.incident_id ? `#${act.incident_id}` : 'MANUAL'}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate" title={act.reason}>
                      {act.reason}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {act.duration_minutes ? `${act.duration_minutes}m` : 'Indefinite'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 capitalize">
                      {act.provider}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1 font-mono text-[10px] ${
                          act.status === 'EXECUTED'
                            ? 'text-emerald-400'
                            : act.status === 'REVERTED'
                            ? 'text-cyan-400'
                            : 'text-rose-400'
                        }`}
                      >
                        {act.status === 'EXECUTED' ? (
                          <CheckCircle2 className="h-3 w-3" />
                        ) : (
                          <XCircle className="h-3 w-3" />
                        )}
                        {act.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {new Date(act.executed_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Admin Policy Configuration Modal */}
      {policyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-cyber-border bg-cyber-card p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Sliders className="h-4 w-4 text-cyan-400" />
                Configure Prevention Policies
              </h3>
              <button
                onClick={() => setPolicyModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            {policyError && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
                {policyError}
              </div>
            )}

            <form onSubmit={handleUpdatePolicies} className="space-y-4 text-xs">
              <div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editEnabled}
                    onChange={(e) => setEditEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-cyber-border bg-cyber-bg text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="font-semibold text-slate-200">
                    Enable Automated Prevention Engine
                  </span>
                </label>
                <p className="text-[11px] text-cyber-muted mt-1 ml-6">
                  When enabled, incidents scoring &ge; auto-block threshold trigger mock prevention actions.
                </p>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Auto-Block Threshold (0-100 Score)
                </label>
                <input
                  type="number"
                  min="50"
                  max="100"
                  value={editThreshold}
                  onChange={(e) => setEditThreshold(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <p className="text-[11px] text-cyber-muted mt-1">
                  Recommended: 80 (CRITICAL incidents only).
                </p>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Default Block Lease Duration (Minutes)
                </label>
                <input
                  type="number"
                  min="5"
                  max="1440"
                  value={editDuration}
                  onChange={(e) => setEditDuration(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <p className="text-[11px] text-cyber-muted mt-1">
                  Active mock block leases automatically expire after this period.
                </p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-cyber-border">
                <button
                  type="button"
                  onClick={() => setPolicyModalOpen(false)}
                  className="px-3 py-2 rounded-lg bg-cyber-surface hover:bg-slate-800 text-slate-300 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingPolicy}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition disabled:opacity-50"
                >
                  {savingPolicy ? 'Saving...' : 'Save Policies'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
