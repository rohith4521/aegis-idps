import React, { useEffect, useState } from 'react';
import { Lock, Unlock, ShieldCheck, Search, RefreshCw, X } from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../hooks/useAuth';
import { BlockedSource } from '../types';

export const BlockedSourcesPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [sources, setSources] = useState<BlockedSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [unblockModalSource, setUnblockModalSource] = useState<BlockedSource | null>(null);
  const [unblockReason, setUnblockReason] = useState('');
  const [unblocking, setUnblocking] = useState(false);
  const [unblockError, setUnblockError] = useState<string | null>(null);

  // Allowlist modal
  const [allowlistModalOpen, setAllowlistModalOpen] = useState(false);
  const [allowlistIp, setAllowlistIp] = useState('');
  const [allowlistReason, setAllowlistReason] = useState('');
  const [allowlisting, setAllowlisting] = useState(false);
  const [allowlistError, setAllowlistError] = useState<string | null>(null);

  // Search & Filter
  const [searchIp, setSearchIp] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchBlockedSources = async () => {
    try {
      setLoading(true);
      const params: Record<string, any> = { limit: 100 };
      if (searchIp) params.ip = searchIp;
      if (statusFilter !== 'ALL') params.status = statusFilter;

      const data = await api.listBlockedSources(params);
      setSources(data);
    } catch (err) {
      console.error('Failed to load blocked sources:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlockedSources();
  }, [searchIp, statusFilter]);

  const handleUnblock = async () => {
    if (!unblockModalSource || !unblockReason.trim()) return;
    try {
      setUnblocking(true);
      setUnblockError(null);
      await api.unblockSource(unblockModalSource.id, unblockReason);
      setUnblockModalSource(null);
      setUnblockReason('');
      fetchBlockedSources();
    } catch (err: any) {
      setUnblockError(err.message || 'Failed to unblock source');
    } finally {
      setUnblocking(false);
    }
  };

  const handleAllowlist = async () => {
    if (!allowlistIp.trim() || !allowlistReason.trim()) return;
    try {
      setAllowlisting(true);
      setAllowlistError(null);
      await api.allowlistSource(allowlistIp, allowlistReason);
      setAllowlistModalOpen(false);
      setAllowlistIp('');
      setAllowlistReason('');
      fetchBlockedSources();
    } catch (err: any) {
      setAllowlistError(err.message || 'Failed to add to allowlist');
    } finally {
      setAllowlisting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Lock className="h-5 w-5 text-cyan-400" />
            Blocked Sources & SOC Allowlist
          </h2>
          <p className="text-xs text-cyber-muted">
            Automated software policy blocks, expiry schedules, and allowlist bypass configurations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isAdmin && (
            <button
              onClick={() => setAllowlistModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/30 hover:bg-emerald-600/50 border border-emerald-500/40 text-emerald-200 text-xs font-semibold transition"
            >
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <span>Allowlist IP</span>
            </button>
          )}

          <button
            onClick={fetchBlockedSources}
            className="p-1.5 rounded-lg bg-cyber-card border border-cyber-border text-slate-300 hover:text-white hover:bg-cyber-surface transition"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP address..."
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            className="pl-8 pr-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500/60"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="ALL">All Statuses</option>
          <option value="ACTIVE">Active Blocks</option>
          <option value="WHITELISTED">Allowlisted</option>
          <option value="MANUALLY_UNBLOCKED">Manually Unblocked</option>
          <option value="EXPIRED">Expired</option>
        </select>
      </div>

      {/* Blocked Sources Table */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-surface/60 text-slate-400 font-mono border-b border-cyber-border">
              <tr>
                <th className="py-3 px-4">TARGET IP</th>
                <th className="py-3 px-4">REASON & THREAT SCORE</th>
                <th className="py-3 px-4">PROVIDER</th>
                <th className="py-3 px-4">BLOCKED AT</th>
                <th className="py-3 px-4">EXPIRY</th>
                <th className="py-3 px-4">STATUS</th>
                <th className="py-3 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {sources.map((item) => (
                <tr key={item.id} className="hover:bg-cyber-surface/30 font-mono transition">
                  <td className="py-3 px-4 font-bold text-slate-200">
                    {item.ip}
                    {item.is_whitelisted && (
                      <span className="ml-2 text-[10px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-1 py-0.2 rounded font-sans">
                        ALLOWLISTED
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 max-w-xs truncate font-sans">
                    <span className="text-slate-300">{item.reason}</span>
                    <span className="block font-mono text-[10px] text-cyan-400 mt-0.5">
                      Threat Score: {item.threat_score}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 rounded text-[10px] uppercase">
                      {item.provider}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                    {new Date(item.blocked_time).toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                    {item.expiry ? new Date(item.expiry).toLocaleString() : 'Permanent / N/A'}
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] border font-bold ${
                        item.status === 'ACTIVE'
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                          : item.status === 'WHITELISTED'
                          ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    {item.status === 'ACTIVE' && (
                      <button
                        onClick={() => setUnblockModalSource(item)}
                        className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 justify-end ml-auto"
                      >
                        <Unlock className="h-3.5 w-3.5" />
                        <span>Unblock</span>
                      </button>
                    )}
                  </td>
                </tr>
              ))}

              {sources.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                    No blocked sources found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Unblock Modal */}
      {unblockModalSource && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Unlock className="h-4 w-4 text-cyan-400" />
                Confirm Manual Unblock
              </h3>
              <button
                onClick={() => setUnblockModalSource(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {unblockError && (
              <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
                {unblockError}
              </div>
            )}

            <p className="text-xs text-slate-300">
              You are about to lift the active block for IP{' '}
              <span className="font-mono text-cyan-400 font-bold">{unblockModalSource.ip}</span>. An auditable log entry will be permanently recorded.
            </p>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Justification / Reason (Required)
              </label>
              <textarea
                rows={3}
                placeholder="e.g., Security analyst verified false alarm or completed penetration test triage."
                value={unblockReason}
                onChange={(e) => setUnblockReason(e.target.value)}
                className="w-full px-3 py-2 bg-cyber-surface border border-cyber-border rounded-md text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-cyber-border">
              <button
                onClick={() => {
                  setUnblockModalSource(null);
                  setUnblockError(null);
                }}
                disabled={unblocking}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleUnblock}
                disabled={unblocking || !unblockReason.trim()}
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition disabled:opacity-50"
              >
                {unblocking ? 'Processing...' : 'Authorize Unblock'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Allowlist Modal */}
      {allowlistModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Add IP to SOC Allowlist
              </h3>
              <button
                onClick={() => {
                  setAllowlistModalOpen(false);
                  setAllowlistError(null);
                }}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {allowlistError && (
              <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
                {allowlistError}
              </div>
            )}

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Target IP Address
                </label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.100"
                  value={allowlistIp}
                  onChange={(e) => setAllowlistIp(e.target.value)}
                  className="w-full px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Business Justification
                </label>
                <textarea
                  rows={2}
                  placeholder="e.g. Internal security scanner host or authorized external partner."
                  value={allowlistReason}
                  onChange={(e) => setAllowlistReason(e.target.value)}
                  className="w-full px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-md text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-cyber-border">
              <button
                onClick={() => setAllowlistModalOpen(false)}
                disabled={allowlisting}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleAllowlist}
                disabled={allowlisting || !allowlistIp.trim() || !allowlistReason.trim()}
                className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white transition disabled:opacity-50"
              >
                {allowlisting ? 'Adding...' : 'Add to Allowlist'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
