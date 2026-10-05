import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  Search,
  Radio,
  X,
  FileCheck,
} from 'lucide-react';
import { api } from '../services/api';
import { Incident } from '../types';

export const IncidentsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [statusUpdateNotes, setStatusUpdateNotes] = useState('');
  const [updatingStatus, setUpdatingStatus] = useState(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchIp, setSearchIp] = useState<string>('');

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const params: Record<string, any> = { limit: 100 };
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (statusFilter !== 'ALL') params.status = statusFilter;
      if (searchIp) params.source_ip = searchIp;

      const data = await api.listIncidents(params);
      setIncidents(data);
    } catch (err) {
      console.error('Failed to fetch incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [severityFilter, statusFilter, searchIp]);

  // Handle URL inspect parameter
  useEffect(() => {
    const inspectId = searchParams.get('inspect');
    if (inspectId) {
      openIncidentDetail(parseInt(inspectId, 10));
    }
  }, [searchParams]);

  const openIncidentDetail = async (id: number) => {
    try {
      const fullIncident = await api.getIncident(id);
      setSelectedIncident(fullIncident);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedIncident) return;
    try {
      setUpdatingStatus(true);
      const updated = await api.updateIncidentStatus(selectedIncident.id, newStatus, statusUpdateNotes);
      setSelectedIncident(updated);
      setStatusUpdateNotes('');
      fetchIncidents();
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      default:
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'ACTIVE':
        return 'bg-red-950/40 text-red-300 border-red-800/40';
      case 'INVESTIGATING':
        return 'bg-amber-950/40 text-amber-300 border-amber-800/40';
      case 'RESOLVED':
        return 'bg-emerald-950/40 text-emerald-300 border-emerald-800/40';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-cyan-400" />
            Correlated Security Incidents
          </h2>
          <p className="text-xs text-cyber-muted">
            Aggregated multi-event threat dossiers with explainable factor scoring.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search IP */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by Source IP..."
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
          >
            <option value="ALL">All Statuses</option>
            <option value="ACTIVE">Active</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-surface/60 text-slate-400 font-mono border-b border-cyber-border">
              <tr>
                <th className="py-3 px-4">INCIDENT ID</th>
                <th className="py-3 px-4">TITLE & CATEGORY</th>
                <th className="py-3 px-4">SOURCE IP</th>
                <th className="py-3 px-4">SEVERITY</th>
                <th className="py-3 px-4">THREAT SCORE</th>
                <th className="py-3 px-4">EVENTS</th>
                <th className="py-3 px-4">STATUS</th>
                <th className="py-3 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {incidents.map((inc) => (
                <tr
                  key={inc.id}
                  onClick={() => openIncidentDetail(inc.id)}
                  className="hover:bg-cyber-surface/40 cursor-pointer transition"
                >
                  <td className="py-3 px-4 font-mono font-bold text-cyan-400">
                    #{inc.id}
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-medium text-slate-200 flex items-center gap-1.5">
                      {inc.title}
                      {inc.origin === 'MIXED' || inc.title.includes('[MIXED') ? (
                        <span className="text-[9px] bg-amber-950/70 text-amber-300 border border-amber-600/50 px-1.5 py-0.5 rounded font-mono font-bold" title="Mixed Origin: Real and Simulated telemetry">
                          MIXED
                        </span>
                      ) : inc.is_simulation ? (
                        <span className="text-[9px] bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 px-1.5 py-0.5 rounded font-mono font-bold" title="Synthetic Simulation Event">
                          SIM
                        </span>
                      ) : (
                        <span className="text-[9px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-1.5 py-0.5 rounded font-mono font-bold" title="Live Telemetry">
                          REAL
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">{inc.category}</span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300">
                    {inc.source_ip}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-semibold ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-2">
                      <span className={`font-mono font-bold ${inc.threat_score >= 80 ? 'text-rose-400' : 'text-cyan-400'}`}>
                        {inc.threat_score}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        ({inc.confidence}%)
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-400">
                    {inc.event_count}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-semibold ${getStatusBadge(inc.status)}`}>
                      {inc.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        openIncidentDetail(inc.id);
                      }}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300"
                    >
                      Investigate →
                    </button>
                  </td>
                </tr>
              ))}

              {incidents.length === 0 && !loading && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 text-xs">
                    No incidents match current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Modal / Dossier */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-4xl max-h-[90vh] bg-cyber-card border border-cyber-border rounded-xl shadow-2xl flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-cyber-border flex items-center justify-between bg-cyber-surface/40">
              <div className="flex items-center space-x-3">
                <span className="px-2 py-1 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono font-bold text-xs rounded">
                  INCIDENT #{selectedIncident.id}
                </span>
                {selectedIncident.origin === 'MIXED' || selectedIncident.title.includes('[MIXED') ? (
                  <span className="px-2 py-0.5 bg-amber-950/70 border border-amber-600/50 text-amber-300 font-mono font-bold text-xs rounded">
                    ORIGIN: MIXED (REAL + SIMULATION)
                  </span>
                ) : selectedIncident.is_simulation ? (
                  <span className="px-2 py-0.5 bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 font-mono font-bold text-xs rounded">
                    ORIGIN: SIMULATION
                  </span>
                ) : (
                  <span className="px-2 py-0.5 bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 font-mono font-bold text-xs rounded">
                    ORIGIN: LIVE NETWORK
                  </span>
                )}
                <h3 className="text-sm font-semibold text-white">{selectedIncident.title}</h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Top Overview Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-3 bg-cyber-surface/50 border border-cyber-border rounded-lg">
                  <span className="text-[11px] font-mono text-slate-400">SEVERITY RATING</span>
                  <div className="mt-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono border font-semibold ${getSeverityBadge(selectedIncident.severity)}`}>
                      {selectedIncident.severity}
                    </span>
                  </div>
                </div>

                <div className="p-3 bg-cyber-surface/50 border border-cyber-border rounded-lg">
                  <span className="text-[11px] font-mono text-slate-400">THREAT SCORE</span>
                  <p className="mt-1 text-lg font-bold font-mono text-cyan-400">
                    {selectedIncident.threat_score} <span className="text-xs text-slate-500">/ 100</span>
                  </p>
                </div>

                <div className="p-3 bg-cyber-surface/50 border border-cyber-border rounded-lg">
                  <span className="text-[11px] font-mono text-slate-400">SOURCE IP</span>
                  <p className="mt-1 font-mono text-sm text-slate-200 truncate">{selectedIncident.source_ip}</p>
                </div>

                <div className="p-3 bg-cyber-surface/50 border border-cyber-border rounded-lg">
                  <span className="text-[11px] font-mono text-slate-400">INCIDENT STATUS</span>
                  <div className="mt-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono border font-semibold ${getStatusBadge(selectedIncident.status)}`}>
                      {selectedIncident.status}
                    </span>
                  </div>
                </div>
              </div>

              {/* Explainable Threat Scoring Breakdown */}
              <div className="p-4 rounded-lg bg-cyber-surface/40 border border-cyber-border space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                    <FileCheck className="h-4 w-4 text-cyan-400" />
                    Explainable Threat Scoring Factors
                  </h4>
                  <span className="text-xs font-mono text-slate-400">
                    Confidence: <span className="text-cyan-400 font-bold">{selectedIncident.confidence}%</span>
                  </span>
                </div>

                <div className="space-y-2">
                  {selectedIncident.threat_score_detail?.factors?.map((factor, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between py-1.5 px-3 bg-slate-900/60 border border-slate-800 rounded text-xs font-mono"
                    >
                      <span className="text-slate-300">{factor.reason}</span>
                      <span className="text-cyan-400 font-bold">+{factor.points} pts</span>
                    </div>
                  ))}

                  {(!selectedIncident.threat_score_detail?.factors ||
                    selectedIncident.threat_score_detail.factors.length === 0) && (
                    <p className="text-xs text-slate-500">No factor breakdown recorded.</p>
                  )}
                </div>
              </div>

              {/* Correlated Events Timeline */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <Radio className="h-4 w-4 text-cyan-400" />
                  Correlated Suricata EVE Events ({selectedIncident.events?.length || selectedIncident.event_count})
                </h4>

                <div className="max-h-60 overflow-y-auto divide-y divide-cyber-border border border-cyber-border rounded-lg bg-cyber-card">
                  {selectedIncident.events?.map((ev) => (
                    <div key={ev.id} className="p-3 text-xs flex items-center justify-between hover:bg-cyber-surface/30">
                      <div>
                        <p className="font-mono text-slate-200">{ev.signature}</p>
                        <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                          Port: {ev.destination_port ?? 'N/A'} • Proto: {ev.protocol} • Time: {new Date(ev.timestamp).toLocaleString()}
                        </p>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(ev.severity === 1 ? 'CRITICAL' : ev.severity === 2 ? 'HIGH' : 'LOW')}`}>
                        Sev {ev.severity}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Status Update Control */}
              <div className="p-4 rounded-lg bg-cyber-surface/40 border border-cyber-border space-y-3">
                <h4 className="text-xs font-semibold text-slate-200">SOC Analyst Incident Triage</h4>
                <div className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="text"
                    placeholder="Analyst resolution or triage note..."
                    value={statusUpdateNotes}
                    onChange={(e) => setStatusUpdateNotes(e.target.value)}
                    className="flex-1 px-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleStatusChange('INVESTIGATING')}
                      disabled={updatingStatus}
                      className="px-3 py-1.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-medium hover:bg-amber-500/30 transition disabled:opacity-50"
                    >
                      Investigate
                    </button>
                    <button
                      onClick={() => handleStatusChange('RESOLVED')}
                      disabled={updatingStatus}
                      className="px-3 py-1.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs font-medium hover:bg-emerald-500/30 transition disabled:opacity-50"
                    >
                      Resolve
                    </button>
                    <button
                      onClick={() => handleStatusChange('FALSE_POSITIVE')}
                      disabled={updatingStatus}
                      className="px-3 py-1.5 rounded bg-slate-700 text-slate-300 border border-slate-600 text-xs font-medium hover:bg-slate-600 transition disabled:opacity-50"
                    >
                      False Positive
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
