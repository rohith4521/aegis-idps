import React, { useEffect, useState } from 'react';
import {
  FileCode2,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Info,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { ThreatScore } from '../types';

export const ThreatsPage: React.FC = () => {
  const navigate = useNavigate();
  const { subscribe } = useWebSocket();

  const [threats, setThreats] = useState<ThreatScore[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [minScore, setMinScore] = useState<number>(0);
  const [expandedThreatId, setExpandedThreatId] = useState<number | null>(null);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const params: Record<string, any> = { limit: 100 };
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (minScore > 0) params.min_score = minScore;

      const data = await api.listThreats(params);
      setThreats(data);
    } catch (err) {
      console.error('Failed to load threats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();

    const unsub = subscribe('threat_score.created', (envelope) => {
      setThreats((prev) => [envelope.data, ...prev.slice(0, 99)]);
    });

    return () => {
      unsub();
    };
  }, [severityFilter, minScore, subscribe]);

  const toggleExpand = (id: number) => {
    setExpandedThreatId(expandedThreatId === id ? null : id);
  };

  // Metrics
  const criticalThreats = threats.filter((t) => t.severity === 'CRITICAL').length;
  const highThreats = threats.filter((t) => t.severity === 'HIGH').length;
  const avgConfidence = threats.length
    ? Math.round(threats.reduce((acc, t) => acc + t.confidence, 0) / threats.length)
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileCode2 className="h-5 w-5 text-cyan-400" />
            Explainable Threat Scoring Ledger
          </h2>
          <p className="text-xs text-cyber-muted">
            Deterministic, rule-based threat assessment with transparent factor breakdowns and confidence scores.
          </p>
        </div>

        <button
          onClick={fetchThreats}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card hover:bg-cyber-surface border border-cyber-border text-slate-300 text-xs font-medium transition self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Explainability Banner */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card/60 p-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">
            <Info className="h-5 w-5" />
          </div>
          <div className="text-xs space-y-1">
            <h4 className="font-semibold text-slate-200">
              TRANSPARENT, AUDITABLE THREAT QUANTIFICATION
            </h4>
            <p className="text-slate-400 leading-relaxed">
              Threat scores (0–100) are generated through an explainable multi-factor formula evaluating signature base weights, event frequency surges, cross-port correlation, and target sensitivity. We do not claim opaque black-box machine learning; every point awarded is fully traceable to documented security criteria.
            </p>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Total Evaluations</span>
          <div className="mt-2 text-2xl font-bold font-mono text-white">{threats.length}</div>
          <p className="mt-1 text-[11px] text-slate-400">Scored security incidents</p>
        </div>

        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Critical Threats (80-100)</span>
          <div className="mt-2 text-2xl font-bold font-mono text-rose-400">{criticalThreats}</div>
          <p className="mt-1 text-[11px] text-slate-400">Auto-prevention eligible</p>
        </div>

        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">High Threats (60-79)</span>
          <div className="mt-2 text-2xl font-bold font-mono text-orange-400">{highThreats}</div>
          <p className="mt-1 text-[11px] text-slate-400">Priority triage queue</p>
        </div>

        <div className="rounded-xl border border-cyber-border bg-cyber-card p-4">
          <span className="text-xs text-cyber-muted font-medium">Mean Engine Confidence</span>
          <div className="mt-2 text-2xl font-bold font-mono text-cyan-300">{avgConfidence}%</div>
          <p className="mt-1 text-[11px] text-slate-400">Deterministic certainty metric</p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl border border-cyber-border bg-cyber-card flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Severity */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-400 font-medium">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="py-1.5 px-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL (80-100)</option>
              <option value="HIGH">HIGH (60-79)</option>
              <option value="MEDIUM">MEDIUM (30-59)</option>
              <option value="LOW">LOW (0-29)</option>
            </select>
          </div>

          {/* Min Score */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Min Score:</span>
            <input
              type="number"
              min="0"
              max="100"
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-20 py-1 px-2 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="text-xs text-slate-400 font-mono">
          Showing {threats.length} scored dossiers
        </div>
      </div>

      {/* Threats Table */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-surface/60 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-cyber-border">
              <tr>
                <th className="py-3 px-4">Evaluation ID</th>
                <th className="py-3 px-4">Incident Link</th>
                <th className="py-3 px-4">Threat Score</th>
                <th className="py-3 px-4">Severity Tier</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Key Explainability Factors</th>
                <th className="py-3 px-4">Assessed At</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {threats.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    <FileCode2 className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <p className="text-xs">No threat evaluations found for selected filter criteria.</p>
                  </td>
                </tr>
              ) : (
                threats.map((threat) => {
                  const isExpanded = expandedThreatId === threat.id;
                  const severityClass =
                    threat.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      : threat.severity === 'HIGH'
                      ? 'bg-orange-500/20 text-orange-300 border-orange-500/40'
                      : threat.severity === 'MEDIUM'
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';

                  return (
                    <React.Fragment key={threat.id}>
                      <tr
                        onClick={() => toggleExpand(threat.id)}
                        className={`hover:bg-cyber-surface/30 cursor-pointer transition ${
                          isExpanded ? 'bg-cyber-surface/40' : ''
                        }`}
                      >
                        <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">
                          #{threat.id}
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/incidents?id=${threat.incident_id}`);
                            }}
                            className="flex items-center gap-1 font-mono text-cyan-400 hover:text-cyan-300 hover:underline"
                          >
                            <span>Incident #{threat.incident_id}</span>
                            <ExternalLink className="h-3 w-3" />
                          </button>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-sm text-white">
                              {threat.score}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">/ 100</span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`inline-block px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${severityClass}`}
                          >
                            {threat.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                              <div
                                className="h-full bg-cyan-400"
                                style={{ width: `${threat.confidence}%` }}
                              ></div>
                            </div>
                            <span className="font-mono text-slate-300 text-[11px]">
                              {threat.confidence}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap gap-1.5 max-w-md">
                            {threat.factors?.slice(0, 2).map((factor, idx) => (
                              <span
                                key={idx}
                                className="inline-block px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[10px] font-mono"
                              >
                                +{factor.points} {factor.reason}
                              </span>
                            ))}
                            {threat.factors?.length > 2 && (
                              <span className="text-[10px] text-cyan-400 font-mono self-center">
                                +{threat.factors.length - 2} more
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                          {new Date(threat.created_at).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button className="text-slate-400 hover:text-slate-200">
                            {isExpanded ? (
                              <ChevronUp className="h-4 w-4" />
                            ) : (
                              <ChevronDown className="h-4 w-4" />
                            )}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Factor Breakdown */}
                      {isExpanded && (
                        <tr className="bg-cyber-surface/60">
                          <td colSpan={8} className="p-4 border-t border-b border-cyber-border">
                            <div className="rounded-lg bg-cyber-bg/90 border border-cyber-border p-4 space-y-3">
                              <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                                <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
                                Mathematical Factor Breakdown for Threat Assessment #{threat.id}
                              </h4>
                              <p className="text-[11px] text-slate-400">
                                Total Threat Score: <strong className="text-cyan-300">{threat.score} / 100</strong> | Confidence: <strong className="text-white">{threat.confidence}%</strong>
                              </p>

                              <div className="space-y-2 pt-2">
                                {threat.factors?.map((f, idx) => (
                                  <div
                                    key={idx}
                                    className="flex items-center justify-between p-2 rounded bg-cyber-card border border-cyber-border text-xs"
                                  >
                                    <span className="text-slate-200 font-medium">{f.reason}</span>
                                    <span className="font-mono font-bold text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                                      +{f.points} pts
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
