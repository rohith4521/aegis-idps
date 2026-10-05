import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  Lock,
  Radio,
  Activity,
  ArrowUpRight,
  TrendingUp,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { api } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { Incident, SecurityEvent, BlockedSource, PreventionStatus } from '../types';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { subscribe } = useWebSocket();

  const [loading, setLoading] = useState(true);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [blockedSources, setBlockedSources] = useState<BlockedSource[]>([]);
  const [preventionStatus, setPreventionStatus] = useState<PreventionStatus | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [incRes, evRes, blRes, prevRes] = await Promise.all([
        api.listIncidents({ limit: 50 }),
        api.listEvents({ limit: 100 }),
        api.listBlockedSources({ limit: 50 }),
        api.getPreventionStatus(),
      ]);
      setIncidents(incRes);
      setEvents(evRes);
      setBlockedSources(blRes);
      setPreventionStatus(prevRes);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Subscribe to live WebSocket events
    const unsubIncidentCreated = subscribe('incident.created', (envelope) => {
      setIncidents((prev) => [envelope.data, ...prev.filter((i) => i.id !== envelope.data.id)]);
    });

    const unsubIncidentUpdated = subscribe('incident.updated', (envelope) => {
      setIncidents((prev) =>
        prev.map((i) => (i.id === envelope.data.id ? { ...i, ...envelope.data } : i))
      );
    });

    const unsubEventCreated = subscribe('security_event.created', (envelope) => {
      setEvents((prev) => [envelope.data, ...prev.slice(0, 99)]);
    });

    const unsubBlockedUpdated = subscribe('blocked_source.updated', () => {
      api.listBlockedSources({ limit: 50 }).then(setBlockedSources).catch(console.error);
    });

    return () => {
      unsubIncidentCreated();
      unsubIncidentUpdated();
      unsubEventCreated();
      unsubBlockedUpdated();
    };
  }, [subscribe]);

  // Metrics computation
  const activeIncidents = useMemo(() => incidents.filter((i) => i.status === 'ACTIVE'), [incidents]);
  const criticalCount = useMemo(() => incidents.filter((i) => i.severity === 'CRITICAL').length, [incidents]);
  const activeBlockedCount = useMemo(() => blockedSources.filter((b) => b.status === 'ACTIVE').length, [blockedSources]);

  // Category distribution data for charts
  const categoryData = useMemo(() => {
    const counts: Record<string, number> = {};
    incidents.forEach((inc) => {
      counts[inc.category] = (counts[inc.category] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, count: value }));
  }, [incidents]);

  // Severity distribution
  const severityData = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    incidents.forEach((inc) => {
      if (counts[inc.severity] !== undefined) {
        counts[inc.severity]++;
      }
    });
    return [
      { name: 'CRITICAL', count: counts.CRITICAL, color: '#ef4444' },
      { name: 'HIGH', count: counts.HIGH, color: '#f97316' },
      { name: 'MEDIUM', count: counts.MEDIUM, color: '#eab308' },
      { name: 'LOW', count: counts.LOW, color: '#06b6d4' },
    ];
  }, [incidents]);

  // Timeline trend (last 10 events grouping)
  const timelineData = useMemo(() => {
    const grouped: Record<string, number> = {};
    events.slice(0, 30).forEach((ev) => {
      const timeStr = new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      grouped[timeStr] = (grouped[timeStr] || 0) + 1;
    });
    return Object.entries(grouped)
      .map(([time, eventsCount]) => ({ time, events: eventsCount }))
      .reverse();
  }, [events]);

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

  return (
    <div className="space-y-6">
      {/* Top Banner: Safe Prevention Mode Explanation */}
      <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border flex items-center justify-between">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Lock className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-semibold text-white">Active Defense Status: Mock Prevention Enabled</h2>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded font-mono font-bold">
                SAFE LAB MODE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Threat scores ≥ {preventionStatus?.auto_block_threshold ?? 80} automatically trigger auditable simulated blocks. Host network interfaces and kernel firewall tables remain completely untouched.
            </p>
          </div>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyber-surface hover:bg-slate-800 text-xs font-mono text-slate-300 border border-cyber-border transition"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-muted uppercase tracking-wider">Active Incidents</span>
            <div className="p-1.5 rounded bg-cyan-500/10 text-cyan-400">
              <AlertTriangle className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-white">{activeIncidents.length}</span>
            <span className="text-xs text-cyan-400 flex items-center">
              <TrendingUp className="h-3 w-3 mr-1" />
              Live Correlated
            </span>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border hover:border-rose-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-muted uppercase tracking-wider">Critical Threats</span>
            <div className="p-1.5 rounded bg-rose-500/10 text-rose-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-rose-400">{criticalCount}</span>
            <span className="text-xs text-rose-400/80">Score ≥ 80</span>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border hover:border-emerald-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-muted uppercase tracking-wider">Blocked Sources</span>
            <div className="p-1.5 rounded bg-emerald-500/10 text-emerald-400">
              <Lock className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-emerald-400">{activeBlockedCount}</span>
            <span className="text-xs text-emerald-400/80">Mock Policy Active</span>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-muted uppercase tracking-wider">Ingested Events</span>
            <div className="p-1.5 rounded bg-cyan-500/10 text-cyan-400">
              <Radio className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-white">{events.length}</span>
            <span className="text-xs text-cyan-400">Suricata EVE</span>
          </div>
        </div>
      </div>

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline AreaChart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-cyber-card border border-cyber-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Event Ingestion Activity Over Time
            </h3>
            <span className="text-xs font-mono text-slate-500">Live Window</span>
          </div>
          <div className="h-64 w-full">
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="cyberCyan" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                  />
                  <Area type="monotone" dataKey="events" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#cyberCyan)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Awaiting event ingestion telemetry...
              </div>
            )}
          </div>
        </div>

        {/* Severity Distribution BarChart */}
        <div className="p-5 rounded-xl bg-cyber-card border border-cyber-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Incident Severity Spread</h3>
            <span className="text-xs font-mono text-slate-500">0 - 100 Scale</span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} layout="vertical">
                <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
                <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={11} width={70} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Live Incident Feed & Attack Vectors */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Incident Stream */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-cyber-card border border-cyber-border">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-semibold text-white">Live Incident Feed</h3>
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping"></span>
            </div>
            <button
              onClick={() => navigate('/incidents')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="divide-y divide-cyber-border overflow-hidden">
            {incidents.slice(0, 7).map((inc) => (
              <div
                key={inc.id}
                onClick={() => navigate(`/incidents?inspect=${inc.id}`)}
                className="py-3 px-2 flex items-center justify-between hover:bg-cyber-surface/40 rounded-lg cursor-pointer transition"
              >
                <div className="flex items-center space-x-3 min-w-0">
                  <div className={`px-2 py-0.5 rounded text-[11px] font-mono border font-semibold ${getSeverityBadge(inc.severity)}`}>
                    {inc.severity}
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-200 truncate flex items-center gap-1.5">
                      {inc.title}
                      {inc.origin === 'MIXED' || inc.title.includes('[MIXED') ? (
                        <span className="text-[9px] bg-amber-950/70 text-amber-300 border border-amber-600/50 px-1 rounded font-mono font-bold" title="Mixed Origin: Real and Simulated telemetry">
                          MIXED
                        </span>
                      ) : inc.is_simulation ? (
                        <span className="text-[9px] bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 px-1 rounded font-mono font-bold" title="Synthetic Simulation Event">
                          SIM
                        </span>
                      ) : (
                        <span className="text-[9px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-1 rounded font-mono font-bold" title="Live Telemetry">
                          REAL
                        </span>
                      )}
                    </p>
                    <p className="text-[11px] font-mono text-slate-500 mt-0.5">
                      Src: <span className="text-slate-300">{inc.source_ip}</span> • Count: {inc.event_count} • Category: {inc.category}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-4 shrink-0">
                  <div className="text-right">
                    <div className="text-xs font-mono font-bold text-slate-200">
                      Score: <span className={inc.threat_score >= 80 ? 'text-red-400' : 'text-cyan-400'}>{inc.threat_score}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      Conf: {inc.confidence}%
                    </span>
                  </div>
                  <ExternalLink className="h-3.5 w-3.5 text-slate-600 hover:text-cyan-400" />
                </div>
              </div>
            ))}

            {incidents.length === 0 && (
              <div className="py-8 text-center text-xs text-slate-500">
                No security incidents logged yet. Click "Trigger Simulation" to generate test events.
              </div>
            )}
          </div>
        </div>

        {/* Attack Categories Breakdown */}
        <div className="p-5 rounded-xl bg-cyber-card border border-cyber-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white">Top Attack Categories</h3>
            <span className="text-xs font-mono text-slate-500">Classification</span>
          </div>
          <div className="space-y-3">
            {categoryData.slice(0, 5).map((cat) => {
              const maxVal = Math.max(...categoryData.map((c) => c.count), 1);
              const pct = Math.round((cat.count / maxVal) * 100);
              return (
                <div key={cat.name} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-300 truncate">{cat.name}</span>
                    <span className="font-mono text-cyan-400">{cat.count}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
            {categoryData.length === 0 && (
              <div className="py-8 text-center text-xs text-slate-500">
                No classification telemetry yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
