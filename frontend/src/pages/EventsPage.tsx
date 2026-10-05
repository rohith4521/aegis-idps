import React, { useEffect, useState } from 'react';
import { Radio, Search, Play, RefreshCw, Terminal, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';
import { SecurityEvent } from '../types';

export const EventsPage: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [simModalOpen, setSimModalOpen] = useState(false);
  const [simScenario, setSimScenario] = useState('mixed');
  const [simCount, setSimCount] = useState(10);
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<string | null>(null);

  // Filters
  const [searchIp, setSearchIp] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const params: Record<string, any> = { limit: 100 };
      if (searchIp) params.source_ip = searchIp;
      if (severityFilter !== 'ALL') params.severity = parseInt(severityFilter, 10);

      const data = await api.listEvents(params);
      setEvents(data);
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [searchIp, severityFilter]);

  const handleSimulate = async () => {
    try {
      setSimulating(true);
      const res = await api.generateDemoEvents(simCount, simScenario);
      setSimResult(`Successfully generated and normalized ${res.ingested_count} simulated Suricata events.`);
      fetchEvents();
      setTimeout(() => {
        setSimResult(null);
        setSimModalOpen(false);
      }, 2000);
    } catch (err: any) {
      setSimResult(`Simulation error: ${err.message}`);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Radio className="h-5 w-5 text-cyan-400" />
            Suricata EVE Normalized Events
          </h2>
          <p className="text-xs text-cyber-muted">
            Ingested, validated, and normalized telemetry from Suricata IDS sensors.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setSimModalOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-600/30 hover:bg-cyan-600/50 border border-cyan-500/40 text-cyan-200 text-xs font-semibold transition"
          >
            <Play className="h-3.5 w-3.5 text-cyan-400" />
            <span>Generate Lab Traffic</span>
          </button>

          <button
            onClick={fetchEvents}
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
            placeholder="Search Source IP..."
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            className="pl-8 pr-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500/60"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 bg-cyber-card border border-cyber-border rounded-md text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="ALL">All Severities</option>
          <option value="1">Severity 1 (Critical/High)</option>
          <option value="2">Severity 2 (Medium)</option>
          <option value="3">Severity 3 (Low)</option>
          <option value="4">Severity 4 (Telemetry)</option>
        </select>
      </div>

      {/* Events Table */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-surface/60 text-slate-400 font-mono border-b border-cyber-border">
              <tr>
                <th className="py-3 px-4">TIMESTAMP</th>
                <th className="py-3 px-4">SOURCE IP:PORT</th>
                <th className="py-3 px-4">DESTINATION IP:PORT</th>
                <th className="py-3 px-4">PROTO</th>
                <th className="py-3 px-4">SIGNATURE & CATEGORY</th>
                <th className="py-3 px-4">SEVERITY</th>
                <th className="py-3 px-4">TYPE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {events.map((ev) => (
                <tr key={ev.id} className="hover:bg-cyber-surface/30 font-mono transition">
                  <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                    {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td className="py-3 px-4 text-slate-200 whitespace-nowrap">
                    {ev.source_ip}:{ev.source_port ?? '—'}
                  </td>
                  <td className="py-3 px-4 text-slate-200 whitespace-nowrap">
                    {ev.destination_ip}:{ev.destination_port ?? '—'}
                  </td>
                  <td className="py-3 px-4 text-cyan-400">{ev.protocol}</td>
                  <td className="py-3 px-4 max-w-xs truncate">
                    <span className="text-slate-200 font-sans">{ev.signature}</span>
                    <span className="block text-[10px] text-slate-500 font-mono mt-0.5">{ev.category}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] border font-bold ${
                        ev.severity === 1
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                          : ev.severity === 2
                          ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                          : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                      }`}
                    >
                      Sev {ev.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {ev.is_simulation ? (
                      <span className="text-[10px] bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 px-1.5 py-0.5 rounded font-mono">
                        [SIMULATION]
                      </span>
                    ) : (
                      <span className="text-[10px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-1.5 py-0.5 rounded font-mono">
                        LIVE
                      </span>
                    )}
                  </td>
                </tr>
              ))}

              {events.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                    No security events observed. Click "Generate Lab Traffic" to simulate events.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Lab Simulation Modal */}
      {simModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-400" />
                Lab Traffic Generator (Safe Mode)
              </h3>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded font-mono">
                NON-DESTRUCTIVE
              </span>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Attack Scenario
                </label>
                <select
                  value={simScenario}
                  onChange={(e) => setSimScenario(e.target.value)}
                  className="w-full px-3 py-2 bg-cyber-surface border border-cyber-border rounded-md text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="mixed">Mixed Lab Traffic (All Vectors)</option>
                  <option value="brute_force">SSH Brute Force Attack (Port 22)</option>
                  <option value="sqli">Web SQL Injection in URI (Port 80)</option>
                  <option value="rce">Remote Command Execution /bin/sh (Port 443)</option>
                  <option value="port_scan">SYN Multi-Port Reconnaissance Scan</option>
                  <option value="smb_exploit">SMB Ghost Exploit Attempt (Port 445)</option>
                  <option value="benign">Benign Inbound HTTPS Web Flow</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Event Batch Count: <span className="font-mono text-cyan-400">{simCount}</span>
                </label>
                <input
                  type="range"
                  min="2"
                  max="50"
                  step="2"
                  value={simCount}
                  onChange={(e) => setSimCount(parseInt(e.target.value, 10))}
                  className="w-full accent-cyan-400"
                />
              </div>

              {simResult && (
                <div className="p-3 bg-cyan-950/40 border border-cyan-800/40 rounded text-xs font-mono text-cyan-300 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-cyan-400" />
                  <span>{simResult}</span>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-cyber-border">
              <button
                onClick={() => setSimModalOpen(false)}
                disabled={simulating}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSimulate}
                disabled={simulating}
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition disabled:opacity-50"
              >
                {simulating ? 'Injecting...' : 'Inject Simulated Traffic'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
