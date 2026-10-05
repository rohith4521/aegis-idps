import React, { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  AlertTriangle,
  Radio,
  FileCode2,
  Lock,
  Cpu,
  LogOut,
  Play,
  CheckCircle2,
  Terminal,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useWebSocket } from '../hooks/useWebSocket';
import { api } from '../services/api';

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const { status, isConnected } = useWebSocket();
  const [simulating, setSimulating] = useState(false);
  const [simNotice, setSimNotice] = useState<string | null>(null);

  const handleQuickSimulation = async () => {
    setSimulating(true);
    try {
      const res = await api.generateDemoEvents(8, 'mixed');
      setSimNotice(`Generated ${res.ingested_count} simulated lab events.`);
      setTimeout(() => setSimNotice(null), 4000);
    } catch (err: any) {
      setSimNotice(`Simulation error: ${err.message}`);
      setTimeout(() => setSimNotice(null), 4000);
    } finally {
      setSimulating(false);
    }
  };

  const navItems = [
    { to: '/dashboard', label: 'SOC Overview', icon: LayoutDashboard },
    { to: '/incidents', label: 'Incidents & Triage', icon: AlertTriangle },
    { to: '/events', label: 'Security Events', icon: Radio },
    { to: '/threats', label: 'Threat Scores', icon: FileCode2 },
    { to: '/blocked-sources', label: 'Blocked Sources', icon: Lock },
    { to: '/prevention', label: 'Prevention Engine', icon: Cpu },
  ];

  return (
    <div className="flex h-screen bg-cyber-bg text-slate-100 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-cyber-border bg-cyber-card flex flex-col justify-between shrink-0">
        <div>
          {/* Logo */}
          <div className="p-4 border-b border-cyber-border flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <h1 className="font-bold text-lg tracking-wider text-white">AEGIS-IDPS</h1>
              <p className="text-xs text-cyber-muted tracking-tight">Intelligent SOC Defense</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-300 border-l-2 border-cyan-400 pl-2.5'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-cyber-surface/60'
                    }`
                  }
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* User Card & Simulation Lab Trigger */}
        <div className="p-3 border-t border-cyber-border space-y-3">
          {/* Quick Simulation Trigger */}
          <div className="p-2.5 rounded-lg bg-cyber-surface/50 border border-cyber-border">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="h-3 w-3 text-cyan-400" />
                Lab Attack Simulator
              </span>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded font-mono">
                SAFE
              </span>
            </div>
            <button
              onClick={handleQuickSimulation}
              disabled={simulating}
              className="w-full flex items-center justify-center gap-2 px-2.5 py-1.5 rounded bg-cyan-600/30 hover:bg-cyan-600/50 border border-cyan-500/40 text-cyan-200 text-xs font-medium transition-all disabled:opacity-50"
            >
              <Play className={`h-3 w-3 ${simulating ? 'animate-spin' : ''}`} />
              {simulating ? 'Injecting Traffic...' : 'Trigger Simulation'}
            </button>
            {simNotice && (
              <p className="mt-1.5 text-[11px] text-cyan-300 font-mono truncate">{simNotice}</p>
            )}
          </div>

          {/* Profile & Logout */}
          <div className="flex items-center justify-between pt-1">
            <div className="flex items-center space-x-2.5 min-w-0">
              <div className="h-8 w-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-slate-300">
                {user?.username?.slice(0, 2).toUpperCase() || 'SO'}
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium text-slate-200 truncate">{user?.username}</p>
                <span className="inline-block text-[10px] font-mono text-cyan-400 uppercase">
                  {user?.role}
                </span>
              </div>
            </div>
            <button
              onClick={logout}
              title="Logout session"
              className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded transition"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="h-14 border-b border-cyber-border bg-cyber-card/80 backdrop-blur px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center space-x-4">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Security Operations Center
            </span>
            <span className="text-slate-600">/</span>
            <div className="flex items-center space-x-1.5 bg-cyan-950/40 border border-cyan-800/40 text-cyan-300 text-xs px-2.5 py-1 rounded-full">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
              <span>SURICATA EVE ENGINE ACTIVE</span>
            </div>
          </div>

          {/* Right Status Indicators */}
          <div className="flex items-center space-x-4">
            {/* Prevention Mode Badge */}
            <div className="flex items-center space-x-1.5 bg-emerald-950/40 border border-emerald-800/40 text-emerald-300 text-xs px-2.5 py-1 rounded-full" title="Automated policy executed in safe software mock mode. Host kernel firewall is not modified.">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>PREVENTION: MOCK LAB MODE</span>
            </div>

            {/* WebSocket Stream Badge */}
            <div
              className={`flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-full border ${
                isConnected
                  ? 'bg-emerald-950/40 border-emerald-800/40 text-emerald-400'
                  : status === 'RECONNECTING'
                  ? 'bg-amber-950/40 border-amber-800/40 text-amber-400'
                  : 'bg-rose-950/40 border-rose-800/40 text-rose-400'
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  isConnected
                    ? 'bg-emerald-400 animate-ping'
                    : status === 'RECONNECTING'
                    ? 'bg-amber-400 animate-pulse'
                    : 'bg-rose-500'
                }`}
              ></span>
              <span className="font-mono uppercase font-semibold text-[11px]">
                {isConnected ? 'LIVE WS CONNECTED' : status}
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6 bg-cyber-bg">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
