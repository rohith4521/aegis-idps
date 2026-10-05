import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Lock, User, Key, ArrowRight, AlertCircle, ShieldCheck } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Please provide both username and password.');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      await login(username.trim(), password);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const fillCredentials = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background Cyber Glow Highlights */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none"></div>

      <div className="w-full max-w-md z-10 space-y-6">
        {/* Brand Banner */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-glow-cyan mb-2">
            <ShieldAlert className="h-8 w-8" />
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-white">AEGIS-IDPS</h1>
          <p className="text-xs text-cyber-muted tracking-wide uppercase font-mono">
            Intelligent Intrusion Detection & Prevention System
          </p>
        </div>

        {/* Login Card */}
        <div className="rounded-2xl border border-cyber-border bg-cyber-card/90 backdrop-blur-xl p-8 shadow-2xl space-y-6">
          <div className="border-b border-cyber-border pb-4">
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Lock className="h-4 w-4 text-cyan-400" />
              SOC Operator Authentication
            </h2>
            <p className="text-xs text-cyber-muted mt-1">
              Authenticate with your enterprise credentials to access the SOC console.
            </p>
          </div>

          {error && (
            <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-start gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Username / Call-Sign
              </label>
              <div className="relative">
                <User className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin or analyst"
                  className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-100 focus:outline-none focus:border-cyan-500 transition font-mono"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Password
              </label>
              <div className="relative">
                <Key className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-100 focus:outline-none focus:border-cyan-500 transition font-mono"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white text-xs font-semibold tracking-wider uppercase transition shadow-lg shadow-cyan-950/50 disabled:opacity-50"
            >
              <span>{loading ? 'Authenticating...' : 'Sign In To Console'}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          {/* Demo Helper - Strictly gated to Development / Demo Mode */}
          {import.meta.env.DEV || import.meta.env.VITE_DEMO_MODE === 'true' ? (
            <div className="pt-4 border-t border-cyber-border space-y-2">
              <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider block text-center">
                Lab Evaluation Mode Active
              </span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => fillCredentials('admin', 'Admin@123456')}
                  className="p-2 rounded-lg bg-cyber-surface/60 hover:bg-cyber-surface border border-cyber-border text-left transition"
                >
                  <div className="text-[11px] font-bold text-cyan-400 flex items-center gap-1">
                    <ShieldCheck className="h-3 w-3" />
                    Demo Admin
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono mt-0.5">Quick fill credentials</div>
                </button>

                <button
                  type="button"
                  onClick={() => fillCredentials('analyst', 'Analyst@123456')}
                  className="p-2 rounded-lg bg-cyber-surface/60 hover:bg-cyber-surface border border-cyber-border text-left transition"
                >
                  <div className="text-[11px] font-bold text-emerald-400 flex items-center gap-1">
                    <ShieldCheck className="h-3 w-3" />
                    Demo Analyst
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono mt-0.5">Quick fill credentials</div>
                </button>
              </div>
            </div>
          ) : (
            <div className="pt-3 border-t border-cyber-border text-center">
              <p className="text-[11px] text-slate-500">
                Enterprise Production Console &bull; Authorized Access Only
              </p>
            </div>
          )}
        </div>

        {/* Footer info */}
        <p className="text-center text-[11px] text-slate-500 font-mono">
          AEGIS-IDPS &bull; Computer Networks Capstone PBL &bull; Zero Real Firewall Alteration
        </p>
      </div>
    </div>
  );
};
