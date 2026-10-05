import {
  User,
  LoginResponse,
  SecurityEvent,
  Incident,
  ThreatScore,
  BlockedSource,
  PreventionAction,
  PreventionStatus,
  SystemHealth,
} from '../types';
const getApiBase = (): string => {
  const envUrl = import.meta.env.VITE_API_URL;
  if (!envUrl) return '/api';
  const clean = envUrl.trim().replace(/\/+$/, '');
  if (clean.startsWith('http') && !clean.endsWith('/api')) {
    return `${clean}/api`;
  }
  return clean;
};

const API_BASE = getApiBase();

class ApiClient {
  private getToken(): string | null {
    return localStorage.getItem('idps_token');
  }

  public setToken(token: string) {
    localStorage.setItem('idps_token', token);
  }

  public clearToken() {
    localStorage.removeItem('idps_token');
    localStorage.removeItem('idps_user');
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      this.clearToken();
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
      throw new Error('Session expired or unauthorized');
    }

    if (!response.ok) {
      let errorMessage = `HTTP Error ${response.status}`;
      try {
        const errJson = await response.json();
        errorMessage = errJson.detail || errJson.message || errorMessage;
      } catch {
        // ignore fallback
      }
      throw new Error(errorMessage);
    }

    return response.json();
  }

  // Auth
  async login(credentials: { username: string; password: string }): Promise<LoginResponse> {
    const data = await this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    this.setToken(data.access_token);
    localStorage.setItem('idps_user', JSON.stringify(data.user));
    return data;
  }

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Health
  async getHealth(): Promise<SystemHealth> {
    return this.request<SystemHealth>('/health');
  }

  // Events
  async listEvents(params?: Record<string, any>): Promise<SecurityEvent[]> {
    const query = new URLSearchParams(params).toString();
    return this.request<SecurityEvent[]>(`/events?${query}`);
  }

  async getEvent(id: number): Promise<SecurityEvent> {
    return this.request<SecurityEvent>(`/events/${id}`);
  }

  async generateDemoEvents(count: number = 10, scenario: string = 'mixed'): Promise<any> {
    return this.request('/events/demo/generate', {
      method: 'POST',
      body: JSON.stringify({ count, scenario }),
    });
  }

  // Incidents
  async listIncidents(params?: Record<string, any>): Promise<Incident[]> {
    const query = new URLSearchParams(params).toString();
    return this.request<Incident[]>(`/incidents?${query}`);
  }

  async getIncident(id: number): Promise<Incident> {
    return this.request<Incident>(`/incidents/${id}`);
  }

  async updateIncidentStatus(id: number, status: string, notes?: string): Promise<Incident> {
    return this.request<Incident>(`/incidents/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
  }

  // Threats
  async listThreats(params?: Record<string, any>): Promise<ThreatScore[]> {
    const query = new URLSearchParams(params).toString();
    return this.request<ThreatScore[]>(`/threats?${query}`);
  }

  async getThreat(id: number): Promise<ThreatScore> {
    return this.request<ThreatScore>(`/threats/${id}`);
  }

  // Blocked Sources
  async listBlockedSources(params?: Record<string, any>): Promise<BlockedSource[]> {
    const query = new URLSearchParams(params).toString();
    return this.request<BlockedSource[]>(`/blocked-sources?${query}`);
  }

  async getBlockedSource(id: number): Promise<BlockedSource> {
    return this.request<BlockedSource>(`/blocked-sources/${id}`);
  }

  async unblockSource(id: number, reason: string): Promise<BlockedSource> {
    return this.request<BlockedSource>(`/blocked-sources/${id}/unblock`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async allowlistSource(ip: string, reason: string): Promise<BlockedSource> {
    return this.request<BlockedSource>('/blocked-sources/allowlist', {
      method: 'POST',
      body: JSON.stringify({ ip, reason }),
    });
  }

  // Prevention
  async getPreventionStatus(): Promise<PreventionStatus> {
    return this.request<PreventionStatus>('/prevention/status');
  }

  async listPreventionActions(params?: Record<string, any>): Promise<PreventionAction[]> {
    const query = new URLSearchParams(params).toString();
    return this.request<PreventionAction[]>(`/prevention/actions?${query}`);
  }

  async getPreventionPolicies(): Promise<any> {
    return this.request('/prevention/policies');
  }

  async updatePreventionPolicies(payload: any): Promise<any> {
    return this.request('/prevention/policies', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }
}

export const api = new ApiClient();
