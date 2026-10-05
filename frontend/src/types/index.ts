export interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string;
  role: 'admin' | 'analyst';
  is_active: boolean;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface SecurityEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  event_type: string;
  signature: string;
  signature_id?: number;
  category: string;
  severity: number;
  action: string;
  raw_reference?: string;
  is_simulation: boolean;
  incident_id?: number;
  created_at: string;
}

export interface ThreatFactor {
  reason: string;
  points: number;
}

export interface ThreatScore {
  id: number;
  incident_id: number;
  score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  factors: ThreatFactor[];
  created_at: string;
}

export interface Incident {
  id: number;
  title: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  threat_score: number;
  confidence: number;
  source_ip: string;
  destination_ip?: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  is_simulation: boolean;
  origin?: 'REAL' | 'SIMULATION' | 'MIXED';
  created_at: string;
  updated_at: string;
  threat_score_detail?: ThreatScore;
  events?: SecurityEvent[];
}

export interface BlockedSource {
  id: number;
  ip: string;
  reason: string;
  severity: string;
  threat_score: number;
  blocked_time: string;
  expiry?: string;
  status: 'ACTIVE' | 'EXPIRED' | 'MANUALLY_UNBLOCKED' | 'WHITELISTED';
  is_whitelisted: boolean;
  provider: string;
  is_simulation: boolean;
  created_by: string;
  unblocked_at?: string;
  unblocked_by?: string;
  created_at: string;
}

export interface PreventionAction {
  id: number;
  incident_id?: number;
  action: string;
  target: string;
  reason: string;
  duration_minutes?: number;
  status: 'EXECUTED' | 'FAILED' | 'REVERTED';
  provider: string;
  is_simulation: boolean;
  executed_at: string;
  created_at: string;
}

export interface PreventionStatus {
  enabled: boolean;
  provider: string;
  auto_block_threshold: number;
  default_block_duration_minutes: number;
  active_blocks_count: number;
  whitelisted_count: number;
  real_firewall_enabled: boolean;
  mode_description: string;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded';
  version: string;
  environment: string;
  components: {
    database: string;
    detection_parser: string;
    prevention_provider: string;
    prevention_enabled: boolean;
    prevention_mode: string;
    real_firewall_enabled: boolean;
    demo_mode: boolean;
    websocket_service: string;
    active_websocket_connections: number;
  };
}

export interface WebSocketEnvelope<T = any> {
  event_type: string;
  version: string;
  event_id: string;
  timestamp: string;
  resource_id?: number | string;
  data: T;
}
