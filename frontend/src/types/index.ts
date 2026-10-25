export interface User {
  id: number;
  username: string;
  email: string;
  created_at?: string;
}

export interface Token {
  access_token: string;
  token_type: string;
  user: User;
}

export interface LogFile {
  id: number;
  filename: string;
  source_type: string;
  uploaded_at?: string;
  processing_status: string;
  event_count: number;
  suspicious_count: number;
}

export interface LogEvent {
  id: number;
  log_file_id?: number;
  timestamp?: string;
  source?: string;
  event_type?: string;
  ip_address?: string;
  username?: string;
  hostname?: string;
  resource?: string;
  severity?: string;
  raw_message?: string;
  is_suspicious: number;
  importance: number;
  created_at?: string;
  alerts?: any[];
}

export interface LogEventDetail extends LogEvent {
  metadata_json?: string;
  related_events?: LogEvent[];
  related_incidents?: any[];
}

export interface DetectionAlert {
  id: number;
  event_id?: number;
  rule_name: string;
  severity: string;
  description?: string;
  risk_points: number;
  created_at?: string;
}

export interface Incident {
  id: number;
  title: string;
  description?: string;
  severity?: string;
  risk_score: number;
  confidence: number;
  status: string;
  created_at?: string;
  updated_at?: string;
  event_count: number;
  related_ips: string[];
  related_users: string[];
}

export interface IncidentDetail extends Incident {
  affected_systems: string[];
  detection_reasons: string[];
}

export interface AttackStoryEntry {
  id: number;
  sequence_order: number;
  timestamp?: string;
  title?: string;
  description?: string;
  event_ids: string;
  event_type?: string;
  severity?: string;
}

export interface AttackStory {
  id: number;
  incident_id: number;
  title?: string;
  summary?: string;
  timeline_json: string;
  conclusion?: string;
  created_at?: string;
  entries: AttackStoryEntry[];
}

export interface DashboardAnalytics {
  total_logs: number;
  total_events: number;
  suspicious_events: number;
  active_incidents: number;
  critical_incidents: number;
  events_over_time: { date: string; count: number }[];
  severity_distribution: { severity: string; count: number }[];
  incidents_by_risk: { level: string; range: string; count: number }[];
  recent_incidents: any[];
  recent_suspicious: any[];
}

export interface EventAnalytics {
  events_over_time: { date: string; total: number; suspicious: number }[];
  suspicious_over_time: { date: string; count: number }[];
  incidents_over_time: { date: string; count: number }[];
  top_ips: { ip: string; count: number }[];
  top_event_types: { type: string; count: number }[];
  top_rules: { rule: string; count: number }[];
  severity_distribution: { severity: string; count: number }[];
}
