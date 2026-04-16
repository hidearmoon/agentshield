import { apiFetch, buildQuery } from "./client";

export interface DashboardSummary {
  total_calls: number;
  blocked_calls: number;
  allowed_calls: number;
  confirm_calls: number;
  avg_drift_score: number;
  active_agents: number;
  total_traces: number;
  block_rate_pct: number;
  time_range_hours: number;
}

export interface TrafficPoint {
  bucket: string;
  total: number;
  blocked: number;
  allowed: number;
  confirm: number;
}

export interface DriftPoint {
  bucket: string;
  avg_drift: number;
  max_drift: number;
  sample_count: number;
}

export interface RiskEntry {
  agent_id: string;
  total_calls: number;
  blocked: number;
  avg_drift: number;
  max_drift: number;
}

export interface DashboardData {
  summary: DashboardSummary;
  traffic: TrafficPoint[];
  intent_drift: DriftPoint[];
  risk_ranking: RiskEntry[];
}

export function fetchDashboard(hours = 24): Promise<DashboardData> {
  return apiFetch<DashboardData>(`/dashboard/stats${buildQuery({ hours })}`);
}
