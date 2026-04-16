import { apiFetch, buildQuery } from "./client";

export interface Alert {
  id: string;
  rule_id: string | null;
  severity: string;
  title: string;
  description: string | null;
  agent_id: string | null;
  trace_id: string | null;
  status: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  metadata: Record<string, unknown>;
  created_at: string | null;
}

export interface AlertListResponse {
  total: number;
  items: Alert[];
}

export interface AlertSearchParams {
  status?: string;
  severity?: string;
  agent_id?: string;
  limit?: number;
  offset?: number;
}

export function fetchAlerts(
  params: AlertSearchParams = {}
): Promise<AlertListResponse> {
  return apiFetch<AlertListResponse>(`/alerts${buildQuery(params)}`);
}

export function fetchAlert(id: string): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${id}`);
}

export function acknowledgeAlert(id: string): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${id}/acknowledge`, { method: "POST" });
}

export function resolveAlert(id: string): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${id}/resolve`, { method: "POST" });
}
