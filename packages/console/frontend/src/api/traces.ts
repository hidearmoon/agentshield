import { apiFetch, buildQuery } from "./client";

export interface TraceListItem {
  trace_id: string;
  trace_start: string;
  trace_end: string;
  agents: string[];
  span_count: number;
  max_drift: number;
  decisions: string[];
  root_intent: string;
}

export interface Span {
  trace_id: string;
  span_id: string;
  parent_span_id: string;
  agent_id: string;
  session_id: string;
  span_type: string;
  intent: string;
  intent_drift_score: number;
  data_trust_level: string;
  tool_name: string;
  tool_params: string;
  tool_result_summary: string;
  decision: string;
  decision_reason: string;
  decision_engine: string;
  merkle_hash: string;
  start_time: string;
  end_time: string;
}

export interface TraceDetail {
  trace_id: string;
  spans: Span[];
  summary: {
    span_count: number;
    agents: string[];
    decisions: string[];
    max_drift: number;
    start_time: string | null;
    end_time: string | null;
  } | null;
}

export interface TraceSearchParams {
  q?: string;
  agent_id?: string;
  decision?: string;
  start_time?: string;
  end_time?: string;
  min_drift?: number;
  limit?: number;
  offset?: number;
}

export function searchTraces(
  params: TraceSearchParams = {}
): Promise<TraceListItem[]> {
  return apiFetch<TraceListItem[]>(`/traces${buildQuery(params)}`);
}

export function fetchTrace(traceId: string): Promise<TraceDetail> {
  return apiFetch<TraceDetail>(`/traces/${traceId}`);
}
