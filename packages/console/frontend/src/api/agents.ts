import { apiFetch, buildQuery } from "./client";

export interface Agent {
  id: string;
  agent_id: string;
  name: string;
  description: string | null;
  allowed_tools: string[];
  metadata: Record<string, unknown>;
  created_at: string | null;
  updated_at: string | null;
}

export interface TopologyNode {
  id: string;
  name: string;
  tools: string[];
}

export interface TopologyEdge {
  source: string;
  target: string;
  weight: number;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export function fetchAgents(
  params: { limit?: number; offset?: number } = {}
): Promise<Agent[]> {
  return apiFetch<Agent[]>(`/agents${buildQuery(params)}`);
}

export function fetchAgent(id: string): Promise<Agent> {
  return apiFetch<Agent>(`/agents/${id}`);
}

export function fetchTopology(hours = 24): Promise<Topology> {
  return apiFetch<Topology>(`/agents/topology${buildQuery({ hours })}`);
}

export function createAgent(payload: {
  agent_id: string;
  name: string;
  description?: string;
  allowed_tools?: string[];
  metadata?: Record<string, unknown>;
}): Promise<Agent> {
  return apiFetch<Agent>("/agents", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateAgent(
  id: string,
  payload: Partial<{
    name: string;
    description: string;
    allowed_tools: string[];
    metadata: Record<string, unknown>;
  }>
): Promise<Agent> {
  return apiFetch<Agent>(`/agents/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function deleteAgent(id: string): Promise<void> {
  return apiFetch<void>(`/agents/${id}`, { method: "DELETE" });
}
