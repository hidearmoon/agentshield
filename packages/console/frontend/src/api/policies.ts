import { apiFetch, buildQuery } from "./client";

export interface PolicyRule {
  id?: string;
  rule_name: string;
  rule_type: string;
  condition: Record<string, unknown>;
  action: string;
  priority: number;
  enabled: boolean;
}

export interface Policy {
  id: string;
  name: string;
  version: number;
  content: Record<string, unknown>;
  is_active: boolean;
  rollout_percentage: number;
  created_by: string | null;
  created_at: string | null;
  rules: PolicyRule[];
}

export interface PolicyCreatePayload {
  name: string;
  content: Record<string, unknown>;
  rules: Omit<PolicyRule, "id">[];
}

export interface SimulateResult {
  final_action: string;
  rule_evaluations: Array<{
    rule_name: string;
    matched: boolean;
    action: string | null;
  }>;
  test_input: Record<string, unknown>;
}

export function fetchPolicies(
  params: { active_only?: boolean; limit?: number; offset?: number } = {}
): Promise<Policy[]> {
  return apiFetch<Policy[]>(`/policies${buildQuery(params)}`);
}

export function fetchPolicy(id: string): Promise<Policy> {
  return apiFetch<Policy>(`/policies/${id}`);
}

export function fetchPolicyVersions(name: string): Promise<Policy[]> {
  return apiFetch<Policy[]>(`/policies/name/${encodeURIComponent(name)}/versions`);
}

export function createPolicy(payload: PolicyCreatePayload): Promise<Policy> {
  return apiFetch<Policy>("/policies", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updatePolicy(
  id: string,
  payload: Partial<PolicyCreatePayload & { is_active: boolean; rollout_percentage: number }>
): Promise<Policy> {
  return apiFetch<Policy>(`/policies/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function activatePolicy(id: string): Promise<Policy> {
  return apiFetch<Policy>(`/policies/${id}/activate`, { method: "POST" });
}

export function simulatePolicy(
  content: Record<string, unknown>,
  rules: Omit<PolicyRule, "id">[],
  testInput: Record<string, unknown>
): Promise<SimulateResult> {
  return apiFetch<SimulateResult>("/policies/simulate", {
    method: "POST",
    body: JSON.stringify({ content, rules, test_input: testInput }),
  });
}
