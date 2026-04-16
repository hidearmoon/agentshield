import { apiFetch } from "./client";

export interface RuleDefinition {
  name: string;
  description: string;
  enabled: boolean;
  when: Record<string, unknown>;
  action: string;
  reason: string;
}

export interface RuleResponse {
  name: string;
  description: string;
  enabled: boolean;
  type: "builtin" | "custom";
}

export interface RuleListResponse {
  rules: RuleResponse[];
  total: number;
}

export interface ValidateResponse {
  valid: boolean;
  name?: string;
  error?: string;
}

export async function fetchRules(): Promise<RuleListResponse> {
  return apiFetch("/api/v1/rules");
}

export async function createRule(rule: RuleDefinition): Promise<RuleResponse> {
  return apiFetch("/api/v1/rules", {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export async function createRulesBatch(rules: RuleDefinition[]): Promise<RuleListResponse> {
  return apiFetch("/api/v1/rules/batch", {
    method: "POST",
    body: JSON.stringify(rules),
  });
}

export async function deleteRule(name: string): Promise<void> {
  return apiFetch(`/api/v1/rules/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}

export async function toggleRule(name: string, enabled: boolean): Promise<void> {
  return apiFetch(`/api/v1/rules/${encodeURIComponent(name)}/enabled?enabled=${enabled}`, {
    method: "PATCH",
  });
}

export async function validateRule(rule: RuleDefinition): Promise<ValidateResponse> {
  return apiFetch("/api/v1/rules/validate", {
    method: "POST",
    body: JSON.stringify(rule),
  });
}
