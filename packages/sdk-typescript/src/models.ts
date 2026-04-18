/** Data models for AgentGuard SDK responses. */

export enum Decision {
  ALLOW = "ALLOW",
  BLOCK = "BLOCK",
  REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION",
}

export interface CheckResult {
  action: Decision;
  reason: string;
  trace_id: string;
  span_id: string;
}

export interface SanitizedData {
  content: string;
  trust_level: string;
  sanitization_chain: string[];
}

export interface ExtractedData {
  extracted: Record<string, unknown>;
  schema_name: string;
}

export interface MarkedData {
  content: string;
  trust_level: string;
  source_id: string;
  allowed_actions: string[];
  tool_restrictions: string[];
}

export interface SessionInfo {
  session_id: string;
  trace_id: string;
}

export interface ShieldConfig {
  apiKey: string;
  baseUrl: string;
  timeout: number;
  maxRetries: number;
  agentId: string;
  confirmCallback?: (toolName: string, params: Record<string, unknown>) => Promise<boolean>;
}
