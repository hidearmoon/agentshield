/**
 * Lightweight HTTP client for AgentGuard Core Engine.
 * Designed for the OpenClaw plugin runtime (Node.js, in-process).
 */

export interface AgentGuardConfig {
  baseUrl: string;
  apiKey: string;
  timeout: number;
  maxRetries: number;
}

export interface CheckResult {
  action: "ALLOW" | "BLOCK" | "REQUIRE_CONFIRMATION";
  reason: string;
  trace_id: string;
  span_id: string;
  engine: string;
  trust_level: string;
  latency_ms: number;
}

export interface SessionInfo {
  session_id: string;
  trace_id: string;
}

export class AgentGuardClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeout: number;
  private readonly maxRetries: number;

  constructor(config: AgentGuardConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.timeout = config.timeout;
    this.maxRetries = config.maxRetries;
    this.headers = {
      Authorization: `Bearer ${config.apiKey}`,
      "Content-Type": "application/json",
      "User-Agent": "agentguard-openclaw/0.1.0",
    };
  }

  private async request<T>(path: string, body: unknown): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      try {
        const response = await fetch(`${this.baseUrl}${path}`, {
          method: "POST",
          headers: this.headers,
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        if (!response.ok) {
          const text = await response.text();
          throw new Error(`AgentGuard HTTP ${response.status}: ${text}`);
        }

        return (await response.json()) as T;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt === this.maxRetries) throw lastError;
      } finally {
        clearTimeout(timer);
      }
    }

    throw lastError ?? new Error("Request failed");
  }

  async checkToolCall(opts: {
    sessionId: string;
    toolName: string;
    params: Record<string, unknown>;
    sourceId?: string;
    clientTrustLevel?: string;
  }): Promise<CheckResult> {
    return this.request<CheckResult>("/api/v1/check", {
      session_id: opts.sessionId,
      tool_name: opts.toolName,
      params: opts.params,
      source_id: opts.sourceId ?? "",
      client_trust_level: opts.clientTrustLevel,
    });
  }

  async createSession(opts: {
    userMessage: string;
    agentId?: string;
    metadata?: Record<string, unknown>;
  }): Promise<SessionInfo> {
    return this.request<SessionInfo>("/api/v1/sessions", {
      user_message: opts.userMessage,
      agent_id: opts.agentId ?? "",
      metadata: opts.metadata ?? {},
    });
  }

  async recordToolResult(opts: {
    sessionId: string;
    toolName: string;
    result: Record<string, unknown>;
    durationMs: number;
  }): Promise<void> {
    await this.request<unknown>("/api/v1/traces/tool-result", {
      session_id: opts.sessionId,
      tool_name: opts.toolName,
      result: opts.result,
      duration_ms: opts.durationMs,
    });
  }
}
