/** HTTP client for the AgentGuard core API. */

import type {
  CheckResult,
  ExtractedData,
  MarkedData,
  SanitizedData,
  SessionInfo,
  ShieldConfig,
} from "./models.js";
import { Decision } from "./models.js";

const SDK_VERSION = "0.1.0";

export class AgentGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentGuardError";
  }
}

export class ToolCallBlocked extends AgentGuardError {
  constructor(
    public readonly tool: string,
    public readonly reason: string,
    public readonly traceId: string,
  ) {
    super(`Tool call '${tool}' blocked: ${reason} (trace_id=${traceId})`);
    this.name = "ToolCallBlocked";
  }
}

export class ConfirmationRejected extends AgentGuardError {
  constructor(public readonly tool: string) {
    super(`Tool call '${tool}' requires confirmation and was not confirmed`);
    this.name = "ConfirmationRejected";
  }
}

export class ConfigError extends AgentGuardError {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * Async HTTP client that forwards requests to the AgentGuard core engine.
 *
 * Uses the built-in `fetch` API (available in Node 18+).
 */
export class ServerClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeout: number;
  private readonly maxRetries: number;

  constructor(config: ShieldConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.timeout = config.timeout;
    this.maxRetries = config.maxRetries;
    this.headers = {
      Authorization: `Bearer ${config.apiKey}`,
      "Content-Type": "application/json",
      "User-Agent": `agentguard-ts/${SDK_VERSION}`,
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
          throw new AgentGuardError(
            `HTTP ${response.status}: ${text}`,
          );
        }

        return (await response.json()) as T;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        // Only retry on network / timeout errors, not on 4xx
        if (
          lastError instanceof AgentGuardError ||
          attempt === this.maxRetries
        ) {
          throw lastError;
        }
      } finally {
        clearTimeout(timer);
      }
    }

    throw lastError ?? new AgentGuardError("Request failed");
  }

  async checkToolCall(opts: {
    sessionId: string;
    toolName: string;
    params: Record<string, unknown>;
    sourceId?: string;
    clientTrustLevel?: string;
  }): Promise<CheckResult> {
    const payload: Record<string, unknown> = {
      session_id: opts.sessionId,
      tool_name: opts.toolName,
      params: opts.params,
      sdk_version: SDK_VERSION,
      source_id: opts.sourceId ?? "",
    };
    if (opts.clientTrustLevel !== undefined) {
      payload.client_trust_level = opts.clientTrustLevel;
    }

    const raw = await this.request<{
      action: string;
      reason: string;
      trace_id: string;
      span_id: string;
    }>("/api/v1/check", payload);

    return {
      action: raw.action as Decision,
      reason: raw.reason ?? "",
      trace_id: raw.trace_id ?? "",
      span_id: raw.span_id ?? "",
    };
  }

  async sanitize(opts: {
    data: string;
    source: string;
    dataType?: string;
  }): Promise<SanitizedData> {
    return this.request<SanitizedData>("/api/v1/sanitize", {
      data: opts.data,
      source: opts.source,
      data_type: opts.dataType ?? "auto",
    });
  }

  async extract(opts: {
    data: string;
    schemaName: string;
  }): Promise<ExtractedData> {
    return this.request<ExtractedData>("/api/v1/extract", {
      data: opts.data,
      schema_name: opts.schemaName,
    });
  }

  async createSession(opts: {
    userMessage: string;
    agentId?: string;
    metadata?: Record<string, unknown>;
  }): Promise<SessionInfo> {
    const raw = await this.request<{
      session_id: string;
      trace_id: string;
    }>("/api/v1/sessions", {
      user_message: opts.userMessage,
      agent_id: opts.agentId ?? "",
      metadata: opts.metadata ?? {},
    });
    return {
      session_id: raw.session_id,
      trace_id: raw.trace_id,
    };
  }

  async markData(opts: {
    data: string;
    sourceId: string;
    clientTrustLevel?: string;
  }): Promise<MarkedData> {
    const payload: Record<string, unknown> = {
      data: opts.data,
      source_id: opts.sourceId,
    };
    if (opts.clientTrustLevel !== undefined) {
      payload.client_trust_level = opts.clientTrustLevel;
    }
    return this.request<MarkedData>("/api/v1/mark", payload);
  }
}
