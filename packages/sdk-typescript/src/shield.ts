/** Shield — primary entry point for the AgentGuard TypeScript SDK. */

import {
  ConfigError,
  ConfirmationRejected,
  ServerClient,
  ToolCallBlocked,
} from "./client.js";
import type {
  CheckResult,
  ExtractedData,
  MarkedData,
  SanitizedData,
  ShieldConfig,
} from "./models.js";
import { Decision } from "./models.js";
import { ShieldSession, type ConfirmCallback } from "./session.js";

const DEFAULT_BASE_URL = "http://localhost:8000";
const DEFAULT_TIMEOUT = 10_000; // ms
const DEFAULT_MAX_RETRIES = 3;

export interface ShieldOptions {
  apiKey?: string;
  baseUrl?: string;
  /** Timeout in milliseconds. */
  timeout?: number;
  maxRetries?: number;
  agentId?: string;
  confirmCallback?: ConfirmCallback;
}

/**
 * Lightweight security guardrail for AI agent tool calls.
 *
 * All security logic lives server-side. This class captures context,
 * forwards it to the core engine, and enforces the returned decision.
 *
 * ```ts
 * const shield = new Shield(); // reads AGENTGUARD_API_KEY from env
 *
 * const guardedFn = shield.guard("send_email", sendEmail);
 * await guardedFn({ to: "a@b.com", body: "hi" });
 * ```
 */
export class Shield {
  private readonly client: ServerClient;
  private readonly config: ShieldConfig;
  private readonly defaultSessionId = "__standalone__";

  constructor(opts: ShieldOptions = {}) {
    const apiKey =
      opts.apiKey ?? process.env.AGENTGUARD_API_KEY ?? "";
    if (!apiKey) {
      throw new ConfigError(
        "API key is required. Set the AGENTGUARD_API_KEY environment variable " +
          "or pass apiKey to the Shield constructor.",
      );
    }

    this.config = {
      apiKey,
      baseUrl: opts.baseUrl ?? process.env.AGENTGUARD_BASE_URL ?? DEFAULT_BASE_URL,
      timeout: opts.timeout ?? DEFAULT_TIMEOUT,
      maxRetries: opts.maxRetries ?? DEFAULT_MAX_RETRIES,
      agentId: opts.agentId ?? process.env.AGENTGUARD_AGENT_ID ?? "",
      confirmCallback: opts.confirmCallback,
    };

    this.client = new ServerClient(this.config);
  }

  /**
   * Wrap an async tool function so a server check runs before every call.
   *
   * Returns a new function with the same signature.
   */
  guard<T>(
    toolName: string,
    fn: (params: Record<string, unknown>) => Promise<T>,
    opts?: { sessionId?: string },
  ): (params: Record<string, unknown>) => Promise<T> {
    const sessionId = opts?.sessionId ?? this.defaultSessionId;

    return async (params: Record<string, unknown>): Promise<T> => {
      const result: CheckResult = await this.client.checkToolCall({
        sessionId,
        toolName,
        params,
      });

      if (result.action === Decision.BLOCK) {
        throw new ToolCallBlocked(toolName, result.reason, result.trace_id);
      }

      if (result.action === Decision.REQUIRE_CONFIRMATION) {
        if (!this.config.confirmCallback) {
          throw new ConfirmationRejected(toolName);
        }
        const confirmed = await this.config.confirmCallback(toolName, params);
        if (!confirmed) {
          throw new ConfirmationRejected(toolName);
        }
      }

      return fn(params);
    };
  }

  /**
   * Create a guarded session.
   *
   * Call `.open()` to register it with the server, then use `.executor`
   * to run guarded tool calls. Call `.close()` when done.
   */
  session(
    userMessage: string,
    opts?: { agentId?: string; metadata?: Record<string, unknown> },
  ): ShieldSession {
    return new ShieldSession(
      this.client,
      userMessage,
      opts?.agentId ?? this.config.agentId,
      opts?.metadata ?? {},
      this.config.confirmCallback,
    );
  }

  /** Forward data to the server-side sanitization pipeline. */
  async sanitize(
    data: string,
    opts: { source: string; dataType?: string },
  ): Promise<SanitizedData> {
    return this.client.sanitize({
      data,
      source: opts.source,
      dataType: opts.dataType,
    });
  }

  /** Forward data to the server-side two-phase extraction pipeline. */
  async twoPhaseExtract(
    data: string,
    opts: { schemaName: string },
  ): Promise<ExtractedData> {
    return this.client.extract({ data, schemaName: opts.schemaName });
  }

  /** Forward data to the server-side trust marker. */
  async markData(
    data: string,
    opts: { sourceId: string; clientTrustLevel?: string },
  ): Promise<MarkedData> {
    return this.client.markData({
      data,
      sourceId: opts.sourceId,
      clientTrustLevel: opts.clientTrustLevel,
    });
  }
}
