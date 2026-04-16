/** ShieldSession — guarded agent session with tool call interception. */

import {
  ConfirmationRejected,
  ServerClient,
  ToolCallBlocked,
} from "./client.js";
import type { CheckResult, ShieldConfig } from "./models.js";
import { Decision } from "./models.js";

export type ConfirmCallback = (
  toolName: string,
  params: Record<string, unknown>,
) => Promise<boolean>;

/**
 * Wraps arbitrary tool calls through the shield check pipeline.
 */
export class GuardedExecutor {
  constructor(
    private readonly client: ServerClient,
    private readonly sessionId: string,
    private readonly confirmCallback?: ConfirmCallback,
  ) {}

  /**
   * Check with the server, enforce the decision, then run the tool function.
   */
  async execute<T>(
    toolName: string,
    params: Record<string, unknown>,
    fn: (params: Record<string, unknown>) => Promise<T>,
    opts?: { sourceId?: string },
  ): Promise<T> {
    const result: CheckResult = await this.client.checkToolCall({
      sessionId: this.sessionId,
      toolName,
      params,
      sourceId: opts?.sourceId,
    });

    if (result.action === Decision.BLOCK) {
      throw new ToolCallBlocked(toolName, result.reason, result.trace_id);
    }

    if (result.action === Decision.REQUIRE_CONFIRMATION) {
      if (!this.confirmCallback) {
        throw new ConfirmationRejected(toolName);
      }
      const confirmed = await this.confirmCallback(toolName, params);
      if (!confirmed) {
        throw new ConfirmationRejected(toolName);
      }
    }

    return fn(params);
  }
}

/**
 * Represents a guarded agent session.
 *
 * Usage:
 * ```ts
 * const session = await shield.session("Summarize my emails");
 * try {
 *   const result = await session.executor.execute("read_inbox", { limit: 10 }, readInbox);
 * } finally {
 *   session.close();
 * }
 * ```
 */
export class ShieldSession {
  public sessionId = "";
  public traceId = "";
  private _executor: GuardedExecutor | null = null;

  constructor(
    private readonly client: ServerClient,
    private readonly userMessage: string,
    private readonly agentId: string,
    private readonly metadata: Record<string, unknown>,
    private readonly confirmCallback?: ConfirmCallback,
  ) {}

  /** Initialize the session by registering it with the server. */
  async open(): Promise<this> {
    const info = await this.client.createSession({
      userMessage: this.userMessage,
      agentId: this.agentId,
      metadata: this.metadata,
    });
    this.sessionId = info.session_id;
    this.traceId = info.trace_id;
    this._executor = new GuardedExecutor(
      this.client,
      this.sessionId,
      this.confirmCallback,
    );
    return this;
  }

  /** Close the session. Currently a no-op as lifecycle is server-tracked. */
  close(): void {
    // Session lifecycle is tracked server-side.
  }

  /** Return the executor that routes tool calls through the server check. */
  get executor(): GuardedExecutor {
    if (!this._executor) {
      throw new Error("ShieldSession.open() must be called before accessing executor");
    }
    return this._executor;
  }
}
