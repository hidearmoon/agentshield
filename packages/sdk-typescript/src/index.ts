/** AgentGuard TypeScript SDK — lightweight security guardrails for AI agents. */

export { Shield } from "./shield.js";
export type { ShieldOptions } from "./shield.js";
export { ShieldSession, GuardedExecutor } from "./session.js";
export type { ConfirmCallback } from "./session.js";
export {
  ServerClient,
  AgentGuardError,
  ToolCallBlocked,
  ConfirmationRejected,
  ConfigError,
} from "./client.js";
export {
  Decision,
  type CheckResult,
  type SanitizedData,
  type ExtractedData,
  type MarkedData,
  type SessionInfo,
  type ShieldConfig,
} from "./models.js";
