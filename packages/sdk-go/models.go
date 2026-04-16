// Package agentshield provides a lightweight SDK for the AgentShield security engine.
//
// All security decisions happen server-side. The SDK captures tool call context,
// forwards it to the core engine, and enforces the returned decision.
package agentshield

// Decision represents the server's verdict on a tool call.
type Decision string

const (
	// Allow means the tool call is permitted.
	Allow Decision = "ALLOW"
	// Block means the tool call is denied.
	Block Decision = "BLOCK"
	// RequireConfirmation means the tool call needs user confirmation.
	RequireConfirmation Decision = "REQUIRE_CONFIRMATION"
)

// CheckResult is the response from POST /api/v1/check.
type CheckResult struct {
	Action  Decision `json:"action"`
	Reason  string   `json:"reason"`
	TraceID string   `json:"trace_id"`
	SpanID  string   `json:"span_id"`
}

// SanitizedData is the response from POST /api/v1/sanitize.
type SanitizedData struct {
	Content           string   `json:"content"`
	TrustLevel        string   `json:"trust_level"`
	SanitizationChain []string `json:"sanitization_chain"`
}

// ExtractedData is the response from POST /api/v1/extract.
type ExtractedData struct {
	Extracted  map[string]any `json:"extracted"`
	SchemaName string         `json:"schema_name"`
}

// MarkedData is data annotated with trust metadata by the server.
type MarkedData struct {
	Content          string   `json:"content"`
	TrustLevel       string   `json:"trust_level"`
	SourceID         string   `json:"source_id"`
	AllowedActions   []string `json:"allowed_actions"`
	ToolRestrictions []string `json:"tool_restrictions"`
}

// SessionInfo is the response from POST /api/v1/sessions.
type SessionInfo struct {
	SessionID string `json:"session_id"`
	TraceID   string `json:"trace_id"`
}

// Config holds the SDK configuration.
type Config struct {
	// APIKey is required. Read from AGENTSHIELD_API_KEY env var or set explicitly.
	APIKey string

	// BaseURL of the AgentShield core engine. Defaults to http://localhost:8000.
	BaseURL string

	// Timeout for HTTP requests in milliseconds. Defaults to 10000.
	TimeoutMs int

	// MaxRetries for transient failures. Defaults to 3.
	MaxRetries int

	// AgentID identifies this agent. Optional.
	AgentID string

	// ConfirmFunc is called when the server returns REQUIRE_CONFIRMATION.
	// Return true to proceed, false to reject.
	ConfirmFunc func(toolName string, params map[string]any) (bool, error)
}
