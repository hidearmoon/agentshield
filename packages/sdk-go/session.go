package agentshield

import (
	"context"
	"fmt"
)

// Session represents a guarded agent session.
//
// Create one via Shield.NewSession(), then use Execute() to run tool calls
// through the server check pipeline.
type Session struct {
	SessionID   string
	TraceID     string
	client      *Client
	confirmFunc func(toolName string, params map[string]any) (bool, error)
}

// Execute checks a tool call with the server, enforces the decision, then runs fn.
func (s *Session) Execute(ctx context.Context, toolName string, params map[string]any, fn func(ctx context.Context, params map[string]any) (any, error)) (any, error) {
	result, err := s.client.CheckToolCall(ctx, s.SessionID, toolName, params, "", nil)
	if err != nil {
		return nil, fmt.Errorf("agentshield: check tool call: %w", err)
	}

	switch result.Action {
	case Block:
		return nil, &ToolCallBlockedError{
			Tool:    toolName,
			Reason:  result.Reason,
			TraceID: result.TraceID,
		}

	case RequireConfirmation:
		if s.confirmFunc == nil {
			return nil, &ConfirmationRejectedError{Tool: toolName}
		}
		confirmed, err := s.confirmFunc(toolName, params)
		if err != nil {
			return nil, fmt.Errorf("agentshield: confirm callback: %w", err)
		}
		if !confirmed {
			return nil, &ConfirmationRejectedError{Tool: toolName}
		}
	}

	return fn(ctx, params)
}

// ToolCallBlockedError is returned when the server blocks a tool call.
type ToolCallBlockedError struct {
	Tool    string
	Reason  string
	TraceID string
}

func (e *ToolCallBlockedError) Error() string {
	return fmt.Sprintf("agentshield: tool call '%s' blocked: %s (trace_id=%s)", e.Tool, e.Reason, e.TraceID)
}

// ConfirmationRejectedError is returned when a tool call requiring confirmation is not confirmed.
type ConfirmationRejectedError struct {
	Tool string
}

func (e *ConfirmationRejectedError) Error() string {
	return fmt.Sprintf("agentshield: tool call '%s' requires confirmation and was not confirmed", e.Tool)
}

// ConfigError is returned when the SDK configuration is invalid.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("agentshield: config error: %s", e.Message)
}
