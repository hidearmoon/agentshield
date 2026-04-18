package agentguard

import (
	"context"
	"fmt"
	"os"
)

// Shield is the primary entry point for the AgentGuard Go SDK.
//
// All security logic lives server-side. Shield captures tool call context,
// forwards it to the core engine, and enforces the returned decision.
//
//	shield, err := agentguard.New(agentguard.Config{})
//	if err != nil { ... }
//
//	session, err := shield.NewSession(ctx, "Handle user request", nil)
//	if err != nil { ... }
//
//	result, err := session.Execute(ctx, "send_email", params, sendEmailFn)
type Shield struct {
	client      *Client
	config      Config
	defaultSID  string
}

// New creates a Shield instance.
//
// The API key is read from Config.APIKey or the AGENTGUARD_API_KEY env var.
// Returns a ConfigError if no API key is available.
func New(cfg Config) (*Shield, error) {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("AGENTGUARD_API_KEY")
	}
	if cfg.APIKey == "" {
		return nil, &ConfigError{
			Message: "API key is required. Set the AGENTGUARD_API_KEY environment variable or pass Config.APIKey.",
		}
	}
	if cfg.BaseURL == "" {
		if envURL := os.Getenv("AGENTGUARD_BASE_URL"); envURL != "" {
			cfg.BaseURL = envURL
		}
	}
	if cfg.AgentID == "" {
		if envID := os.Getenv("AGENTGUARD_AGENT_ID"); envID != "" {
			cfg.AgentID = envID
		}
	}

	return &Shield{
		client:     NewClient(cfg),
		config:     cfg,
		defaultSID: "__standalone__",
	}, nil
}

// Guard returns a middleware function that checks a tool call with the server
// before executing the wrapped function.
//
//	guarded := shield.Guard("send_email", sendEmail)
//	result, err := guarded(ctx, params)
func (s *Shield) Guard(
	toolName string,
	fn func(ctx context.Context, params map[string]any) (any, error),
) func(ctx context.Context, params map[string]any) (any, error) {
	return func(ctx context.Context, params map[string]any) (any, error) {
		result, err := s.client.CheckToolCall(ctx, s.defaultSID, toolName, params, "", nil)
		if err != nil {
			return nil, fmt.Errorf("agentguard: check tool call: %w", err)
		}

		switch result.Action {
		case Block:
			return nil, &ToolCallBlockedError{
				Tool:    toolName,
				Reason:  result.Reason,
				TraceID: result.TraceID,
			}

		case RequireConfirmation:
			if s.config.ConfirmFunc == nil {
				return nil, &ConfirmationRejectedError{Tool: toolName}
			}
			confirmed, err := s.config.ConfirmFunc(toolName, params)
			if err != nil {
				return nil, fmt.Errorf("agentguard: confirm callback: %w", err)
			}
			if !confirmed {
				return nil, &ConfirmationRejectedError{Tool: toolName}
			}
		}

		return fn(ctx, params)
	}
}

// NewSession creates a new guarded session by registering it with the server.
func (s *Shield) NewSession(ctx context.Context, userMessage string, metadata map[string]any) (*Session, error) {
	agentID := s.config.AgentID
	info, err := s.client.CreateSession(ctx, userMessage, agentID, metadata)
	if err != nil {
		return nil, fmt.Errorf("agentguard: create session: %w", err)
	}

	return &Session{
		SessionID:   info.SessionID,
		TraceID:     info.TraceID,
		client:      s.client,
		confirmFunc: s.config.ConfirmFunc,
	}, nil
}

// Sanitize forwards data to the server-side sanitization pipeline.
func (s *Shield) Sanitize(ctx context.Context, data, source, dataType string) (*SanitizedData, error) {
	return s.client.Sanitize(ctx, data, source, dataType)
}

// TwoPhaseExtract forwards data to the server-side extraction pipeline.
func (s *Shield) TwoPhaseExtract(ctx context.Context, data, schemaName string) (*ExtractedData, error) {
	return s.client.Extract(ctx, data, schemaName)
}

// MarkData forwards data to the server-side trust marker.
func (s *Shield) MarkData(ctx context.Context, data, sourceID string, clientTrustLevel *string) (*MarkedData, error) {
	return s.client.MarkData(ctx, data, sourceID, clientTrustLevel)
}
