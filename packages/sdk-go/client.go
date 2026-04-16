package agentshield

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const sdkVersion = "0.1.0"

// Client is the HTTP client for the AgentShield core API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	maxRetries int
}

// NewClient creates a Client from the given Config.
func NewClient(cfg Config) *Client {
	timeout := cfg.TimeoutMs
	if timeout <= 0 {
		timeout = 10000
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8000"
	}

	return &Client{
		baseURL: baseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Millisecond,
		},
		maxRetries: maxRetries,
	}
}

func (c *Client) doPost(ctx context.Context, path string, body any, result any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("agentshield: marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("agentshield: create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "agentshield-go/"+sdkVersion)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue // retry on transport errors
		}

		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("agentshield: read response: %w", err)
			continue
		}

		if resp.StatusCode >= 400 {
			return fmt.Errorf("agentshield: HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("agentshield: unmarshal response: %w", err)
		}
		return nil
	}
	return fmt.Errorf("agentshield: request failed after %d retries: %w", c.maxRetries, lastErr)
}

// checkRequest matches the server's CheckRequest schema.
type checkRequest struct {
	SessionID        string         `json:"session_id"`
	ToolName         string         `json:"tool_name"`
	Params           map[string]any `json:"params"`
	SDKVersion       string         `json:"sdk_version"`
	SourceID         string         `json:"source_id"`
	ClientTrustLevel *string        `json:"client_trust_level,omitempty"`
}

// CheckToolCall sends a tool call check to the server.
func (c *Client) CheckToolCall(ctx context.Context, sessionID, toolName string, params map[string]any, sourceID string, clientTrustLevel *string) (*CheckResult, error) {
	req := checkRequest{
		SessionID:        sessionID,
		ToolName:         toolName,
		Params:           params,
		SDKVersion:       sdkVersion,
		SourceID:         sourceID,
		ClientTrustLevel: clientTrustLevel,
	}
	var result CheckResult
	if err := c.doPost(ctx, "/api/v1/check", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type sanitizeRequest struct {
	Data     string `json:"data"`
	Source   string `json:"source"`
	DataType string `json:"data_type"`
}

// Sanitize sends data to the server-side sanitization pipeline.
func (c *Client) Sanitize(ctx context.Context, data, source, dataType string) (*SanitizedData, error) {
	if dataType == "" {
		dataType = "auto"
	}
	req := sanitizeRequest{Data: data, Source: source, DataType: dataType}
	var result SanitizedData
	if err := c.doPost(ctx, "/api/v1/sanitize", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type extractRequest struct {
	Data       string `json:"data"`
	SchemaName string `json:"schema_name"`
}

// Extract sends data to the server-side two-phase extraction pipeline.
func (c *Client) Extract(ctx context.Context, data, schemaName string) (*ExtractedData, error) {
	req := extractRequest{Data: data, SchemaName: schemaName}
	var result ExtractedData
	if err := c.doPost(ctx, "/api/v1/extract", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type createSessionRequest struct {
	UserMessage string         `json:"user_message"`
	AgentID     string         `json:"agent_id"`
	Metadata    map[string]any `json:"metadata"`
}

// CreateSession registers a new guarded session with the server.
func (c *Client) CreateSession(ctx context.Context, userMessage, agentID string, metadata map[string]any) (*SessionInfo, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	req := createSessionRequest{
		UserMessage: userMessage,
		AgentID:     agentID,
		Metadata:    metadata,
	}
	var result SessionInfo
	if err := c.doPost(ctx, "/api/v1/sessions", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type markRequest struct {
	Data             string  `json:"data"`
	SourceID         string  `json:"source_id"`
	ClientTrustLevel *string `json:"client_trust_level,omitempty"`
}

// MarkData annotates data with trust metadata via the server.
func (c *Client) MarkData(ctx context.Context, data, sourceID string, clientTrustLevel *string) (*MarkedData, error) {
	req := markRequest{Data: data, SourceID: sourceID, ClientTrustLevel: clientTrustLevel}
	var result MarkedData
	if err := c.doPost(ctx, "/api/v1/mark", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
