package agentshield

import (
	"testing"
)

func TestNew(t *testing.T) {
	shield, err := New(Config{
		APIKey:  "test-key",
		BaseURL: "http://localhost:8000",
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if shield == nil {
		t.Fatal("Shield should not be nil")
	}
}

func TestNewRequiresAPIKey(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("Expected error for missing API key")
	}
}

func TestDecisionValues(t *testing.T) {
	if Allow != "ALLOW" {
		t.Errorf("Allow = %s, want ALLOW", Allow)
	}
	if Block != "BLOCK" {
		t.Errorf("Block = %s, want BLOCK", Block)
	}
	if RequireConfirmation != "REQUIRE_CONFIRMATION" {
		t.Errorf("RequireConfirmation = %s, want REQUIRE_CONFIRMATION", RequireConfirmation)
	}
}
