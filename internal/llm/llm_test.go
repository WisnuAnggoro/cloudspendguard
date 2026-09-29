package llm

import (
	"context"
	"errors"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

func TestGenerateAndVerify_StubReportsNotImplemented(t *testing.T) {
	engine := New(Config{Provider: ProviderOllama, Model: "llama3.1:8b"})
	_, err := engine.GenerateAndVerify(context.Background(), models.Finding{ID: "f1"})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before Week 5, got %v", err)
	}
}
