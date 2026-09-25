package verify

import (
	"context"
	"errors"
	"testing"
)

func TestNewVerifier_StubReportsNotImplemented(t *testing.T) {
	_, err := NewVerifier().Verify(context.Background(), "", "", "finding-1")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before v0.6.0-beta, got %v", err)
	}
}

// TestMaxRetriesIsBounded guards the safety property that the generate-then-verify
// loop terminates rather than retrying a hallucinating model indefinitely.
func TestMaxRetriesIsBounded(t *testing.T) {
	if MaxRetries < 1 || MaxRetries > 5 {
		t.Fatalf("MaxRetries = %d, want a small bounded value", MaxRetries)
	}
}
