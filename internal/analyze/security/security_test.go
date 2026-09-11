package security

import (
	"context"
	"errors"
	"testing"
)

func TestAnalyze_StubReportsNotImplementedUntilDetectorsRegistered(t *testing.T) {
	_, err := Analyze(context.Background(), nil, nil)
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before Week 4, got %v", err)
	}
}
