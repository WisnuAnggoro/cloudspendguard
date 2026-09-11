package cloudtrail

import (
	"context"
	"errors"
	"testing"
)

func TestNewReader_StubReportsNotImplemented(t *testing.T) {
	_, err := NewReader().Read(context.Background(), "testdata/sample-events.json")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before Week 3, got %v", err)
	}
}
