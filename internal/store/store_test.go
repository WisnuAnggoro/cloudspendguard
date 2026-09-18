package store

import (
	"context"
	"errors"
	"testing"
)

func TestOpen_StubReportsNotImplemented(t *testing.T) {
	_, err := Open(context.Background(), "testdata/local.duckdb")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before Week 3, got %v", err)
	}
}
