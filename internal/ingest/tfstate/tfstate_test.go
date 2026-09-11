package tfstate

import (
	"context"
	"errors"
	"testing"
)

func TestNewParser_StubReportsNotImplemented(t *testing.T) {
	_, err := NewParser().Parse(context.Background(), "testdata/terraform.tfstate")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before Week 3, got %v", err)
	}
}
