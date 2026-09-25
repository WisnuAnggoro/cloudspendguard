package live

import (
	"context"
	"errors"
	"testing"
)

func TestNewCollector_StubReportsNotImplemented(t *testing.T) {
	_, err := NewCollector().Collect(context.Background(), Options{RoleARN: "arn:aws:iam::000000000000:role/csg-readonly"})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before v0.1.0-ingest, got %v", err)
	}
}
