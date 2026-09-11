package report

import (
	"errors"
	"io"
	"testing"
)

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewRenderer("yaml"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestRender_StubReportsNotImplemented(t *testing.T) {
	r, err := NewRenderer(FormatMarkdown)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	if err := r.Render(io.Discard, nil); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented before Week 6, got %v", err)
	}
}
