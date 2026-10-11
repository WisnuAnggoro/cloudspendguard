package sample

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedCopiesMatchTestdata stops the embedded sample from drifting
// away from the fixtures the other tests use.
func TestEmbeddedCopiesMatchTestdata(t *testing.T) {
	for _, name := range Files {
		want, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Read(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs from testdata/%s; run `make sample-data`", name, name)
		}
	}
}

func TestWriteTo(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range Files {
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.Size() == 0 {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	if err := WriteTo(filepath.Join(dir, "missing")); err == nil {
		t.Error("expected an error for a missing directory")
	}
}
