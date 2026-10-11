// Package sample embeds the synthetic sample account so `csg run --sample`
// works from a single static binary with no files and no AWS credentials
// (NFR5: useful output within five minutes of installation).
//
// The three files are copies of testdata/sample-cur.csv,
// testdata/sample-events.json, and testdata/terraform.tfstate. A test fails
// when the copies drift from the originals; regenerate both with
// `make sample-data`.
package sample

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed data/*
var files embed.FS

// Files lists the embedded file names.
var Files = []string{"sample-cur.csv", "sample-events.json", "terraform.tfstate"}

// WriteTo extracts the sample account into dir, which must exist.
func WriteTo(dir string) error {
	for _, name := range Files {
		b, err := files.ReadFile("data/" + name)
		if err != nil {
			return fmt.Errorf("sample: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return fmt.Errorf("sample: %w", err)
		}
	}
	return nil
}

// Read returns one embedded file.
func Read(name string) ([]byte, error) { return files.ReadFile("data/" + name) }
