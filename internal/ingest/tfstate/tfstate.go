// Package tfstate parses terraform.tfstate JSON (and, later, HCL source) to
// recover the declared configuration of AWS resources for the security
// analyzers in internal/analyze/security.
//
// Scaffolded in Unit 2 (Week 2). The state-file parser and golden-file tests
// land in Unit 3 (Week 3), tagged v0.1.0-ingest.
package tfstate

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by stubs until the Week 3 implementation lands.
var ErrNotImplemented = errors.New("tfstate: not implemented until Week 3 (v0.1.0-ingest)")

// Resource is a normalized resource declaration extracted from Terraform
// state or configuration.
type Resource struct {
	Address    string // Terraform resource address, e.g. "aws_s3_bucket.data"
	Type       string // e.g. "aws_s3_bucket", "aws_security_group"
	Name       string
	Provider   string
	Attributes map[string]any
}

// Parser parses a terraform.tfstate file (or a directory of *.tf files, in a
// later iteration) into normalized Resource values.
type Parser interface {
	Parse(ctx context.Context, path string) ([]Resource, error)
}

// NewParser returns the default Parser. It currently returns a stub that
// reports ErrNotImplemented.
func NewParser() Parser { return stubParser{} }

type stubParser struct{}

func (stubParser) Parse(_ context.Context, _ string) ([]Resource, error) {
	return nil, ErrNotImplemented
}
