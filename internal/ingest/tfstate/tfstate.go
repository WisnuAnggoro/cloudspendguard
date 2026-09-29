// Package tfstate parses terraform.tfstate JSON to recover the declared
// configuration of AWS resources for the analyzers in internal/analyze.
//
// Module M3 in docs/architecture.md. The state-file parser is implemented in
// Unit 4 (Week 4), carrying over the Week 3 ingest milestone. HCL source
// parsing (*.tf) follows in Unit 5 alongside the patch verifier, which needs
// the same abstract syntax tree walk.
package tfstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// ErrHCLNotYetSupported is returned when a directory of *.tf files is passed.
var ErrHCLNotYetSupported = errors.New("tfstate: HCL parsing lands in Unit 5; pass a terraform.tfstate file")

// Resource is a normalized resource declaration extracted from Terraform
// state or configuration.
type Resource struct {
	Address    string // Terraform resource address, e.g. "aws_s3_bucket.data"
	Type       string // e.g. "aws_s3_bucket", "aws_security_group"
	Name       string
	Provider   string
	Attributes map[string]any
}

// Attr returns attribute key as a string, or "" if absent or not a string.
func (r Resource) Attr(key string) string {
	s, _ := r.Attributes[key].(string)
	return s
}

// Bool returns attribute key as a bool; ok is false if absent or not a bool.
func (r Resource) Bool(key string) (value, ok bool) {
	value, ok = r.Attributes[key].(bool)
	return value, ok
}

// Parser parses a terraform.tfstate file into normalized Resource values.
type Parser interface {
	Parse(ctx context.Context, path string) ([]Resource, error)
}

// NewParser returns the default state-file Parser.
func NewParser() Parser { return stateParser{} }

type stateParser struct{}

// state is the subset of the Terraform state v4 format we rely on.
// https://developer.hashicorp.com/terraform/language/state
type state struct {
	Version   int `json:"version"`
	Resources []struct {
		Module    string `json:"module"`
		Mode      string `json:"mode"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Provider  string `json:"provider"`
		Instances []struct {
			IndexKey   any            `json:"index_key"`
			Attributes map[string]any `json:"attributes"`
		} `json:"instances"`
	} `json:"resources"`
}

func (stateParser) Parse(ctx context.Context, path string) ([]Resource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("tfstate: %w", err)
	}
	if info.IsDir() {
		return nil, ErrHCLNotYetSupported
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tfstate: %w", err)
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("tfstate: %s: %w", path, err)
	}
	if st.Version != 4 {
		return nil, fmt.Errorf("tfstate: %s: unsupported state version %d (want 4)", path, st.Version)
	}
	var out []Resource
	for _, r := range st.Resources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.Mode != "managed" {
			continue // data sources describe lookups, not owned infrastructure
		}
		base := r.Type + "." + r.Name
		if r.Module != "" {
			base = r.Module + "." + base
		}
		for _, inst := range r.Instances {
			addr := base
			switch k := inst.IndexKey.(type) {
			case string:
				addr = fmt.Sprintf("%s[%q]", base, k)
			case float64:
				addr = fmt.Sprintf("%s[%d]", base, int(k))
			}
			out = append(out, Resource{
				Address:    addr,
				Type:       r.Type,
				Name:       r.Name,
				Provider:   r.Provider,
				Attributes: inst.Attributes,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}
