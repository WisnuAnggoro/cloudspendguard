// Package cur reads AWS Cost and Usage Report (CUR) exports (Parquet or CSV)
// and normalizes each line item into a [Record] the local store can ingest.
//
// Module M1 in docs/architecture.md. Implemented in Unit 4 (Week 4), carrying
// over the Week 3 ingest milestone (v0.1.0-ingest).
//
// Both the CUR 2.0 snake_case column names (line_item_unblended_cost) and the
// legacy CUR 1.0 slash-separated names (lineItem/UnblendedCost) are accepted,
// so the same reader handles fresh Data Exports and older CSV archives.
package cur

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrUnsupportedFormat is returned for files that are neither Parquet nor CSV.
var ErrUnsupportedFormat = errors.New("cur: unsupported file format (want .parquet, .csv, or .csv.gz)")

// Record is a normalized CUR line item, independent of the Parquet/CSV
// source format, ready for insertion into the local store.
type Record struct {
	UsageAccountID string
	Service        string // line_item_product_code, e.g. "AmazonEC2", "AmazonS3"
	ResourceID     string
	UsageType      string // e.g. "EBS:VolumeUsage.gp3", "PublicIPv4:IdleAddress"
	Region         string
	Tags           map[string]string
	UnblendedCost  float64
	UsageStartDate time.Time
	UsageEndDate   time.Time
}

// Reader reads a CUR export from path and returns normalized records.
// path may be a single file or a directory; directories are walked
// recursively for .parquet, .csv, and .csv.gz files.
type Reader interface {
	Read(ctx context.Context, path string) ([]Record, error)
}

// NewReader returns the default Reader, which dispatches on file extension.
func NewReader() Reader { return fileReader{} }

type fileReader struct{}

func (fileReader) Read(ctx context.Context, path string) ([]Record, error) {
	files, err := collectFiles(path)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var recs []Record
		switch {
		case strings.HasSuffix(strings.ToLower(f), ".parquet"):
			recs, err = readParquet(f)
		case strings.HasSuffix(strings.ToLower(f), ".csv"), strings.HasSuffix(strings.ToLower(f), ".csv.gz"):
			recs, err = readCSV(f)
		default:
			err = fmt.Errorf("%w: %s", ErrUnsupportedFormat, f)
		}
		if err != nil {
			return nil, fmt.Errorf("cur: %s: %w", f, err)
		}
		out = append(out, recs...)
	}
	return out, nil
}

func collectFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cur: %w", err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		lower := strings.ToLower(p)
		if !d.IsDir() && (strings.HasSuffix(lower, ".parquet") || strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".csv.gz")) {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

// ServiceOrUnknown returns r.Service, or "Unknown" when the export left it empty.
func (r Record) ServiceOrUnknown() string {
	if r.Service == "" {
		return "Unknown"
	}
	return r.Service
}
