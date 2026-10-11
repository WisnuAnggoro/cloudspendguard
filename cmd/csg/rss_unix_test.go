//go:build linux || darwin

package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/internal/report"
)

func TestRSSBytes(t *testing.T) {
	tests := []struct {
		name   string
		rss    int64
		darwin bool
		want   uint64
		ok     bool
	}{
		{"negative Linux", -1, false, 0, false},
		{"negative Darwin", -1, true, 0, false},
		{"zero", 0, false, 0, true},
		{"Linux KiB", 2048, false, 2097152, true},
		{"Darwin bytes", 2048, true, 2048, true},
		{"Linux boundary", int64(math.MaxUint64 / 1024), false, (math.MaxUint64 / 1024) * 1024, true},
		{"Linux overflow", int64(math.MaxUint64/1024) + 1, false, 0, false},
		{"Darwin maximum", math.MaxInt64, true, math.MaxInt64, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := rssBytes(tt.rss, tt.darwin)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("rssBytes(%d, %t) = (%d, %t), want (%d, %t)",
					tt.rss, tt.darwin, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestWriteReportPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "report.json")
	if err := writeReport(path, report.FormatJSON, report.Report{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(path), path} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s grants group or other permissions: %o", p, info.Mode().Perm())
		}
	}
}
