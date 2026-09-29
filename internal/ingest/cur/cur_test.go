package cur

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixtures = "../../../testdata"

func TestRead_ParquetAndLegacyCSVAgree(t *testing.T) {
	ctx := context.Background()
	pq, err := NewReader().Read(ctx, filepath.Join(fixtures, "sample-cur.parquet"))
	if err != nil {
		t.Fatalf("parquet: %v", err)
	}
	csv, err := NewReader().Read(ctx, filepath.Join(fixtures, "sample-cur.csv"))
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(pq) != 300 || len(csv) != 300 {
		t.Fatalf("want 300 records each, got parquet=%d csv=%d", len(pq), len(csv))
	}
	for i := range pq {
		a, b := pq[i], csv[i]
		if a.Service != b.Service || a.ResourceID != b.ResourceID || a.UsageType != b.UsageType ||
			a.Region != b.Region || a.UsageAccountID != b.UsageAccountID ||
			math.Abs(a.UnblendedCost-b.UnblendedCost) > 1e-9 ||
			!a.UsageStartDate.Equal(b.UsageStartDate) || !a.UsageEndDate.Equal(b.UsageEndDate) {
			t.Fatalf("record %d differs:\nparquet %+v\ncsv     %+v", i, a, b)
		}
		if a.Tags["team"] != b.Tags["team"] || a.Tags["env"] != b.Tags["env"] {
			t.Fatalf("record %d tag mismatch: %v vs %v", i, a.Tags, b.Tags)
		}
	}
}

func TestRead_ParquetGolden(t *testing.T) {
	recs, err := NewReader().Read(context.Background(), filepath.Join(fixtures, "sample-cur.parquet"))
	if err != nil {
		t.Fatal(err)
	}
	first := recs[0]
	want := Record{
		UsageAccountID: "111122223333", Service: "AmazonEC2", ResourceID: "i-0a1b2c3d4e5f60001",
		UsageType: "EUW1-BoxUsage:m5.large", Region: "eu-west-1", UnblendedCost: 2.304,
		UsageStartDate: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		UsageEndDate:   time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
	}
	if first.UsageAccountID != want.UsageAccountID || first.Service != want.Service || first.ResourceID != want.ResourceID ||
		first.UsageType != want.UsageType || first.Region != want.Region || first.UnblendedCost != want.UnblendedCost ||
		!first.UsageStartDate.Equal(want.UsageStartDate) || !first.UsageEndDate.Equal(want.UsageEndDate) {
		t.Fatalf("first record = %+v, want %+v", first, want)
	}
	if first.Tags["team"] != "booking" || first.Tags["env"] != "prod" {
		t.Fatalf("tags = %v", first.Tags)
	}
	var total float64
	for _, r := range recs {
		total += r.UnblendedCost
	}
	if math.Abs(total-221.28) > 0.01 {
		t.Fatalf("total cost = %.4f, want 221.28", total)
	}
}

func TestRead_Directory(t *testing.T) {
	dir := t.TempDir()
	copyFile(t, filepath.Join(fixtures, "sample-cur.csv"), filepath.Join(dir, "a", "part-0.csv"))
	copyFile(t, filepath.Join(fixtures, "sample-cur.parquet"), filepath.Join(dir, "b", "part-1.parquet"))
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := NewReader().Read(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 600 {
		t.Fatalf("want 600 records from directory, got %d", len(recs))
	}
}

func TestRead_Errors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]struct {
		path    string
		wantErr error
	}{
		"missing file":    {path: filepath.Join(dir, "nope.csv")},
		"unsupported":     {path: write("x.xlsx", "x"), wantErr: ErrUnsupportedFormat},
		"no cost column":  {path: write("nocost.csv", "line_item_product_code\nAmazonEC2\n")},
		"bad cost":        {path: write("badcost.csv", "line_item_unblended_cost\nabc\n")},
		"bad timestamp":   {path: write("badts.csv", "line_item_unblended_cost,line_item_usage_start_date\n1,yesterday\n")},
		"corrupt parquet": {path: write("bad.parquet", "not parquet")},
		"empty csv":       {path: write("empty.csv", "")},
		"bad gzip":        {path: write("bad.csv.gz", "not gzip")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewReader().Read(context.Background(), tc.path)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestRead_CUR2CSVWithDateOnlyAndGzip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cur2.csv")
	body := "line_item_usage_account_id,line_item_product_code,line_item_resource_id,line_item_usage_type,product_region_code,line_item_unblended_cost,line_item_usage_start_date,line_item_usage_end_date\n" +
		"111122223333,AmazonS3,bucket-a,TimedStorage-ByteHrs,eu-west-1,0.5,2026-09-01,2026-09-02\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := NewReader().Read(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Service != "AmazonS3" || recs[0].UnblendedCost != 0.5 || recs[0].UsageStartDate.Day() != 1 {
		t.Fatalf("unexpected records: %+v", recs)
	}
	if recs[0].ServiceOrUnknown() != "AmazonS3" || (Record{}).ServiceOrUnknown() != "Unknown" {
		t.Fatal("ServiceOrUnknown")
	}
}

func TestRead_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewReader().Read(ctx, filepath.Join(fixtures, "sample-cur.csv")); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
