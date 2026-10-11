// Command benchgen writes a synthetic CUR export of a chosen size, for the
// Unit 6 performance measurements (NFR1). Rows are deterministic: the same
// -rows and -seed always produce the same file.
//
// Each resource bills once per day for 90 days with a weekday and weekend
// pattern, so the anomaly detector has realistic series to decompose.
//
// Usage: go run ./tools/benchgen -rows 1000000 -out tmp/bench-1m
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
)

const days = 90

var services = []struct{ code, usage string }{
	{"AmazonEC2", "EUW1-BoxUsage:m5.large"}, {"AmazonRDS", "EUW1-InstanceUsage:db.t3.medium"},
	{"AmazonS3", "EUW1-TimedStorage-ByteHrs"}, {"AWSLambda", "EUW1-Lambda-GB-Second"},
	{"AmazonEC2", "EUW1-EBS:VolumeUsage.gp3"}, {"AmazonCloudWatch", "EUW1-DataProcessing-Bytes"},
}

func main() {
	rows := flag.Int("rows", 100000, "number of CUR line items")
	out := flag.String("out", "tmp/bench", "output directory")
	format := flag.String("format", "parquet", "parquet or csv")
	seed := flag.Int64("seed", 1, "random seed")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	resources := (*rows + days - 1) / days
	rng := rand.New(rand.NewSource(*seed))
	base := make([]float64, resources)
	for i := range base {
		base[i] = 0.05 + rng.ExpFloat64()*2
	}
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	gen := func(i int) cur.ParquetRow {
		res, day := i%resources, i/resources
		s := start.AddDate(0, 0, day)
		svc := services[res%len(services)]
		c := base[res] * (1 + 0.25*math.Sin(2*math.Pi*float64(day)/7))
		if wd := s.Weekday(); wd == time.Saturday || wd == time.Sunday {
			c *= 0.6
		}
		c += rng.NormFloat64() * base[res] * 0.03
		if c < 0 {
			c = 0
		}
		return cur.ParquetRow{
			UsageAccountID: "111122223333", ProductCode: svc.code,
			ResourceID: fmt.Sprintf("res-%07d", res), UsageType: svc.usage, RegionCode: "eu-west-1",
			UnblendedCost: math.Round(c*10000) / 10000, UsageStart: s, UsageEnd: s.Add(24 * time.Hour),
			ResourceTags: map[string]string{"user_team": fmt.Sprintf("team-%d", res%25), "user_env": []string{"prod", "staging", "dev"}[res%3]},
		}
	}

	var err error
	switch *format {
	case "parquet":
		err = writeParquet(filepath.Join(*out, "bench-cur.parquet"), *rows, gen)
	case "csv":
		err = writeCSV(filepath.Join(*out, "bench-cur.csv"), *rows, gen)
	default:
		err = fmt.Errorf("unknown format %q", *format)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d CUR line items (%d resources x %d days) to %s\n", *rows, resources, days, *out)
}

func writeParquet(path string, n int, gen func(int) cur.ParquetRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[cur.ParquetRow](f)
	buf := make([]cur.ParquetRow, 0, 50000)
	for i := 0; i < n; i++ {
		buf = append(buf, gen(i))
		if len(buf) == cap(buf) || i == n-1 {
			if _, err := w.Write(buf); err != nil {
				f.Close()
				return err
			}
			buf = buf[:0]
		}
	}
	if err := w.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeCSV(path string, n int, gen func(int) cur.ParquetRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"line_item_usage_account_id", "line_item_product_code", "line_item_resource_id", "line_item_usage_type", "product_region_code", "line_item_unblended_cost", "line_item_usage_start_date", "line_item_usage_end_date", "resource_tags_user_team", "resource_tags_user_env"})
	for i := 0; i < n; i++ {
		r := gen(i)
		_ = w.Write([]string{r.UsageAccountID, r.ProductCode, r.ResourceID, r.UsageType, r.RegionCode,
			strconv.FormatFloat(r.UnblendedCost, 'f', -1, 64), r.UsageStart.Format(time.RFC3339), r.UsageEnd.Format(time.RFC3339),
			r.ResourceTags["user_team"], r.ResourceTags["user_env"]})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
