// Command gensample writes the synthetic fixtures in testdata/ used by unit
// tests, `make demo`, and the Unit 4 system demonstration video.
//
// The data describes one fictional AWS account (111122223333) for September
// 2026. v0.2.0 planted four patterns: an unattached 500 GiB gp3 volume, an
// idle Elastic IP, a public S3 bucket, and an IAM policy granting "*:*".
// v0.3.0 adds a two-day GPU spike from an instance Terraform does not know
// about (19 and 20 September, the cost-anomaly target), a Lambda series with
// a weekday/weekend pattern that must NOT be flagged, an idle NAT gateway
// (hours billed, no data processed), and an oversized staging RDS instance.
//
// Usage: go run ./tools/gensample -out testdata
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
)

const account = "111122223333"

type lineItem struct {
	service, resource, usage, region string
	dailyCost                        float64
	tags                             map[string]string
	weekendCost                      float64 // when > 0, used on Saturdays and Sundays
	onlyDays                         []int   // when set, the item bills only on these day offsets
}

var items = []lineItem{
	{"AmazonEC2", "i-0a1b2c3d4e5f60001", "EUW1-BoxUsage:m5.large", "eu-west-1", 2.304, map[string]string{"team": "booking", "env": "prod"}, 0, nil},
	{"AmazonEC2", "vol-0a1b2c3d4e5f60002", "EUW1-EBS:VolumeUsage.gp3", "eu-west-1", 0.2667, map[string]string{"team": "booking", "env": "prod"}, 0, nil},
	{"AmazonEC2", "vol-0a1b2c3d4e5f60099", "EUW1-EBS:VolumeUsage.gp3", "eu-west-1", 1.3333, map[string]string{"team": "data", "env": "staging"}, 0, nil},
	{"AmazonEC2", "eipalloc-0a1b2c3d4e5f60010", "EUW1-PublicIPv4:InUseAddress", "eu-west-1", 0.12, map[string]string{"team": "booking"}, 0, nil},
	{"AmazonEC2", "eipalloc-0a1b2c3d4e5f60077", "EUW1-PublicIPv4:IdleAddress", "eu-west-1", 0.12, map[string]string{"team": "legacy"}, 0, nil},
	{"AmazonEC2", "nat-0a1b2c3d4e5f60020", "EUW1-NatGateway-Hours", "eu-west-1", 1.08, map[string]string{"team": "platform"}, 0, nil},
	{"AmazonRDS", "arn:aws:rds:eu-west-1:111122223333:db:bookings", "EUW1-InstanceUsage:db.t3.medium", "eu-west-1", 1.632, map[string]string{"team": "booking", "env": "prod"}, 0, nil},
	{"AmazonS3", "tui-demo-booking-exports", "EUW1-TimedStorage-ByteHrs", "eu-west-1", 0.35, map[string]string{"team": "data"}, 0, nil},
	{"AmazonS3", "tui-demo-access-logs", "EUW1-TimedStorage-ByteHrs", "eu-west-1", 0.12, map[string]string{"team": "platform"}, 0, nil},
	{"AWSCloudTrail", "", "EUW1-PaidEventsRecorded", "eu-west-1", 0.05, nil, 0, nil},
	{"AmazonRDS", "arn:aws:rds:eu-west-1:111122223333:db:analytics-staging", "EUW1-Multi-AZUsage:db.r5.2xlarge", "eu-west-1", 23.04, map[string]string{"team": "data", "env": "staging"}, 0, nil},
	{"AWSLambda", "arn:aws:lambda:eu-west-1:111122223333:function:booking-pricing", "EUW1-Lambda-GB-Second", "eu-west-1", 4.20, map[string]string{"team": "booking", "env": "prod"}, 1.40, nil},
	{"AmazonEC2", "i-0a1b2c3d4e5f60042", "EUW1-BoxUsage:m4.xlarge", "eu-west-1", 5.328, map[string]string{"team": "reporting", "env": "staging"}, 0, nil},
	// Crypto-mining style spike: an unknown GPU instance, 18 and 19 days after the 1st.
	{"AmazonEC2", "i-0a1b2c3d4e5f60666", "EUW1-BoxUsage:p3.2xlarge", "eu-west-1", 73.44, map[string]string{"team": "booking"}, 0, []int{18, 19}},
}

func main() {
	out := flag.String("out", "testdata", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	rows := curRows()
	must(writeParquet(filepath.Join(*out, "sample-cur.parquet"), rows))
	must(writeLegacyCSV(filepath.Join(*out, "sample-cur.csv"), rows))
	fmt.Printf("wrote %d CUR line items to %s\n", len(rows), *out)
}

func curRows() []cur.ParquetRow {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	var rows []cur.ParquetRow
	for day := 0; day < 30; day++ {
		s := start.AddDate(0, 0, day)
		for _, it := range items {
			if len(it.onlyDays) > 0 && !containsDay(it.onlyDays, day) {
				continue
			}
			cost := it.dailyCost
			if wd := s.Weekday(); it.weekendCost > 0 && (wd == time.Saturday || wd == time.Sunday) {
				cost = it.weekendCost
			}
			rows = append(rows, cur.ParquetRow{
				UsageAccountID: account,
				ProductCode:    it.service,
				ResourceID:     it.resource,
				UsageType:      it.usage,
				RegionCode:     it.region,
				UnblendedCost:  cost,
				UsageStart:     s,
				UsageEnd:       s.Add(24 * time.Hour),
				ResourceTags:   cur2Tags(it.tags),
			})
		}
	}
	return rows
}

func writeParquet(path string, rows []cur.ParquetRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[cur.ParquetRow](f)
	if _, err := w.Write(rows); err != nil {
		f.Close()
		return err
	}
	if err := w.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeLegacyCSV uses CUR 1.0 headers so tests cover both naming schemes.
func writeLegacyCSV(path string, rows []cur.ParquetRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"lineItem/UsageAccountId", "lineItem/ProductCode", "lineItem/ResourceId", "lineItem/UsageType", "product/region", "lineItem/UnblendedCost", "lineItem/UsageStartDate", "lineItem/UsageEndDate", "resourceTags/user:team", "resourceTags/user:env"})
	for _, r := range rows {
		_ = w.Write([]string{r.UsageAccountID, r.ProductCode, r.ResourceID, r.UsageType, r.RegionCode,
			strconv.FormatFloat(r.UnblendedCost, 'f', -1, 64),
			r.UsageStart.Format(time.RFC3339), r.UsageEnd.Format(time.RFC3339),
			r.ResourceTags["user_team"], r.ResourceTags["user_env"]})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// cur2Tags renders tags the way CUR 2.0 names user-defined tag keys.
func cur2Tags(tags map[string]string) map[string]string {
	if tags == nil {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		out["user_"+k] = v
	}
	return out
}

func containsDay(days []int, d int) bool {
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}
