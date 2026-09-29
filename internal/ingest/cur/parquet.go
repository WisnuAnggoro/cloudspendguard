package cur

import (
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/parquet-go/parquet-go"
)

// ParquetRow mirrors the subset of CUR 2.0 columns CloudSpendGuard needs.
// Columns missing from a file are left at their zero value. It is exported so
// tools/gensample can write fixtures with exactly the schema the reader expects.
type ParquetRow struct {
	UsageAccountID string            `parquet:"line_item_usage_account_id,optional"`
	ProductCode    string            `parquet:"line_item_product_code,optional"`
	ResourceID     string            `parquet:"line_item_resource_id,optional"`
	UsageType      string            `parquet:"line_item_usage_type,optional"`
	RegionCode     string            `parquet:"product_region_code,optional"`
	UnblendedCost  float64           `parquet:"line_item_unblended_cost,optional"`
	UsageStart     time.Time         `parquet:"line_item_usage_start_date,optional,timestamp(millisecond)"`
	UsageEnd       time.Time         `parquet:"line_item_usage_end_date,optional,timestamp(millisecond)"`
	ResourceTags   map[string]string `parquet:"resource_tags,optional"`
}

func readParquet(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// OpenFile validates the footer and returns an error for corrupt input,
	// whereas NewGenericReader panics on it.
	pf, err := parquet.OpenFile(f, info.Size())
	if err != nil {
		return nil, err
	}
	reader := parquet.NewGenericReader[ParquetRow](pf)
	defer reader.Close()

	var out []Record
	for {
		// A fresh buffer per batch: the reader reuses map values inside the
		// slice it is given, so recycling buf would alias tags across rows.
		buf := make([]ParquetRow, 256)
		n, err := reader.Read(buf)
		for _, row := range buf[:n] {
			out = append(out, Record{
				UsageAccountID: row.UsageAccountID,
				Service:        row.ProductCode,
				ResourceID:     row.ResourceID,
				UsageType:      row.UsageType,
				Region:         row.RegionCode,
				Tags:           normalizeTags(row.ResourceTags),
				UnblendedCost:  row.UnblendedCost,
				UsageStartDate: row.UsageStart.UTC(),
				UsageEndDate:   row.UsageEnd.UTC(),
			})
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// normalizeTags strips the "user:" (CUR 1.0) or "user_" (CUR 2.0) prefix
// from user-defined cost allocation tags, so both formats yield {"team": ...}.
// AWS-generated tags such as "aws:createdBy" are kept as they are.
func normalizeTags(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch {
		case strings.HasPrefix(k, "user:"):
			k = k[len("user:"):]
		case strings.HasPrefix(k, "user_"):
			k = k[len("user_"):]
		}
		out[k] = v
	}
	return out
}
