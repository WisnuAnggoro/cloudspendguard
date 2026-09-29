package cur

import (
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// columnAliases maps each normalized field to the header names used by
// CUR 2.0 (snake_case) and legacy CUR 1.0 (category/Name) exports.
var columnAliases = map[string][]string{
	"account":  {"line_item_usage_account_id", "lineitem/usageaccountid"},
	"service":  {"line_item_product_code", "lineitem/productcode"},
	"resource": {"line_item_resource_id", "lineitem/resourceid"},
	"usage":    {"line_item_usage_type", "lineitem/usagetype"},
	"region":   {"product_region_code", "product/regioncode", "product_region", "product/region"},
	"cost":     {"line_item_unblended_cost", "lineitem/unblendedcost"},
	"start":    {"line_item_usage_start_date", "lineitem/usagestartdate"},
	"end":      {"line_item_usage_end_date", "lineitem/usageenddate"},
}

func readCSV(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var src io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		src = gz
	}

	r := csv.NewReader(src)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	idx := map[string]int{}
	tagCols := map[int]string{}
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		for field, aliases := range columnAliases {
			for _, a := range aliases {
				if key == a {
					idx[field] = i
				}
			}
		}
		// Legacy CUR exposes one column per tag: resourceTags/user:Team.
		if strings.HasPrefix(key, "resourcetags/") {
			tagCols[i] = strings.TrimSpace(h)[len("resourceTags/"):]
		}
	}
	if _, ok := idx["cost"]; !ok {
		return nil, errors.New("missing unblended cost column")
	}

	get := func(row []string, field string) string {
		i, ok := idx[field]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	var out []Record
	line := 1
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		cost, err := strconv.ParseFloat(get(row, "cost"), 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: parse cost: %w", line, err)
		}
		start, err := parseTime(get(row, "start"))
		if err != nil {
			return nil, fmt.Errorf("line %d: parse usage start: %w", line, err)
		}
		end, err := parseTime(get(row, "end"))
		if err != nil {
			return nil, fmt.Errorf("line %d: parse usage end: %w", line, err)
		}
		var tags map[string]string
		for i, name := range tagCols {
			if i < len(row) && row[i] != "" {
				if tags == nil {
					tags = map[string]string{}
				}
				tags[name] = row[i]
			}
		}
		tags = normalizeTags(tags)
		out = append(out, Record{
			UsageAccountID: get(row, "account"),
			Service:        get(row, "service"),
			ResourceID:     get(row, "resource"),
			UsageType:      get(row, "usage"),
			Region:         get(row, "region"),
			Tags:           tags,
			UnblendedCost:  cost,
			UsageStartDate: start,
			UsageEndDate:   end,
		})
	}
}

var timeLayouts = []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02"}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
}
