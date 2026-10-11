package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

func open(t *testing.T) Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "nested", "csg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRoundTripAndIdempotentIngest(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	recs := []cur.Record{
		{UsageAccountID: "1", Service: "AmazonEC2", ResourceID: "vol-1", UsageType: "EBS", Region: "eu-west-1", UnblendedCost: 1.5, UsageStartDate: start, UsageEndDate: start.Add(24 * time.Hour), Tags: map[string]string{"team": "a"}},
		{UsageAccountID: "1", Service: "AmazonS3", ResourceID: "b", UnblendedCost: 0.25, UsageStartDate: start, UsageEndDate: start.Add(24 * time.Hour)},
	}
	n, err := s.InsertCURRecords(ctx, recs)
	if err != nil || n != 2 {
		t.Fatalf("first insert: n=%d err=%v", n, err)
	}
	if n, _ = s.InsertCURRecords(ctx, recs); n != 0 {
		t.Fatalf("re-ingest should be a no-op, wrote %d", n)
	}
	got, err := s.LoadCURRecords(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("load: %v, %d", err, len(got))
	}
	if got[0].Tags["team"] != "a" && got[1].Tags["team"] != "a" {
		t.Fatalf("tags lost: %+v", got)
	}
	if !got[0].UsageStartDate.Equal(start) {
		t.Fatalf("time lost: %v", got[0].UsageStartDate)
	}

	evs := []cloudtrail.Event{{EventID: "e1", EventName: "PutBucketAcl", EventTime: start, Raw: map[string]any{"eventID": "e1", "requestParameters": map[string]any{"bucketName": "b"}}}}
	if n, err := s.InsertCloudTrailEvents(ctx, evs); err != nil || n != 1 {
		t.Fatalf("events: %d %v", n, err)
	}
	if n, _ := s.InsertCloudTrailEvents(ctx, evs); n != 0 {
		t.Fatal("duplicate event IDs must be ignored")
	}
	gotEv, err := s.LoadCloudTrailEvents(ctx)
	if err != nil || len(gotEv) != 1 || gotEv[0].RequestParameters()["bucketName"] != "b" || !gotEv[0].EventTime.Equal(start) {
		t.Fatalf("events load: %v %+v", err, gotEv)
	}

	res := []tfstate.Resource{{Address: "aws_eip.a", Type: "aws_eip", Name: "a", Attributes: map[string]any{"id": "eip-1"}}}
	if _, err := s.InsertTerraformResources(ctx, res); err != nil {
		t.Fatal(err)
	}
	res[0].Attributes["id"] = "eip-2"
	if _, err := s.InsertTerraformResources(ctx, res); err != nil {
		t.Fatal(err)
	}
	gotRes, err := s.LoadTerraformResources(ctx)
	if err != nil || len(gotRes) != 1 || gotRes[0].Attr("id") != "eip-2" {
		t.Fatalf("tf resources should be replaced by address: %v %+v", err, gotRes)
	}
}

func TestQuery(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, _ = s.InsertCURRecords(ctx, []cur.Record{
		{Service: "AmazonEC2", ResourceID: "a", UnblendedCost: 2},
		{Service: "AmazonEC2", ResourceID: "b", UnblendedCost: 3},
		{Service: "AmazonS3", ResourceID: "c", UnblendedCost: 1},
	})
	rows, err := s.Query(ctx, "SELECT service, SUM(cost) FROM cur GROUP BY 1 ORDER BY 1")
	if err != nil {
		t.Fatal(err)
	}
	cols, _ := rows.Columns()
	if len(cols) != 2 || cols[0] != "service" {
		t.Fatalf("columns = %v", cols)
	}
	want := map[string]float64{"AmazonEC2": 5, "AmazonS3": 1}
	count := 0
	for rows.Next() {
		var svc string
		var sum float64
		if err := rows.Scan(&svc, &sum); err != nil {
			t.Fatal(err)
		}
		if want[svc] != sum {
			t.Fatalf("%s = %v, want %v", svc, sum, want[svc])
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil || count != 2 {
		t.Fatalf("iteration: count=%d err=%v", count, rows.Err())
	}

	for _, q := range []string{"DELETE FROM cur", "DROP TABLE cur", "  insert into cur(line_id, cost) values ('x', 1)"} {
		if _, err := s.Query(ctx, q); !errors.Is(err, ErrReadOnlyQuery) {
			t.Fatalf("%q: want ErrReadOnlyQuery, got %v", q, err)
		}
	}
	// A write hidden behind WITH passes the prefix check but SQLite's
	// query_only pragma must still reject it.
	if _, err := s.Query(ctx, "WITH x AS (SELECT 1) INSERT INTO cur(line_id, cost) SELECT 'y', 1"); err == nil {
		t.Fatal("write inside WITH must be rejected")
	}
	if _, err := s.Query(ctx, "SELECT nope FROM missing"); err == nil {
		t.Fatal("expected SQL error")
	}
	// The connection must be writable again after a read-only query.
	if n, err := s.InsertCURRecords(ctx, []cur.Record{{ResourceID: "d", UnblendedCost: 4}}); err != nil || n != 1 {
		t.Fatalf("insert after query: %d %v", n, err)
	}
}

func TestOpen_BadPath(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	// Close before TempDir cleanup: Windows cannot delete a file that is
	// still open, so a leaked handle fails the test there.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A directory where the file should be cannot be opened as a database.
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("expected error opening a directory")
	}
}

// TestDedupeCURMatchesStoreRoundTrip proves the in-memory path used by
// `csg run` returns exactly what inserting into the store and loading back
// returns, including de-duplication, ordering, and time truncation.
func TestDedupeCURMatchesStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 500, time.UTC) // sub-second part must be dropped
	mk := func(res string, day int, cost float64) cur.Record {
		return cur.Record{UsageAccountID: "1", Service: "AmazonEC2", ResourceID: res, UsageType: "BoxUsage", Region: "eu-west-1",
			Tags: map[string]string{"team": "a"}, UnblendedCost: cost, UsageStartDate: t0.AddDate(0, 0, day), UsageEndDate: t0.AddDate(0, 0, day+1)}
	}
	in := []cur.Record{mk("b", 1, 1.5), mk("a", 0, 2), mk("a", 0, 2), mk("c", 1, 0.25), mk("a", 1, 3)}

	st, err := Open(ctx, filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.InsertCURRecords(ctx, in); err != nil {
		t.Fatal(err)
	}
	want, err := st.LoadCURRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := DedupeCUR(in)
	if len(got) != 4 || !reflect.DeepEqual(got, want) {
		t.Fatalf("in-memory path differs from the store:\n got  %+v\n want %+v", got, want)
	}
	if len(DedupeCUR(nil)) != 0 {
		t.Error("nil input must give an empty result")
	}
}
