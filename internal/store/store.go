// Package store persists normalized CUR, CloudTrail, and Terraform data in a
// local embedded SQL database for querying by the analyzers in
// internal/analyze and by the `csg query` command.
//
// Module M4 in docs/architecture.md. Implemented in Unit 4 (Week 4).
//
// Engine choice: the design named DuckDB (github.com/marcboeker/go-duckdb),
// but that driver requires cgo, which conflicts with NFR4 (a single static
// binary built with CGO_ENABLED=0 for macOS, Linux, and Windows). Following
// the contingency recorded as D-03 in docs/raid-log.md, this implementation
// uses pure-Go SQLite (modernc.org/sqlite) behind the same Store interface,
// so a DuckDB backend can be swapped in later without touching callers.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

// ErrReadOnlyQuery is returned when Query receives a statement that is not a
// SELECT, WITH, or EXPLAIN query.
var ErrReadOnlyQuery = errors.New("store: only SELECT, WITH, or EXPLAIN statements are allowed")

// Store persists normalized ingest records locally and answers analytical
// queries over them. All implementations must keep data on the local
// filesystem only; no network calls.
type Store interface {
	InsertCURRecords(ctx context.Context, records []cur.Record) (int, error)
	InsertCloudTrailEvents(ctx context.Context, events []cloudtrail.Event) (int, error)
	InsertTerraformResources(ctx context.Context, resources []tfstate.Resource) (int, error)

	LoadCURRecords(ctx context.Context) ([]cur.Record, error)
	LoadCloudTrailEvents(ctx context.Context) ([]cloudtrail.Event, error)
	LoadTerraformResources(ctx context.Context) ([]tfstate.Resource, error)

	// Query runs a read-only SQL statement against the tables cur,
	// cloudtrail_events, and tf_resources.
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	Close() error
}

// Rows is a minimal row-iteration contract, mirroring database/sql.Rows.
type Rows interface {
	Columns() ([]string, error)
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

const schema = `
CREATE TABLE IF NOT EXISTS cur (
	line_id     TEXT PRIMARY KEY,
	account_id  TEXT,
	service     TEXT,
	resource_id TEXT,
	usage_type  TEXT,
	region      TEXT,
	cost        REAL NOT NULL,
	usage_start TEXT,
	usage_end   TEXT,
	tags        TEXT
);
CREATE INDEX IF NOT EXISTS idx_cur_resource ON cur(resource_id);
CREATE TABLE IF NOT EXISTS cloudtrail_events (
	event_id     TEXT PRIMARY KEY,
	event_name   TEXT,
	event_source TEXT,
	event_time   TEXT,
	region       TEXT,
	source_ip    TEXT,
	user_arn     TEXT,
	resource_id  TEXT,
	raw          TEXT
);
CREATE TABLE IF NOT EXISTS tf_resources (
	address    TEXT PRIMARY KEY,
	type       TEXT,
	name       TEXT,
	provider   TEXT,
	attributes TEXT
);`

type sqliteStore struct{ db *sql.DB }

// Open opens (creating if absent) a local database file at path.
func Open(ctx context.Context, path string) (Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: init schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

func (s *sqliteStore) InsertCURRecords(ctx context.Context, records []cur.Record) (int, error) {
	return s.insert(ctx, `INSERT OR IGNORE INTO cur
		(line_id, account_id, service, resource_id, usage_type, region, cost, usage_start, usage_end, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, len(records), func(i int) ([]any, error) {
		r := records[i]
		tags, err := json.Marshal(r.Tags)
		if err != nil {
			return nil, err
		}
		start, end := fmtTime(r.UsageStartDate), fmtTime(r.UsageEndDate)
		id := lineID(r.UsageAccountID, r.Service, r.ResourceID, r.UsageType, r.Region, start, end, fmt.Sprint(r.UnblendedCost))
		return []any{id, r.UsageAccountID, r.Service, r.ResourceID, r.UsageType, r.Region, r.UnblendedCost, start, end, string(tags)}, nil
	})
}

func (s *sqliteStore) InsertCloudTrailEvents(ctx context.Context, events []cloudtrail.Event) (int, error) {
	return s.insert(ctx, `INSERT OR IGNORE INTO cloudtrail_events
		(event_id, event_name, event_source, event_time, region, source_ip, user_arn, resource_id, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, len(events), func(i int) ([]any, error) {
		e := events[i]
		raw, err := json.Marshal(e.Raw)
		if err != nil {
			return nil, err
		}
		return []any{e.EventID, e.EventName, e.EventSource, fmtTime(e.EventTime), e.Region, e.SourceIP, e.UserARN, e.ResourceID, string(raw)}, nil
	})
}

func (s *sqliteStore) InsertTerraformResources(ctx context.Context, resources []tfstate.Resource) (int, error) {
	return s.insert(ctx, `INSERT OR REPLACE INTO tf_resources
		(address, type, name, provider, attributes) VALUES (?, ?, ?, ?, ?)`, len(resources), func(i int) ([]any, error) {
		r := resources[i]
		attrs, err := json.Marshal(r.Attributes)
		if err != nil {
			return nil, err
		}
		return []any{r.Address, r.Type, r.Name, r.Provider, string(attrs)}, nil
	})
}

// insert runs stmt n times inside one transaction and returns the number of
// rows actually written (duplicates skipped by INSERT OR IGNORE are excluded).
func (s *sqliteStore) insert(ctx context.Context, stmt string, n int, args func(int) ([]any, error)) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	prep, err := tx.PrepareContext(ctx, stmt)
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	defer prep.Close()
	written := 0
	for i := 0; i < n; i++ {
		a, err := args(i)
		if err != nil {
			return 0, fmt.Errorf("store: row %d: %w", i, err)
		}
		res, err := prep.ExecContext(ctx, a...)
		if err != nil {
			return 0, fmt.Errorf("store: row %d: %w", i, err)
		}
		if c, err := res.RowsAffected(); err == nil {
			written += int(c)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return written, nil
}

func (s *sqliteStore) LoadCURRecords(ctx context.Context) ([]cur.Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account_id, service, resource_id, usage_type, region, cost, usage_start, usage_end, tags FROM cur ORDER BY usage_start, line_id`)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	var out []cur.Record
	for rows.Next() {
		var r cur.Record
		var start, end, tags string
		if err := rows.Scan(&r.UsageAccountID, &r.Service, &r.ResourceID, &r.UsageType, &r.Region, &r.UnblendedCost, &start, &end, &tags); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		r.UsageStartDate, r.UsageEndDate = parseTime(start), parseTime(end)
		if err := json.Unmarshal([]byte(tags), &r.Tags); err != nil {
			return nil, fmt.Errorf("store: tags: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqliteStore) LoadCloudTrailEvents(ctx context.Context) ([]cloudtrail.Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, event_name, event_source, event_time, region, source_ip, user_arn, resource_id, raw FROM cloudtrail_events ORDER BY event_time, event_id`)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	var out []cloudtrail.Event
	for rows.Next() {
		var e cloudtrail.Event
		var ts, raw string
		if err := rows.Scan(&e.EventID, &e.EventName, &e.EventSource, &ts, &e.Region, &e.SourceIP, &e.UserARN, &e.ResourceID, &raw); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		e.EventTime = parseTime(ts)
		if err := json.Unmarshal([]byte(raw), &e.Raw); err != nil {
			return nil, fmt.Errorf("store: raw event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *sqliteStore) LoadTerraformResources(ctx context.Context) ([]tfstate.Resource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT address, type, name, provider, attributes FROM tf_resources ORDER BY address`)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	var out []tfstate.Resource
	for rows.Next() {
		var r tfstate.Resource
		var attrs string
		if err := rows.Scan(&r.Address, &r.Type, &r.Name, &r.Provider, &attrs); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		if err := json.Unmarshal([]byte(attrs), &r.Attributes); err != nil {
			return nil, fmt.Errorf("store: attributes: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqliteStore) Query(ctx context.Context, q string, args ...any) (Rows, error) {
	if !isReadOnly(q) {
		return nil, ErrReadOnlyQuery
	}
	// query_only makes SQLite itself reject writes, so a statement that slips
	// past the prefix check (for example a CTE wrapping an INSERT) still fails.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	rows, err := conn.QueryContext(ctx, q, args...)
	if err != nil {
		_, _ = conn.ExecContext(ctx, "PRAGMA query_only = OFF")
		_ = conn.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return &connRows{Rows: rows, conn: conn}, nil
}

// connRows releases the dedicated connection (and resets query_only) on Close.
type connRows struct {
	*sql.Rows
	conn *sql.Conn
}

func (r *connRows) Close() error {
	err := r.Rows.Close()
	_, _ = r.conn.ExecContext(context.Background(), "PRAGMA query_only = OFF")
	if cerr := r.conn.Close(); err == nil {
		err = cerr
	}
	return err
}

func isReadOnly(q string) bool {
	q = strings.ToUpper(strings.TrimSpace(q))
	for _, p := range []string{"SELECT", "WITH", "EXPLAIN"} {
		if strings.HasPrefix(q, p) {
			return true
		}
	}
	return false
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func lineID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(h[:12])
}

// DedupeCUR returns records exactly as LoadCURRecords would return them after
// they had been inserted into an empty store: duplicates (same line ID as
// InsertCURRecords computes it) are dropped, timestamps are truncated to
// whole seconds, and the order is by usage start and then line ID. It lets
// `csg run` analyze a throwaway account without paying for a database
// round trip; Unit 6 measurements showed that round trip was 95% of the run
// time at one million line items.
func DedupeCUR(records []cur.Record) []cur.Record {
	type keyed struct {
		id    string
		start string
		rec   cur.Record
	}
	seen := make(map[string]struct{}, len(records))
	keep := make([]keyed, 0, len(records))
	for _, r := range records {
		start, end := fmtTime(r.UsageStartDate), fmtTime(r.UsageEndDate)
		id := lineID(r.UsageAccountID, r.Service, r.ResourceID, r.UsageType, r.Region, start, end, fmt.Sprint(r.UnblendedCost))
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		r.UsageStartDate, r.UsageEndDate = parseTime(start), parseTime(end)
		keep = append(keep, keyed{id, start, r})
	}
	sort.Slice(keep, func(i, j int) bool {
		if keep[i].start != keep[j].start {
			return keep[i].start < keep[j].start
		}
		return keep[i].id < keep[j].id
	})
	out := make([]cur.Record, len(keep))
	for i, k := range keep {
		out[i] = k.rec
	}
	return out
}
