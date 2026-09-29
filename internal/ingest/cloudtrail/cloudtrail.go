// Package cloudtrail reads AWS CloudTrail JSON event logs and normalizes
// each entry into an [Event] the local store and security analyzers can
// consume.
//
// Module M2 in docs/architecture.md. Implemented in Unit 4 (Week 4), carrying
// over the Week 3 ingest milestone (v0.1.0-ingest). The reader streams the
// top-level "Records" array with a json.Decoder so large log shards are not
// loaded into memory in one piece.
package cloudtrail

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Event is a normalized CloudTrail record.
type Event struct {
	EventID     string
	EventName   string // e.g. "PutBucketAcl", "AuthorizeSecurityGroupIngress"
	EventSource string // e.g. "s3.amazonaws.com"
	EventTime   time.Time
	Region      string
	SourceIP    string
	UserARN     string
	ResourceID  string
	Raw         map[string]any // full event payload, redacted before any LLM call
}

// Reader reads a CloudTrail JSON export (single file or directory of
// dated shards) and returns normalized events.
type Reader interface {
	Read(ctx context.Context, path string) ([]Event, error)
}

// NewReader returns the default file-system Reader.
func NewReader() Reader { return fileReader{} }

type fileReader struct{}

func (fileReader) Read(ctx context.Context, path string) ([]Event, error) {
	files, err := collectFiles(path)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evs, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("cloudtrail: %s: %w", f, err)
		}
		out = append(out, evs...)
	}
	return out, nil
}

func collectFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cloudtrail: %w", err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		l := strings.ToLower(p)
		if !d.IsDir() && (strings.HasSuffix(l, ".json") || strings.HasSuffix(l, ".json.gz")) {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func readFile(path string) ([]Event, error) {
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
	return decode(src)
}

// decode streams {"Records": [ ... ]} and returns one Event per record.
func decode(r io.Reader) ([]Event, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	var out []Event
	found := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if key != "Records" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
			continue
		}
		found = true
		if err := expectDelim(dec, '['); err != nil {
			return nil, err
		}
		for dec.More() {
			var raw map[string]any
			if err := dec.Decode(&raw); err != nil {
				return nil, err
			}
			ev, err := normalize(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		}
		if err := expectDelim(dec, ']'); err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, errors.New(`missing top-level "Records" array`)
	}
	return out, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q, got %v", want, tok)
	}
	return nil
}

func normalize(raw map[string]any) (Event, error) {
	ev := Event{
		EventID:     str(raw["eventID"]),
		EventName:   str(raw["eventName"]),
		EventSource: str(raw["eventSource"]),
		Region:      str(raw["awsRegion"]),
		SourceIP:    str(raw["sourceIPAddress"]),
		Raw:         raw,
	}
	if ev.EventID == "" {
		return Event{}, errors.New("record without eventID")
	}
	if ts := str(raw["eventTime"]); ts != "" {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return Event{}, fmt.Errorf("event %s: %w", ev.EventID, err)
		}
		ev.EventTime = t.UTC()
	}
	if ui, ok := raw["userIdentity"].(map[string]any); ok {
		ev.UserARN = str(ui["arn"])
	}
	ev.ResourceID = resourceID(raw)
	return ev, nil
}

// resourceID extracts the primary target of the call. It prefers the
// "resources" array CloudTrail attaches to data and some management events,
// and otherwise falls back to well-known request parameters.
func resourceID(raw map[string]any) string {
	if res, ok := raw["resources"].([]any); ok && len(res) > 0 {
		if m, ok := res[0].(map[string]any); ok {
			if arn := str(m["ARN"]); arn != "" {
				return arn
			}
		}
	}
	rp, _ := raw["requestParameters"].(map[string]any)
	for _, k := range []string{"bucketName", "roleName", "userName", "groupName", "policyArn", "policyName", "volumeId", "allocationId", "instanceId", "groupId"} {
		if v := str(rp[k]); v != "" {
			return v
		}
	}
	return ""
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

// RequestParameters returns the event's requestParameters object, or nil.
func (e Event) RequestParameters() map[string]any {
	rp, _ := e.Raw["requestParameters"].(map[string]any)
	return rp
}
