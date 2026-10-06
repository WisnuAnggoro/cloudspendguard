package tfstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const fixture = "../../../testdata/terraform.tfstate"

func TestParse_Golden(t *testing.T) {
	res, err := NewParser().Parse(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 22 {
		t.Fatalf("want 22 managed resources (data source excluded), got %d", len(res))
	}
	byAddr := map[string]Resource{}
	for _, r := range res {
		byAddr[r.Address] = r
	}
	vol, ok := byAddr["aws_ebs_volume.etl_scratch"]
	if !ok {
		t.Fatal("aws_ebs_volume.etl_scratch missing")
	}
	if vol.Type != "aws_ebs_volume" || vol.Name != "etl_scratch" || vol.Attr("id") != "vol-0a1b2c3d4e5f60099" {
		t.Fatalf("unexpected volume: %+v", vol)
	}
	if vol.Attr("size") != "" {
		t.Fatal("Attr should return empty string for non-string values")
	}
	pab := byAddr["aws_s3_bucket_public_access_block.exports"]
	if v, ok := pab.Bool("block_public_acls"); !ok || v {
		t.Fatalf("block_public_acls = %v, %v", v, ok)
	}
	if _, ok := pab.Bool("missing"); ok {
		t.Fatal("Bool should report ok=false for absent keys")
	}
	if _, ok := byAddr["data.aws_caller_identity.current"]; ok {
		t.Fatal("data sources must be skipped")
	}
}

func TestParse_ModulesAndIndexKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.tfstate")
	body := `{"version": 4, "resources": [
		{"module": "module.net", "mode": "managed", "type": "aws_eip", "name": "nat", "instances": [
			{"index_key": 0, "attributes": {"id": "a"}}, {"index_key": "b", "attributes": {"id": "b"}}]}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewParser().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Address != `module.net.aws_eip.nat["b"]` || res[1].Address != "module.net.aws_eip.nat[0]" {
		t.Fatalf("unexpected addresses: %q, %q", res[0].Address, res[1].Address)
	}
}

func TestParse_Errors(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewParser().Parse(context.Background(), dir); !errors.Is(err, ErrNoResources) {
		t.Fatalf("empty directory: want ErrNoResources, got %v", err)
	}
	if _, err := NewParser().Parse(context.Background(), filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file: expected error")
	}
	for name, body := range map[string]string{"bad-json": "{", "v3": `{"version": 3}`} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := NewParser().Parse(context.Background(), p); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewParser().Parse(ctx, fixture); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
