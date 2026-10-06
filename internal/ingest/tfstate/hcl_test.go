package tfstate

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestRenderParseRoundTrip is a white-box property test: rendering state
// attributes as HCL and parsing them back must preserve every
// human-authored attribute. The patch verifier depends on this property.
func TestRenderParseRoundTrip(t *testing.T) {
	r := Resource{Type: "aws_instance", Name: "web", Attributes: map[string]any{
		"id":            "i-123", // computed, omitted
		"instance_type": "m5.large",
		"ebs_optimized": true,
		"cpu_count":     2.0,
		"ratio":         0.5,
		"empty":         "",
		"nothing":       nil,
		"none":          []any{},
		"sg_ids":        []any{"sg-1", "sg-2"},
		"tags":          map[string]any{"team": "booking"},
		"metadata_options": []any{
			map[string]any{"http_tokens": "required", "http_put_response_hop_limit": 1.0},
		},
		"policy": `{"Statement":[{"Action":"s3:GetObject","Effect":"Allow"}],"Version":"2012-10-17"}`,
	}}
	src := RenderHCL(r)
	for _, want := range []string{`resource "aws_instance" "web"`, "metadata_options {", "jsonencode(", `instance_type = "m5.large"`} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("rendered HCL missing %q:\n%s", want, src)
		}
	}
	if strings.Contains(string(src), "i-123") {
		t.Fatalf("computed id must not be rendered:\n%s", src)
	}
	hf, err := ParseHCL(src, "x.tf")
	if err != nil {
		t.Fatal(err)
	}
	if len(hf.Resources) != 1 || hf.Resources[0].Address != "aws_instance.web" {
		t.Fatalf("unexpected resources: %+v", hf.Resources)
	}
	got := hf.Resources[0].Attributes
	for _, k := range []string{"instance_type", "ebs_optimized", "cpu_count", "ratio", "sg_ids", "tags", "metadata_options"} {
		if !reflect.DeepEqual(got[k], r.Attributes[k]) {
			t.Errorf("%s: got %#v, want %#v", k, got[k], r.Attributes[k])
		}
	}
	if !strings.Contains(got["policy"].(string), `"s3:GetObject"`) {
		t.Errorf("policy not re-encoded as JSON: %v", got["policy"])
	}
}

func TestParseHCL_ReferencesAndOtherBlocks(t *testing.T) {
	src := []byte(`
provider "aws" { region = "eu-west-1" }
data "external" "x" { program = ["sh", "-c", "id"] }
resource "aws_flow_log" "main" {
  vpc_id       = aws_vpc.main.id
  traffic_type = "ALL"
  provisioner "local-exec" { command = "curl evil" }
}`)
	hf, err := ParseHCL(src, "main.tf")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hf.OtherBlocks, []string{"provider.aws", "data.external.x"}) {
		t.Fatalf("other blocks = %v", hf.OtherBlocks)
	}
	a := hf.Resources[0].Attributes
	if a["vpc_id"] != "${aws_vpc.main.id}" {
		t.Fatalf("unresolvable reference should keep its source text, got %v", a["vpc_id"])
	}
	if _, ok := a["provisioner"]; !ok {
		t.Fatal("nested provisioner block must be visible to the verifier")
	}
	if _, err := ParseHCL([]byte(`resource "a" {`), "bad.tf"); err == nil {
		t.Fatal("syntax error expected")
	}
}

func TestParse_HCLDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("b.tf", `resource "aws_s3_bucket" "logs" { bucket = "logs" }`)
	write("a.tf", `resource "aws_ebs_volume" "data" {
  size      = 100
  encrypted = false
}`)
	write("notes.txt", "ignored")
	res, err := NewParser().Parse(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Address != "aws_ebs_volume.data" || res[1].Attr("bucket") != "logs" {
		t.Fatalf("unexpected resources: %+v", res)
	}
	if v, ok := res[0].Bool("encrypted"); !ok || v {
		t.Fatalf("encrypted = %v, %v", v, ok)
	}
	write("c.tf", `resource "x" {`)
	if _, err := NewParser().Parse(context.Background(), dir); err == nil {
		t.Fatal("syntax error in a .tf file must fail the directory parse")
	}
}
