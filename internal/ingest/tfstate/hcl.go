package tfstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// ErrNoResources is returned when an HCL source holds no resource blocks.
var ErrNoResources = errors.New("tfstate: no resource blocks found")

// ComputedAttributes are set by the provider, not written by humans. The HCL
// renderer omits them, and the patch verifier carries them over from the
// original resource so identifiers stay stable across a patch.
var ComputedAttributes = map[string]bool{
	"id": true, "arn": true, "owner_id": true, "tags_all": true, "unique_id": true,
}

// jsonPolicyAttributes hold IAM-style JSON documents; they are rendered as
// jsonencode({...}) so a human or a model can edit them as HCL objects.
var jsonPolicyAttributes = map[string]bool{"policy": true, "assume_role_policy": true}

// RenderHCL reconstructs a Terraform resource block from state attributes.
// Output is deterministic (sorted keys) so it can be diffed and golden-tested.
// Nested blocks are recognized as lists of objects, which is how Terraform
// state stores them.
func RenderHCL(r Resource) []byte {
	f := hclwrite.NewEmptyFile()
	block := f.Body().AppendNewBlock("resource", []string{r.Type, r.Name})
	writeBody(block.Body(), r.Attributes, true)
	return hclwrite.Format(f.Bytes())
}

func writeBody(body *hclwrite.Body, attrs map[string]any, top bool) {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var blocks []string
	for _, k := range keys {
		v := attrs[k]
		if (top && ComputedAttributes[k]) || isEmpty(v) {
			continue
		}
		if objs, ok := objectList(v); ok {
			blocks = append(blocks, k)
			_ = objs
			continue
		}
		if s, ok := v.(string); ok && jsonPolicyAttributes[k] {
			var doc any
			if json.Unmarshal([]byte(s), &doc) == nil {
				body.SetAttributeRaw(k, hclwrite.TokensForFunctionCall("jsonencode", hclwrite.TokensForValue(toCty(doc))))
				continue
			}
		}
		body.SetAttributeValue(k, toCty(v))
	}
	for _, k := range blocks {
		objs, _ := objectList(attrs[k])
		for _, o := range objs {
			nested := body.AppendNewBlock(k, nil)
			writeBody(nested.Body(), o, false)
		}
	}
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// objectList reports whether v is a non-empty list whose elements are all
// objects, i.e. a nested block in Terraform state.
func objectList(v any) ([]map[string]any, bool) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		out = append(out, m)
	}
	return out, true
}

func toCty(v any) cty.Value {
	switch t := v.(type) {
	case nil:
		return cty.NullVal(cty.DynamicPseudoType)
	case string:
		return cty.StringVal(t)
	case bool:
		return cty.BoolVal(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return cty.NumberIntVal(int64(t))
		}
		return cty.NumberFloatVal(t)
	case int:
		return cty.NumberIntVal(int64(t))
	case []any:
		if len(t) == 0 {
			return cty.EmptyTupleVal
		}
		vals := make([]cty.Value, len(t))
		for i, e := range t {
			vals[i] = toCty(e)
		}
		return cty.TupleVal(vals)
	case map[string]any:
		if len(t) == 0 {
			return cty.EmptyObjectVal
		}
		vals := make(map[string]cty.Value, len(t))
		for k, e := range t {
			vals[k] = toCty(e)
		}
		return cty.ObjectVal(vals)
	}
	return cty.StringVal(fmt.Sprint(v))
}

// HCLFile is the result of parsing one HCL source.
type HCLFile struct {
	Resources []Resource
	// OtherBlocks lists top-level blocks that are not resources, such as
	// "provider", "data.external", or "terraform". The patch verifier rejects
	// any patch that contains them.
	OtherBlocks []string
}

// evalContext deliberately exposes no variables and a single pure function.
// Anything else (var.x, file(), references to other resources) cannot be
// evaluated and is kept as its source text in "${...}" form.
var evalContext = &hcl.EvalContext{
	Functions: map[string]function.Function{"jsonencode": stdlib.JSONEncodeFunc},
}

// ParseHCL parses Terraform configuration source. Literal expressions and
// jsonencode() are evaluated; everything else is kept as source text.
func ParseHCL(src []byte, filename string) (HCLFile, error) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return HCLFile{}, fmt.Errorf("tfstate: %s: %s", filename, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return HCLFile{}, fmt.Errorf("tfstate: %s: unexpected body type", filename)
	}
	var out HCLFile
	for _, b := range body.Blocks {
		if b.Type != "resource" || len(b.Labels) != 2 {
			name := b.Type
			if len(b.Labels) > 0 {
				name += "." + strings.Join(b.Labels, ".")
			}
			out.OtherBlocks = append(out.OtherBlocks, name)
			continue
		}
		out.Resources = append(out.Resources, Resource{
			Address:    b.Labels[0] + "." + b.Labels[1],
			Type:       b.Labels[0],
			Name:       b.Labels[1],
			Provider:   "hcl",
			Attributes: bodyToMap(b.Body, src),
		})
	}
	return out, nil
}

func bodyToMap(body *hclsyntax.Body, src []byte) map[string]any {
	out := map[string]any{}
	for name, attr := range body.Attributes {
		val, diags := attr.Expr.Value(evalContext)
		if diags.HasErrors() || !val.IsWhollyKnown() {
			rng := attr.Expr.Range()
			out[name] = "${" + string(rng.SliceBytes(src)) + "}"
			continue
		}
		if val.IsNull() {
			continue
		}
		out[name] = ctyToGo(val)
	}
	for _, b := range body.Blocks {
		list, _ := out[b.Type].([]any)
		out[b.Type] = append(list, bodyToMap(b.Body, src))
	}
	return out
}

func ctyToGo(v cty.Value) any {
	b, err := ctyjson.Marshal(v, v.Type())
	if err != nil {
		return v.GoString()
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return string(b)
	}
	return out
}

// parseDir reads every *.tf file in dir (not recursive, as Terraform does).
func parseDir(ctx context.Context, dir string) ([]Resource, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		return nil, fmt.Errorf("tfstate: %w", err)
	}
	sort.Strings(files)
	var out []Resource
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("tfstate: %w", err)
		}
		hf, err := ParseHCL(src, f)
		if err != nil {
			return nil, err
		}
		out = append(out, hf.Resources...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w in %s (want *.tf files or a terraform.tfstate file)", ErrNoResources, dir)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}
