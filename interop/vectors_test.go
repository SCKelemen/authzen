package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// ---------------------------------------------------------------------------
// Vendored vector shapes (the OFFICIAL interop file formats; see
// testdata/SOURCES.md). We decode the request/expected as RawMessage so the
// harness can both (a) round-trip the bytes through OUR types and (b) re-decode
// into OUR types for the client<->server path.
// ---------------------------------------------------------------------------

// todoFile is the shape of interop/authzen-todo-backend/test/decisions-*.json.
type todoFile struct {
	Evaluation  []todoEvalCase  `json:"evaluation"`
	Evaluations []todoBatchCase `json:"evaluations"`
}

type todoEvalCase struct {
	Request  json.RawMessage `json:"request"`
	Expected bool            `json:"expected"`
}

type todoBatchCase struct {
	Request  json.RawMessage `json:"request"`
	Expected []struct {
		Decision bool `json:"decision"`
	} `json:"expected"`
}

// searchFile is the shape of interop/authzen-search-demo/.../results.json.
type searchFile struct {
	Evaluation []searchCase `json:"evaluation"`
}

type searchCase struct {
	Request  json.RawMessage `json:"request"`
	Expected struct {
		Results []map[string]any `json:"results"`
	} `json:"expected"`
}

const (
	todo00 = "testdata/todo/decisions-authorization-api-1_0-00.json"
	todo01 = "testdata/todo/decisions-authorization-api-1_0-01.json"
	todo02 = "testdata/todo/decisions-authorization-api-1_0-02.json"

	searchSubjectFile  = "testdata/search/subject-results.json"
	searchResourceFile = "testdata/search/resource-results.json"
	searchActionFile   = "testdata/search/action-results.json"
)

func loadTodo(t *testing.T, path string) todoFile {
	t.Helper()
	var f todoFile
	loadJSON(t, path, &f)
	return f
}

func loadSearch(t *testing.T, path string) searchFile {
	t.Helper()
	var f searchFile
	loadJSON(t, path, &f)
	return f
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read vendored vector %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode vendored vector %s: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// JSON structural diff (used for wire round-trip conformance).
// ---------------------------------------------------------------------------

// jsonDiff reports the structural differences between an official vector's raw
// request (orig) and the JSON produced by marshaling OUR decoded type (ours).
// dropped lists JSON paths present in orig but absent in ours (fields our types
// do not model); changed lists paths whose value differs or that we added.
type jsonDiff struct {
	dropped []string
	changed []string
}

func diffRawVsTyped(orig []byte, typed any) (jsonDiff, error) {
	var o any
	if err := json.Unmarshal(orig, &o); err != nil {
		return jsonDiff{}, fmt.Errorf("unmarshal original: %w", err)
	}
	reser, err := json.Marshal(typed)
	if err != nil {
		return jsonDiff{}, fmt.Errorf("marshal typed: %w", err)
	}
	var u any
	if err := json.Unmarshal(reser, &u); err != nil {
		return jsonDiff{}, fmt.Errorf("unmarshal typed: %w", err)
	}
	var d jsonDiff
	walkDiff("", o, u, &d)
	sort.Strings(d.dropped)
	sort.Strings(d.changed)
	return d, nil
}

func walkDiff(path string, orig, ours any, d *jsonDiff) {
	switch o := orig.(type) {
	case map[string]any:
		u, ok := ours.(map[string]any)
		if !ok {
			d.changed = append(d.changed, path+" (object->non-object)")
			return
		}
		for k, ov := range o {
			np := joinPath(path, k)
			uv, present := u[k]
			if !present {
				d.dropped = append(d.dropped, np)
				continue
			}
			walkDiff(np, ov, uv, d)
		}
		for k := range u {
			if _, present := o[k]; !present {
				d.changed = append(d.changed, joinPath(path, k)+" (added)")
			}
		}
	case []any:
		u, ok := ours.([]any)
		if !ok {
			d.changed = append(d.changed, path+" (array->non-array)")
			return
		}
		if len(u) != len(o) {
			d.changed = append(d.changed, fmt.Sprintf("%s (len %d->%d)", path, len(o), len(u)))
			return
		}
		for i := range o {
			walkDiff(fmt.Sprintf("%s[%d]", path, i), o[i], u[i], d)
		}
	default:
		if !reflect.DeepEqual(orig, ours) {
			d.changed = append(d.changed, fmt.Sprintf("%s (%v != %v)", path, orig, ours))
		}
	}
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

// leafKey returns the last path segment (the dotted field name) of a JSON path.
func leafKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

// preSpecAttributeKeys are the attribute keys that the pre-1.0 (draft 00) and
// annotated (draft 01) Todo vectors place as TOP-LEVEL siblings of type/id (or
// use as inline comments), rather than under the 1.0 `properties` object. Our
// AuthZEN 1.0 types deliberately model extra attributes only under
// `properties`, so dropping exactly these keys on round-trip is expected and is
// NOT a 1.0 conformance gap.
var preSpecAttributeKeys = map[string]bool{
	"identity": true, // draft-00 subject sibling attribute (1.0: subject.properties)
	"userID":   true, // draft-00 resource sibling attribute (1.0: resource.properties)
	"ownerID":  true, // draft-00 resource sibling attribute (1.0: resource.properties.ownerID, as in -01/-02)
	"_note":    true, // draft-01 inline fixture annotation (not a spec field)
}

// ---------------------------------------------------------------------------
// Request signatures (used to seed the vector-backed PDP).
// ---------------------------------------------------------------------------

func evalSig(r *authzen.EvaluationRequest) string {
	var st, si, an, rt, ri, owner string
	if r.Subject != nil {
		st, si = r.Subject.Type, r.Subject.ID
	}
	if r.Action != nil {
		an = r.Action.Name
	}
	if r.Resource != nil {
		rt, ri = r.Resource.Type, r.Resource.ID
		if r.Resource.Properties != nil {
			if v, ok := r.Resource.Properties["ownerID"]; ok {
				owner = fmt.Sprint(v)
			}
		}
	}
	return strings.Join([]string{st, si, an, rt, ri, owner}, "|")
}

func subjectSearchSig(r *authzen.SubjectSearchRequest) string {
	var rt, ri, an string
	if r.Resource != nil {
		rt, ri = r.Resource.Type, r.Resource.ID
	}
	if r.Action != nil {
		an = r.Action.Name
	}
	return strings.Join([]string{rt, ri, an}, "|")
}

func resourceSearchSig(r *authzen.ResourceSearchRequest) string {
	var si, an, rt string
	if r.Subject != nil {
		si = r.Subject.ID
	}
	if r.Action != nil {
		an = r.Action.Name
	}
	if r.Resource != nil {
		rt = r.Resource.Type
	}
	return strings.Join([]string{si, an, rt}, "|")
}

func actionSearchSig(r *authzen.ActionSearchRequest) string {
	var si, rt, ri string
	if r.Subject != nil {
		si = r.Subject.ID
	}
	if r.Resource != nil {
		rt, ri = r.Resource.Type, r.Resource.ID
	}
	return strings.Join([]string{si, rt, ri}, "|")
}

// ---------------------------------------------------------------------------
// vectorPDP is a server.PDP backed entirely by the official vectors. Looking up
// a request that was never seeded returns an error (HTTP 500), so a missing
// seed surfaces as a clear test failure rather than a silent wrong answer.
// ---------------------------------------------------------------------------

type vectorPDP struct {
	eval      map[string]bool
	subjects  map[string][]authzen.Subject
	resources map[string][]authzen.Resource
	actions   map[string][]authzen.Action
}

func (p *vectorPDP) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	sig := evalSig(req)
	d, ok := p.eval[sig]
	if !ok {
		return nil, fmt.Errorf("vectorPDP: no decision seeded for evaluation %q", sig)
	}
	return &authzen.EvaluationResponse{Decision: d}, nil
}

func (p *vectorPDP) SearchSubjects(_ context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	sig := subjectSearchSig(req)
	res, ok := p.subjects[sig]
	if !ok {
		return nil, fmt.Errorf("vectorPDP: no subject-search results seeded for %q", sig)
	}
	return &authzen.SubjectSearchResponse{Results: res}, nil
}

func (p *vectorPDP) SearchResources(_ context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	sig := resourceSearchSig(req)
	res, ok := p.resources[sig]
	if !ok {
		return nil, fmt.Errorf("vectorPDP: no resource-search results seeded for %q", sig)
	}
	return &authzen.ResourceSearchResponse{Results: res}, nil
}

func (p *vectorPDP) SearchActions(_ context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	sig := actionSearchSig(req)
	res, ok := p.actions[sig]
	if !ok {
		return nil, fmt.Errorf("vectorPDP: no action-search results seeded for %q", sig)
	}
	return &authzen.ActionSearchResponse{Results: res}, nil
}

// decodeInto unmarshals raw JSON into a fresh T and returns it.
func decodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vector into %T: %v\n%s", v, err, raw)
	}
	return v
}

// convertResults re-encodes a slice of generic result objects into a concrete
// AuthZEN result slice ([]Subject, []Resource, or []Action) via JSON.
func convertResults[T any](t *testing.T, results []map[string]any) []T {
	t.Helper()
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	var out []T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("convert results to %T: %v", out, err)
	}
	return out
}
