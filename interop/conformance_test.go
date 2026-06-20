package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/client"
	"github.com/SCKelemen/authzen/server"
)

// ===========================================================================
// 1. Request WIRE-FORMAT conformance: marshal OUR request types and compare to
//    the OFFICIAL vector's request JSON (field names, casing, omitempty,
//    nesting). Strict on the AuthZEN 1.0-aligned (-02) vectors; the pre-1.0
//    (-00) and annotated (-01) vectors are allowed to drop ONLY the documented
//    non-1.0 sibling/annotation keys (identity, userID, _note).
// ===========================================================================

func TestTodoEvaluationRequestWireConformance(t *testing.T) {
	for _, path := range []string{todo00, todo01, todo02} {
		path := path
		t.Run(shortName(path), func(t *testing.T) {
			f := loadTodo(t, path)
			if len(f.Evaluation) == 0 {
				t.Fatalf("no evaluation vectors in %s", path)
			}
			var allowedDrops int
			for i, c := range f.Evaluation {
				req := decodeInto[authzen.EvaluationRequest](t, c.Request)
				d, err := diffRawVsTyped(c.Request, &req)
				if err != nil {
					t.Fatalf("case %d: %v", i, err)
				}
				if len(d.changed) != 0 {
					t.Errorf("case %d: our wire format CHANGED official fields: %v\nofficial: %s",
						i, d.changed, c.Request)
				}
				for _, dp := range d.dropped {
					if !preSpecAttributeKeys[leafKey(dp)] {
						t.Errorf("case %d: our types DROPPED an official 1.0 field %q\nofficial: %s",
							i, dp, c.Request)
						continue
					}
					allowedDrops++
				}
			}
			t.Logf("%s: %d evaluation requests round-tripped; %d documented pre-1.0/annotation keys dropped",
				shortName(path), len(f.Evaluation), allowedDrops)
		})
	}
}

func TestTodoEvaluationsBatchRequestWireConformance(t *testing.T) {
	f := loadTodo(t, todo02)
	if len(f.Evaluations) == 0 {
		t.Fatal("no batch evaluations vectors in -02 file")
	}
	for i, c := range f.Evaluations {
		req := decodeInto[authzen.EvaluationsRequest](t, c.Request)
		d, err := diffRawVsTyped(c.Request, &req)
		if err != nil {
			t.Fatalf("batch case %d: %v", i, err)
		}
		if len(d.changed) != 0 || len(d.dropped) != 0 {
			t.Errorf("batch case %d: wire mismatch changed=%v dropped=%v\nofficial: %s",
				i, d.changed, d.dropped, c.Request)
		}
	}
	t.Logf("-02: %d batch (evaluations) requests round-tripped byte-for-byte", len(f.Evaluations))
}

func TestSearchRequestWireConformance(t *testing.T) {
	t.Run("subject", func(t *testing.T) {
		f := loadSearch(t, searchSubjectFile)
		for i, c := range f.Evaluation {
			req := decodeInto[authzen.SubjectSearchRequest](t, c.Request)
			assertExactWire(t, i, c.Request, &req)
		}
		t.Logf("subject search: %d requests round-tripped byte-for-byte", len(f.Evaluation))
	})
	t.Run("resource", func(t *testing.T) {
		f := loadSearch(t, searchResourceFile)
		for i, c := range f.Evaluation {
			req := decodeInto[authzen.ResourceSearchRequest](t, c.Request)
			assertExactWire(t, i, c.Request, &req)
		}
		t.Logf("resource search: %d requests round-tripped byte-for-byte", len(f.Evaluation))
	})
	t.Run("action", func(t *testing.T) {
		f := loadSearch(t, searchActionFile)
		for i, c := range f.Evaluation {
			req := decodeInto[authzen.ActionSearchRequest](t, c.Request)
			assertExactWire(t, i, c.Request, &req)
		}
		t.Logf("action search: %d requests round-tripped byte-for-byte", len(f.Evaluation))
	})
}

func assertExactWire(t *testing.T, i int, raw []byte, typed any) {
	t.Helper()
	d, err := diffRawVsTyped(raw, typed)
	if err != nil {
		t.Fatalf("case %d: %v", i, err)
	}
	if len(d.changed) != 0 || len(d.dropped) != 0 {
		t.Errorf("case %d: wire mismatch changed=%v dropped=%v\nofficial: %s",
			i, d.changed, d.dropped, raw)
	}
}

// ===========================================================================
// 2. Response PARSING conformance: unmarshal official-shaped responses into OUR
//    response types and confirm the decision/results parse correctly.
// ===========================================================================

func TestResponseParsingConformance(t *testing.T) {
	// Single Access Evaluation Response (Section 6.2) with a decision context.
	t.Run("evaluation", func(t *testing.T) {
		raw := []byte(`{"decision":true,"context":{"reason_admin":{"123":"ok"}}}`)
		var resp authzen.EvaluationResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("parse evaluation response: %v", err)
		}
		if !resp.Decision {
			t.Errorf("decision = false, want true")
		}
		if resp.Context == nil {
			t.Errorf("context dropped")
		}
	})
	// Batch Access Evaluations Response (Section 7.2).
	t.Run("evaluations", func(t *testing.T) {
		raw := []byte(`{"evaluations":[{"decision":true},{"decision":false}]}`)
		var resp authzen.EvaluationsResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("parse evaluations response: %v", err)
		}
		if len(resp.Evaluations) != 2 || !resp.Evaluations[0].Decision || resp.Evaluations[1].Decision {
			t.Errorf("decisions parsed wrong: %+v", resp.Evaluations)
		}
	})
	// Search Response with a page object (Section 8.3).
	t.Run("subject-search", func(t *testing.T) {
		raw := []byte(`{"page":{"next_token":"abc"},"results":[{"type":"user","id":"alice"}]}`)
		var resp authzen.SubjectSearchResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("parse subject search response: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].ID != "alice" {
			t.Errorf("results parsed wrong: %+v", resp.Results)
		}
		if resp.Page == nil || resp.Page.NextToken != "abc" {
			t.Errorf("page.next_token parsed wrong: %+v", resp.Page)
		}
	})
}

// ===========================================================================
// 3. End-to-end PDP path: drive OUR client against OUR server (PDP backed by
//    the official vectors) over the real HTTPS+JSON wire (httptest). Also POST
//    the RAW official request bytes to OUR server to prove it parses the
//    official wire format and returns the expected decision.
// ===========================================================================

func TestTodoDecisionPathThroughServerAndClient(t *testing.T) {
	pdp := seedPDP(t)
	ts := httptest.NewServer(server.NewHandler(pdp))
	defer ts.Close()
	c := client.New(ts.URL)
	ctx := context.Background()

	for _, path := range []string{todo00, todo01, todo02} {
		path := path
		t.Run(shortName(path), func(t *testing.T) {
			f := loadTodo(t, path)
			for i, tc := range f.Evaluation {
				req := decodeInto[authzen.EvaluationRequest](t, tc.Request)

				// (a) typed client -> server -> PDP -> client decode.
				resp, err := c.Evaluate(ctx, &req)
				if err != nil {
					t.Fatalf("case %d: client.Evaluate: %v", i, err)
				}
				if resp.Decision != tc.Expected {
					t.Errorf("case %d: client decision = %v, want %v (%s)",
						i, resp.Decision, tc.Expected, evalSig(&req))
				}

				// (b) RAW official bytes -> server (proves server parses the
				// official wire format, including draft-00 sibling attributes).
				got := postRawDecision(t, ts.URL+authzen.DefaultEvaluationPath, tc.Request)
				if got != tc.Expected {
					t.Errorf("case %d: raw-bytes server decision = %v, want %v", i, got, tc.Expected)
				}
			}
			t.Logf("%s: %d evaluations conform end-to-end (typed client + raw bytes)",
				shortName(path), len(f.Evaluation))
		})
	}
}

func TestTodoBatchPathThroughServerAndClient(t *testing.T) {
	pdp := seedPDP(t)
	ts := httptest.NewServer(server.NewHandler(pdp))
	defer ts.Close()
	c := client.New(ts.URL)
	ctx := context.Background()

	f := loadTodo(t, todo02)
	for i, tc := range f.Evaluations {
		req := decodeInto[authzen.EvaluationsRequest](t, tc.Request)
		resp, err := c.EvaluateBatch(ctx, &req)
		if err != nil {
			t.Fatalf("batch %d: client.EvaluateBatch: %v", i, err)
		}
		if len(resp.Evaluations) != len(tc.Expected) {
			t.Fatalf("batch %d: got %d decisions, want %d", i, len(resp.Evaluations), len(tc.Expected))
		}
		for j, want := range tc.Expected {
			if resp.Evaluations[j].Decision != want.Decision {
				t.Errorf("batch %d member %d: decision = %v, want %v",
					i, j, resp.Evaluations[j].Decision, want.Decision)
			}
		}
	}
	t.Logf("-02: %d batch requests conform end-to-end", len(f.Evaluations))
}

func TestSearchPathThroughServerAndClient(t *testing.T) {
	pdp := seedPDP(t)
	ts := httptest.NewServer(server.NewHandler(pdp))
	defer ts.Close()
	c := client.New(ts.URL)
	ctx := context.Background()

	t.Run("subject", func(t *testing.T) {
		f := loadSearch(t, searchSubjectFile)
		for i, tc := range f.Evaluation {
			req := decodeInto[authzen.SubjectSearchRequest](t, tc.Request)
			resp, err := c.SearchSubjects(ctx, &req)
			if err != nil {
				t.Fatalf("case %d: SearchSubjects: %v", i, err)
			}
			want := convertResults[authzen.Subject](t, tc.Expected.Results)
			if !equalKeySets(subjectKeys(resp.Results), subjectKeys(want)) {
				t.Errorf("case %d: subjects = %v, want %v", i, subjectKeys(resp.Results), subjectKeys(want))
			}
		}
		t.Logf("subject search: %d queries conform end-to-end", len(f.Evaluation))
	})

	t.Run("resource", func(t *testing.T) {
		f := loadSearch(t, searchResourceFile)
		for i, tc := range f.Evaluation {
			req := decodeInto[authzen.ResourceSearchRequest](t, tc.Request)
			resp, err := c.SearchResources(ctx, &req)
			if err != nil {
				t.Fatalf("case %d: SearchResources: %v", i, err)
			}
			want := convertResults[authzen.Resource](t, tc.Expected.Results)
			if !equalKeySets(resourceKeys(resp.Results), resourceKeys(want)) {
				t.Errorf("case %d: resources = %v, want %v", i, resourceKeys(resp.Results), resourceKeys(want))
			}
		}
		t.Logf("resource search: %d queries conform end-to-end", len(f.Evaluation))
	})

	t.Run("action", func(t *testing.T) {
		f := loadSearch(t, searchActionFile)
		for i, tc := range f.Evaluation {
			req := decodeInto[authzen.ActionSearchRequest](t, tc.Request)
			resp, err := c.SearchActions(ctx, &req)
			if err != nil {
				t.Fatalf("case %d: SearchActions: %v", i, err)
			}
			want := convertResults[authzen.Action](t, tc.Expected.Results)
			if !equalKeySets(actionKeys(resp.Results), actionKeys(want)) {
				t.Errorf("case %d: actions = %v, want %v", i, actionKeys(resp.Results), actionKeys(want))
			}
		}
		t.Logf("action search: %d queries conform end-to-end", len(f.Evaluation))
	})
}

// ---------------------------------------------------------------------------
// Seeding + helpers
// ---------------------------------------------------------------------------

func seedPDP(t *testing.T) *vectorPDP {
	t.Helper()
	p := &vectorPDP{
		eval:      map[string]bool{},
		subjects:  map[string][]authzen.Subject{},
		resources: map[string][]authzen.Resource{},
		actions:   map[string][]authzen.Action{},
	}

	setEval := func(sig string, d bool) {
		if prev, ok := p.eval[sig]; ok && prev != d {
			t.Fatalf("vector conflict: signature %q expects both %v and %v", sig, prev, d)
		}
		p.eval[sig] = d
	}

	for _, path := range []string{todo00, todo01, todo02} {
		f := loadTodo(t, path)
		for _, c := range f.Evaluation {
			req := decodeInto[authzen.EvaluationRequest](t, c.Request)
			setEval(evalSig(&req), c.Expected)
		}
		for _, c := range f.Evaluations {
			batch := decodeInto[authzen.EvaluationsRequest](t, c.Request)
			members := batch.Resolved()
			if len(members) != len(c.Expected) {
				t.Fatalf("%s: batch member/expected length mismatch %d != %d", path, len(members), len(c.Expected))
			}
			for j := range members {
				setEval(evalSig(&members[j]), c.Expected[j].Decision)
			}
		}
	}

	sf := loadSearch(t, searchSubjectFile)
	for _, c := range sf.Evaluation {
		req := decodeInto[authzen.SubjectSearchRequest](t, c.Request)
		p.subjects[subjectSearchSig(&req)] = convertResults[authzen.Subject](t, c.Expected.Results)
	}
	rf := loadSearch(t, searchResourceFile)
	for _, c := range rf.Evaluation {
		req := decodeInto[authzen.ResourceSearchRequest](t, c.Request)
		p.resources[resourceSearchSig(&req)] = convertResults[authzen.Resource](t, c.Expected.Results)
	}
	af := loadSearch(t, searchActionFile)
	for _, c := range af.Evaluation {
		req := decodeInto[authzen.ActionSearchRequest](t, c.Request)
		p.actions[actionSearchSig(&req)] = convertResults[authzen.Action](t, c.Expected.Results)
	}
	return p
}

func postRawDecision(t *testing.T, url string, raw []byte) bool {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("raw POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw POST status %d: %s", resp.StatusCode, body)
	}
	var out authzen.EvaluationResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("raw POST decode: %v (%s)", err, body)
	}
	return out.Decision
}

func subjectKeys(s []authzen.Subject) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = v.Type + "|" + v.ID
	}
	sort.Strings(out)
	return out
}

func resourceKeys(s []authzen.Resource) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = v.Type + "|" + v.ID
	}
	sort.Strings(out)
	return out
}

func actionKeys(s []authzen.Action) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = v.Name
	}
	sort.Strings(out)
	return out
}

func equalKeySets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func shortName(path string) string {
	// e.g. testdata/todo/decisions-authorization-api-1_0-02.json -> 1_0-02
	for _, tag := range []string{"1_0-00", "1_0-01", "1_0-02"} {
		if bytes.Contains([]byte(path), []byte(tag)) {
			return tag
		}
	}
	return path
}
