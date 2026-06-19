package authzen

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// TestResolvedNoAliasing proves that Resolved does not alias shared
// pointers/maps across batch members or back to the source request. A PDP that
// mutates one resolved member's context or a subject's properties MUST NOT
// affect sibling members or the caller's original EvaluationsRequest.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.1 (Defaulting rules).
// https://openid.net/specs/authorization-api-1_0.html
func TestResolvedNoAliasing(t *testing.T) {
	src := EvaluationsRequest{
		Subject: &Subject{
			Type:       "user",
			ID:         "alice@example.com",
			Properties: map[string]any{"dept": "sales"},
		},
		Action:   &Action{Name: "can_read"},
		Resource: &Resource{Type: "document", ID: "default"},
		Context:  Context{"time": "t0"},
		Evaluations: []EvaluationRequest{
			{Resource: &Resource{Type: "document", ID: "1"}},
			{Resource: &Resource{Type: "document", ID: "2"}},
		},
	}

	resolved := src.Resolved()
	if len(resolved) != 2 {
		t.Fatalf("Resolved() length = %d, want 2", len(resolved))
	}

	// Mutate member 0's resolved context, subject properties, and subject id,
	// exactly as a misbehaving (or merely enriching) PDP might.
	resolved[0].Context["time"] = "MUTATED"
	resolved[0].Context["added"] = true
	resolved[0].Subject.Properties["dept"] = "MUTATED"
	resolved[0].Subject.ID = "MUTATED"
	resolved[0].Resource.ID = "MUTATED"

	// Sibling member 1 must be untouched.
	if got := resolved[1].Context["time"]; got != "t0" {
		t.Errorf("sibling context[time] = %v, want t0 (cross-member aliasing)", got)
	}
	if _, ok := resolved[1].Context["added"]; ok {
		t.Errorf("sibling context gained key from member 0 (cross-member aliasing)")
	}
	if got := resolved[1].Subject.Properties["dept"]; got != "sales" {
		t.Errorf("sibling subject.properties[dept] = %v, want sales (cross-member aliasing)", got)
	}
	if got := resolved[1].Subject.ID; got != "alice@example.com" {
		t.Errorf("sibling subject.id = %v, want alice@example.com (cross-member aliasing)", got)
	}

	// The source request must be untouched.
	if got := src.Context["time"]; got != "t0" {
		t.Errorf("source context[time] = %v, want t0 (source contamination)", got)
	}
	if _, ok := src.Context["added"]; ok {
		t.Errorf("source context gained key from resolved member (source contamination)")
	}
	if got := src.Subject.Properties["dept"]; got != "sales" {
		t.Errorf("source subject.properties[dept] = %v, want sales (source contamination)", got)
	}
	if got := src.Subject.ID; got != "alice@example.com" {
		t.Errorf("source subject.id = %v, want alice@example.com (source contamination)", got)
	}
	if got := src.Resource.ID; got != "default" {
		t.Errorf("source resource.id = %v, want default (source contamination)", got)
	}
}

// TestResolvedSingleNoAliasing proves the empty-evaluations (single) form also
// returns copies that do not alias the source request.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.1 (backwards-compatible
// single request).
// https://openid.net/specs/authorization-api-1_0.html
func TestResolvedSingleNoAliasing(t *testing.T) {
	src := EvaluationsRequest{
		Subject:  &Subject{Type: "user", ID: "alice@example.com", Properties: map[string]any{"k": "v"}},
		Action:   &Action{Name: "can_read"},
		Resource: &Resource{Type: "document", ID: "1"},
		Context:  Context{"time": "t0"},
	}
	resolved := src.Resolved()
	if len(resolved) != 1 {
		t.Fatalf("Resolved() length = %d, want 1", len(resolved))
	}
	resolved[0].Context["time"] = "MUTATED"
	resolved[0].Subject.Properties["k"] = "MUTATED"
	if src.Context["time"] != "t0" {
		t.Errorf("source context mutated through single resolved request")
	}
	if src.Subject.Properties["k"] != "v" {
		t.Errorf("source subject.properties mutated through single resolved request")
	}
}

// TestEvaluationsResponseSingleDecisionRoundTrip verifies the backwards-compatible
// single-decision response shape (Section 6.2), which a batch endpoint MUST
// return when the request carried no evaluations array (Section 7.1).
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1, Section 7.2, and Section
// 6.2 (Access Evaluation Response).
// https://openid.net/specs/authorization-api-1_0.html
func TestEvaluationsResponseSingleDecisionRoundTrip(t *testing.T) {
	cases := map[string]string{
		"single allow (Figure 10 shape)": `{
  "decision": true
}`,
		"single deny with context": `{
  "decision": false,
  "context": {
    "reason": "Subject is not a viewer of the resource"
  }
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			roundTrip[EvaluationsResponse](t, fixture)

			var r EvaluationsResponse
			if err := json.Unmarshal([]byte(fixture), &r); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if r.Decision == nil {
				t.Fatalf("single-decision response decoded with nil Decision (wrong mode)")
			}
			if r.Evaluations != nil {
				t.Errorf("single-decision response decoded with non-nil Evaluations: %v", r.Evaluations)
			}
		})
	}
}

// TestEvaluationsResponseBatchModeDecode verifies that a body carrying an
// evaluations array decodes into batch mode (Decision left nil), even if a
// stray top-level decision is present (which SHOULD be omitted and is ignored).
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2 (Access Evaluations
// Response).
// https://openid.net/specs/authorization-api-1_0.html
func TestEvaluationsResponseBatchModeDecode(t *testing.T) {
	const fixture = `{"decision": true, "evaluations": [{"decision": false}]}`
	var r EvaluationsResponse
	if err := json.Unmarshal([]byte(fixture), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Decision != nil {
		t.Errorf("batch response decoded with non-nil Decision: %v", *r.Decision)
	}
	if len(r.Evaluations) != 1 || r.Evaluations[0].Decision {
		t.Errorf("batch evaluations = %+v, want one deny", r.Evaluations)
	}
	// Re-encodes in batch shape, ignoring the stray top-level decision.
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(out, []byte(`"decision":true`)) {
		t.Errorf("batch re-encoding leaked top-level decision: %s", out)
	}
}

// TestSingleDecisionHelper verifies the SingleDecision constructor encodes the
// Section 6.2 single-decision shape and omits the evaluations array.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1 and Section 6.2.
// https://openid.net/specs/authorization-api-1_0.html
func TestSingleDecisionHelper(t *testing.T) {
	out, err := json.Marshal(SingleDecision(true, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(out); got != `{"decision":true}` {
		t.Errorf("SingleDecision(true,nil) = %s, want {\"decision\":true}", got)
	}
	out, err = json.Marshal(SingleDecision(false, map[string]any{"reason": "no"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(out); got != `{"decision":false,"context":{"reason":"no"}}` {
		t.Errorf("SingleDecision(false,ctx) = %s, unexpected", got)
	}
}

// TestEvaluationsResponseNilEvaluationsMarshalsEmpty verifies that the batch
// shape never serializes the evaluations key as JSON null; an absent/nil slice
// MUST encode as [] per the specification's examples.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2 (Access Evaluations
// Response).
// https://openid.net/specs/authorization-api-1_0.html
func TestEvaluationsResponseNilEvaluationsMarshalsEmpty(t *testing.T) {
	out, err := json.Marshal(EvaluationsResponse{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(out); got != `{"evaluations":[]}` {
		t.Errorf("zero EvaluationsResponse = %s, want {\"evaluations\":[]}", got)
	}
}

// TestOptionsNonStringSemantic verifies that a non-string evaluations_semantic
// is rejected rather than silently swallowed and downgraded to the default
// execute_all semantic.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1 (evaluations_semantic)
// and Section 10.1.1 (a malformed required attribute MUST be rejected).
// https://openid.net/specs/authorization-api-1_0.html
func TestOptionsNonStringSemantic(t *testing.T) {
	t.Run("number on Options", func(t *testing.T) {
		var o Options
		err := json.Unmarshal([]byte(`{"evaluations_semantic": 123}`), &o)
		if !errors.Is(err, ErrInvalidSemantic) {
			t.Fatalf("Unmarshal = %v, want errors.Is ErrInvalidSemantic", err)
		}
	})
	t.Run("boolean within request", func(t *testing.T) {
		var req EvaluationsRequest
		err := json.Unmarshal([]byte(`{
  "subject": {"type": "user", "id": "alice@example.com"},
  "action": {"name": "can_read"},
  "evaluations": [{"resource": {"type": "document", "id": "1"}}],
  "options": {"evaluations_semantic": true}
}`), &req)
		if !errors.Is(err, ErrInvalidSemantic) {
			t.Fatalf("Unmarshal = %v, want errors.Is ErrInvalidSemantic", err)
		}
	})
	t.Run("valid string still accepted", func(t *testing.T) {
		var o Options
		if err := json.Unmarshal([]byte(`{"evaluations_semantic": "deny_on_first_deny"}`), &o); err != nil {
			t.Fatalf("Unmarshal = %v, want nil", err)
		}
		if o.EvaluationsSemantic != SemanticDenyOnFirstDeny {
			t.Errorf("EvaluationsSemantic = %q, want deny_on_first_deny", o.EvaluationsSemantic)
		}
	})
}

// TestSearchResponseNilResultsMarshalsEmpty verifies that the REQUIRED results
// key of each Search response encodes as [] (not null) when the slice is
// nil/empty, matching the specification's response examples.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.3 (Search response).
// https://openid.net/specs/authorization-api-1_0.html
func TestSearchResponseNilResultsMarshalsEmpty(t *testing.T) {
	cases := map[string]any{
		"subject":  SubjectSearchResponse{},
		"resource": ResourceSearchResponse{},
		"action":   ActionSearchResponse{},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if bytes.Contains(out, []byte(`"results":null`)) {
				t.Errorf("%s search response serialized results as null: %s", name, out)
			}
			if !bytes.Contains(out, []byte(`"results":[]`)) {
				t.Errorf("%s search response missing empty results array: %s", name, out)
			}
		})
	}
}
