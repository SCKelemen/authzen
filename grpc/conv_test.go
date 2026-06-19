package authzengrpc

import (
	"reflect"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	authzenv1 "github.com/SCKelemen/authzen/grpc/gen/authzen/v1"
)

// These tests exercise the proto<->core conversions in conv.go. They use values
// that survive the google.protobuf.Struct round-trip (strings and nested
// objects) because, like JSON, a Struct represents every number as a double.
//
// Fixtures are drawn from the verbatim examples in the AuthZEN specification.
// OpenID AuthZEN Authorization API 1.0.
// https://openid.net/specs/authorization-api-1_0.html

func TestSubjectRoundTrip(t *testing.T) {
	// Spec Figure 3: subject with ip_address + device_id properties.
	want := &authzen.Subject{
		Type: "user",
		ID:   "alice@example.com",
		Properties: map[string]any{
			"ip_address": "172.217.22.14",
			"device_id":  "8:65:ee:17:7e:0b",
		},
	}
	p, err := subjectToProto(want)
	if err != nil {
		t.Fatalf("subjectToProto: %v", err)
	}
	got := subjectFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestResourceRoundTrip(t *testing.T) {
	// Spec Figure 5: resource with a nested library_record object.
	want := &authzen.Resource{
		Type: "book",
		ID:   "123",
		Properties: map[string]any{
			"library_record": map[string]any{
				"title": "AuthZEN in Action",
				"isbn":  "978-0593383322",
			},
		},
	}
	p, err := resourceToProto(want)
	if err != nil {
		t.Fatalf("resourceToProto: %v", err)
	}
	got := resourceFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestActionRoundTrip(t *testing.T) {
	// Spec Figure 7: action with properties.
	want := &authzen.Action{
		Name:       "extend-loan",
		Properties: map[string]any{"period": "2W"},
	}
	p, err := actionToProto(want)
	if err != nil {
		t.Fatalf("actionToProto: %v", err)
	}
	got := actionFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestNilEntityConversions(t *testing.T) {
	if s, err := subjectToProto(nil); err != nil || s != nil {
		t.Fatalf("subjectToProto(nil) = %v, %v; want nil, nil", s, err)
	}
	if subjectFromProto(nil) != nil {
		t.Fatal("subjectFromProto(nil) should be nil")
	}
	if r, err := resourceToProto(nil); err != nil || r != nil {
		t.Fatalf("resourceToProto(nil) = %v, %v; want nil, nil", r, err)
	}
	if a, err := actionToProto(nil); err != nil || a != nil {
		t.Fatalf("actionToProto(nil) = %v, %v; want nil, nil", a, err)
	}
}

func TestEvaluationRequestRoundTrip(t *testing.T) {
	// Spec Figure 28: full Access Evaluation request.
	want := authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
		Context:  authzen.Context{"time": "1985-10-26T01:22-07:00"},
	}
	p, err := evaluationRequestToProto(want)
	if err != nil {
		t.Fatalf("evaluationRequestToProto: %v", err)
	}
	got := evaluationRequestFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestEvaluationResponseRoundTrip(t *testing.T) {
	// Spec Figure 11-style decision context (reason_admin/reason_user).
	want := authzen.EvaluationResponse{
		Decision: false,
		Context: map[string]any{
			"reason_admin": map[string]any{"403": "Request failed policy C076E82F"},
			"reason_user":  map[string]any{"403": "Insufficient privileges. Contact your administrator"},
		},
	}
	p, err := evaluationResponseToProto(want)
	if err != nil {
		t.Fatalf("evaluationResponseToProto: %v", err)
	}
	got := evaluationResponseFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestSemanticConversionRoundTrip(t *testing.T) {
	cases := []struct {
		core  authzen.EvaluationsSemantic
		proto authzenv1.EvaluationsSemantic
	}{
		{"", authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_UNSPECIFIED},
		{authzen.SemanticExecuteAll, authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_EXECUTE_ALL},
		{authzen.SemanticDenyOnFirstDeny, authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_DENY_ON_FIRST_DENY},
		{authzen.SemanticPermitOnFirstPermit, authzenv1.EvaluationsSemantic_EVALUATIONS_SEMANTIC_PERMIT_ON_FIRST_PERMIT},
	}
	for _, c := range cases {
		if got := semanticToProto(c.core); got != c.proto {
			t.Errorf("semanticToProto(%q) = %v; want %v", c.core, got, c.proto)
		}
		if got := semanticFromProto(c.proto); got != c.core {
			t.Errorf("semanticFromProto(%v) = %q; want %q", c.proto, got, c.core)
		}
	}
}

func TestEvaluationsRequestRoundTrip(t *testing.T) {
	// Spec Figure 30: top-level subject/action/context defaults with per-item
	// resource overrides, plus an options object.
	want := authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "can_read"},
		Context: authzen.Context{"time": "2024-05-31T15:22-07:00"},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "boxcarring.md"}},
			{Resource: &authzen.Resource{Type: "document", ID: "subject-search.md"}},
			{
				Action:   &authzen.Action{Name: "can_edit"},
				Resource: &authzen.Resource{Type: "document", ID: "resource-search.md"},
			},
		},
		Options: &authzen.Options{
			EvaluationsSemantic: authzen.SemanticExecuteAll,
			Additional:          map[string]any{"another_option": "value"},
		},
	}
	p, err := evaluationsRequestToProto(want)
	if err != nil {
		t.Fatalf("evaluationsRequestToProto: %v", err)
	}
	got := evaluationsRequestFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestSubjectSearchRequestRoundTrip(t *testing.T) {
	// Spec Figure 20 + a page object (Section 8.2.1).
	want := authzen.SubjectSearchRequest{
		Subject:  &authzen.Subject{Type: "user"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
		Context:  authzen.Context{"time": "2024-10-26T01:22-07:00"},
		Page:     &authzen.Page{Token: "a3M9NDU2O3N6PTI=", Limit: 2},
	}
	p, err := subjectSearchRequestToProto(want)
	if err != nil {
		t.Fatalf("subjectSearchRequestToProto: %v", err)
	}
	got := subjectSearchRequestFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestSubjectSearchResponseRoundTrip(t *testing.T) {
	// Spec Figure 16: first page of three with next_token + total.
	want := authzen.SubjectSearchResponse{
		Page: &authzen.PageResponse{NextToken: "a3M9NDU2O3N6PTI=", Count: 2, Total: 3},
		Results: []authzen.Subject{
			{Type: "user", ID: "alice@example.com"},
			{Type: "user", ID: "bob@example.com"},
		},
	}
	p, err := subjectSearchResponseToProto(want)
	if err != nil {
		t.Fatalf("subjectSearchResponseToProto: %v", err)
	}
	got := subjectSearchResponseFromProto(p)
	// Count and Total are carried explicitly in the page object, so they
	// survive the round-trip unchanged.
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestActionSearchRequestRoundTrip(t *testing.T) {
	// Spec Figure 24: action search carries no action.
	want := authzen.ActionSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
		Context:  authzen.Context{"time": "2024-10-26T01:22-07:00"},
	}
	p, err := actionSearchRequestToProto(want)
	if err != nil {
		t.Fatalf("actionSearchRequestToProto: %v", err)
	}
	got := actionSearchRequestFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	// Spec Section 9.2.2 metadata example.
	want := authzen.Metadata{
		PolicyDecisionPoint:      "https://pdp.example.com",
		AccessEvaluationEndpoint: "https://pdp.example.com/access/v1/evaluation",
		SearchSubjectEndpoint:    "https://pdp.example.com/access/v1/search/subject",
		SearchResourceEndpoint:   "https://pdp.example.com/access/v1/search/resource",
		Capabilities:             []string{"urn:authzen:capability:example"},
	}
	got := metadataFromProto(metadataToProto(want))
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestPageResponseNilRoundTrips(t *testing.T) {
	// An absent page object (nil) round-trips to an absent page object.
	p, err := pageResponseToProto(nil)
	if err != nil || p != nil {
		t.Fatalf("pageResponseToProto(nil) = %v, %v; want nil, nil", p, err)
	}
	if got := pageResponseFromProto(nil); got != nil {
		t.Fatalf("pageResponseFromProto(nil) = %#v; want nil", got)
	}
}

func TestPageResponseRoundTripPreservesCountAndTotal(t *testing.T) {
	// Lossless: Count and Total are carried explicitly (Count is NOT derived
	// from len(results)), and Properties survive (Section 8.2.2).
	want := &authzen.PageResponse{
		NextToken:  "a3M9NDU2O3N6PTI=",
		Count:      7,
		Total:      99,
		Properties: map[string]any{"sort": "asc"},
	}
	p, err := pageResponseToProto(want)
	if err != nil {
		t.Fatalf("pageResponseToProto: %v", err)
	}
	got := pageResponseFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestPageResponsePresentButEmptyRoundTrips(t *testing.T) {
	// A present-but-empty page is the end-of-results marker (next_token=""
	// with everything else zero). It MUST NOT collapse into an absent page
	// (Section 8.2.2): the nullable PageResponse message preserves presence.
	want := &authzen.PageResponse{}
	p, err := pageResponseToProto(want)
	if err != nil {
		t.Fatalf("pageResponseToProto: %v", err)
	}
	if p == nil {
		t.Fatal("present-but-empty page must serialize to a non-nil message")
	}
	got := pageResponseFromProto(p)
	if got == nil {
		t.Fatal("present-but-empty page collapsed to nil on the inverse conversion")
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestSubjectSearchResponseEmptyPageRoundTrips(t *testing.T) {
	// End-to-end through a search response: a present-but-empty page (final
	// page) survives the round-trip rather than vanishing.
	want := authzen.SubjectSearchResponse{
		Page:    &authzen.PageResponse{},
		Results: []authzen.Subject{{Type: "user", ID: "alice@example.com"}},
	}
	p, err := subjectSearchResponseToProto(want)
	if err != nil {
		t.Fatalf("subjectSearchResponseToProto: %v", err)
	}
	got := subjectSearchResponseFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestResourceSearchResponseRoundTripCountDiffersFromResults(t *testing.T) {
	// Count is carried independently of the number of results, proving it is
	// not reconstructed from len(results).
	want := authzen.ResourceSearchResponse{
		Page: &authzen.PageResponse{NextToken: "next", Count: 1, Total: 50},
		Results: []authzen.Resource{
			{Type: "document", ID: "a"},
			{Type: "document", ID: "b"},
		},
	}
	p, err := resourceSearchResponseToProto(want)
	if err != nil {
		t.Fatalf("resourceSearchResponseToProto: %v", err)
	}
	got := resourceSearchResponseFromProto(p)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %#v\n  got %#v", want, got)
	}
}

func TestPageFromProtoNilWhenEmpty(t *testing.T) {
	if got := pageFromProto(0, "", nil); got != nil {
		t.Fatalf("pageFromProto with no data = %#v; want nil", got)
	}
}
