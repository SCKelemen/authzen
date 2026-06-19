package server_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/client"
	"github.com/SCKelemen/authzen/server"
)

// stubPDP is a deterministic PDP used by the round-trip tests. It permits every
// request except those targeting a resource whose id is "2" (so that a batch of
// resources 1, 2, 3 yields the verbatim decisions true, false, true from the
// specification's Access Evaluations examples), denies when the subject id is
// "deny", and returns a transport error when the subject id is "boom".
type stubPDP struct{}

func (stubPDP) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if req.Subject != nil && req.Subject.ID == "boom" {
		return nil, errors.New("backend exploded")
	}
	deny := (req.Resource != nil && req.Resource.ID == "2") ||
		(req.Subject != nil && req.Subject.ID == "deny")
	return &authzen.EvaluationResponse{Decision: !deny}, nil
}

func (stubPDP) SearchSubjects(_ context.Context, _ *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	// Verbatim from SPEC_NOTES Figure 21 / Figure 33.
	return &authzen.SubjectSearchResponse{
		Page: &authzen.PageResponse{NextToken: "a3M9NDU2O3N6PTI="},
		Results: []authzen.Subject{
			{Type: "user", ID: "alice@example.com"},
			{Type: "user", ID: "bob@example.com"},
		},
	}, nil
}

func (stubPDP) SearchResources(_ context.Context, _ *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	// Verbatim from SPEC_NOTES Figure 23 / Figure 35.
	return &authzen.ResourceSearchResponse{
		Results: []authzen.Resource{
			{Type: "account", ID: "123"},
			{Type: "account", ID: "456"},
		},
	}, nil
}

func (stubPDP) SearchActions(_ context.Context, _ *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	// Verbatim from SPEC_NOTES Figure 25 / Figure 37.
	return &authzen.ActionSearchResponse{
		Results: []authzen.Action{
			{Name: "can_read"},
			{Name: "can_write"},
		},
	}, nil
}

// newTestServer wires the real PDP handler behind an httptest server and returns
// a real client pointed at it.
func newTestServer(t *testing.T, pdp server.PDP, opts ...server.HandlerOption) (*client.Client, func()) {
	t.Helper()
	h := server.NewHandler(pdp, opts...)
	srv := httptest.NewServer(h)
	c := client.New(srv.URL)
	return c, srv.Close
}

// TestEvaluateRoundTrip exercises the Access Evaluation API end to end using the
// verbatim full request fixture (SPEC_NOTES Figure 28). Spec Section 6.
func TestEvaluateRoundTrip(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
		Action:   &authzen.Action{Name: "can_read"},
		Context:  authzen.Context{"time": "1985-10-26T01:22-07:00"},
	}
	resp, err := c.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Matches the verbatim response fixture (Figure 29): {"decision": true}.
	if !resp.Decision {
		t.Fatalf("expected decision true, got false")
	}
}

// TestEvaluateDenyIsSuccess confirms that a deny is a successful HTTP 200 with
// {"decision": false} rather than an HTTP error. Spec Section 10.1.2.
func TestEvaluateDenyIsSuccess(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "deny"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
		Action:   &authzen.Action{Name: "can_read"},
	}
	resp, err := c.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate returned error for a deny (denies must be HTTP 200): %v", err)
	}
	if resp.Decision {
		t.Fatalf("expected decision false")
	}
}

// TestBatchExecuteAll exercises the default execute_all semantic with the
// verbatim batch fixture, expecting all three decisions true, false, true.
// Spec Section 7.1.2.1.
func TestBatchExecuteAll(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticExecuteAll},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	got := decisions(resp)
	want := []bool{true, false, true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("execute_all decisions = %v, want %v", got, want)
	}
}

// TestBatchDenyOnFirstDeny verifies the deny_on_first_deny short-circuit: the
// response stops at and includes the first deny (decisions true, false). Spec
// Section 7.1.2.1.
func TestBatchDenyOnFirstDeny(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticDenyOnFirstDeny},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	got := decisions(resp)
	want := []bool{true, false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deny_on_first_deny decisions = %v, want %v", got, want)
	}
}

// TestBatchPermitOnFirstPermit verifies the permit_on_first_permit short-circuit:
// the response stops at and includes the first permit (a single true). Spec
// Section 7.1.2.1.
func TestBatchPermitOnFirstPermit(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticPermitOnFirstPermit},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	got := decisions(resp)
	want := []bool{true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permit_on_first_permit decisions = %v, want %v", got, want)
	}
}

// TestBatchDefaultsApplied verifies that top-level defaults are applied to each
// member and that a member may override a default (here the action). With
// resources boxcarring.md, subject-search.md, resource-search.md all permitted,
// the result is three trues. Spec Section 7.1.1.
func TestBatchDefaultsApplied(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Context: authzen.Context{"time": "2024-05-31T15:22-07:00"},
		Action:  &authzen.Action{Name: "can_read"},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "boxcarring.md"}},
			{Resource: &authzen.Resource{Type: "document", ID: "subject-search.md"}},
			{
				Action:   &authzen.Action{Name: "can_edit"},
				Resource: &authzen.Resource{Type: "document", ID: "resource-search.md"},
			},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	got := decisions(resp)
	want := []bool{true, true, true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaulted batch decisions = %v, want %v", got, want)
	}
}

// TestSearchSubjectsRoundTrip exercises the Subject Search API with the verbatim
// request fixture (Figure 20/32) and verifies the verbatim results. Spec
// Section 8.4.
func TestSearchSubjectsRoundTrip(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.SubjectSearchRequest{
		Subject:  &authzen.Subject{Type: "user"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	}
	resp, err := c.SearchSubjects(context.Background(), req)
	if err != nil {
		t.Fatalf("SearchSubjects: %v", err)
	}
	want := []authzen.Subject{
		{Type: "user", ID: "alice@example.com"},
		{Type: "user", ID: "bob@example.com"},
	}
	if !reflect.DeepEqual(resp.Results, want) {
		t.Fatalf("subjects = %+v, want %+v", resp.Results, want)
	}
	if resp.Page == nil || resp.Page.NextToken != "a3M9NDU2O3N6PTI=" {
		t.Fatalf("missing/incorrect page next_token: %+v", resp.Page)
	}
}

// TestSearchResourcesRoundTrip exercises the Resource Search API with the
// verbatim request/response fixtures (Figure 22/23). Spec Section 8.5.
func TestSearchResourcesRoundTrip(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.ResourceSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account"},
	}
	resp, err := c.SearchResources(context.Background(), req)
	if err != nil {
		t.Fatalf("SearchResources: %v", err)
	}
	want := []authzen.Resource{
		{Type: "account", ID: "123"},
		{Type: "account", ID: "456"},
	}
	if !reflect.DeepEqual(resp.Results, want) {
		t.Fatalf("resources = %+v, want %+v", resp.Results, want)
	}
}

// TestSearchActionsRoundTrip exercises the Action Search API with the verbatim
// request/response fixtures (Figure 24/25). Spec Section 8.6.
func TestSearchActionsRoundTrip(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.ActionSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
		Context:  authzen.Context{"time": "2024-10-26T01:22-07:00"},
	}
	resp, err := c.SearchActions(context.Background(), req)
	if err != nil {
		t.Fatalf("SearchActions: %v", err)
	}
	want := []authzen.Action{
		{Name: "can_read"},
		{Name: "can_write"},
	}
	if !reflect.DeepEqual(resp.Results, want) {
		t.Fatalf("actions = %+v, want %+v", resp.Results, want)
	}
}

// TestMetadataRoundTrip exercises well-known PDP metadata discovery against the
// verbatim metadata response fixture (Section 9.2.2), with a
// policy_decision_point that matches the discovery origin so the Section 9.2.3
// validation passes. Spec Section 9.
func TestMetadataRoundTrip(t *testing.T) {
	// The metadata's policy_decision_point must match the origin discovery is
	// derived from, so build the server first and then point the document at
	// its URL (Section 9.2.3).
	md := &authzen.Metadata{}
	h := server.NewHandler(stubPDP{}, server.WithMetadata(md))
	srv := httptest.NewServer(h)
	defer srv.Close()

	md.PolicyDecisionPoint = srv.URL
	md.AccessEvaluationEndpoint = srv.URL + authzen.DefaultEvaluationPath
	md.SearchSubjectEndpoint = srv.URL + authzen.DefaultSearchSubjectPath
	md.SearchResourceEndpoint = srv.URL + authzen.DefaultSearchResourcePath

	c := client.New(srv.URL)
	got, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !reflect.DeepEqual(got, md) {
		t.Fatalf("metadata = %+v, want %+v", got, md)
	}
}

// TestPDPErrorMapsTo500 verifies that a PDP error surfaces to the client as an
// *APIError carrying HTTP 500. Spec Section 10.1.2.
func TestPDPErrorMapsTo500(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "boom"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
		Action:   &authzen.Action{Name: "can_read"},
	}
	_, err := c.Evaluate(context.Background(), req)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *client.APIError, got %v", err)
	}
	if apiErr.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", apiErr.StatusCode)
	}
}

// decisions extracts the decision booleans from a batch response in order.
func decisions(resp *authzen.EvaluationsResponse) []bool {
	out := make([]bool, len(resp.Evaluations))
	for i, e := range resp.Evaluations {
		out[i] = e.Decision
	}
	return out
}
