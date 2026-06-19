package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/client"
	"github.com/SCKelemen/authzen/server"
)

// recordingPDP records the searched-entity ids it receives so tests can assert
// that the handler stripped them per Sections 8.4/8.5.
type recordingPDP struct {
	gotSubjectID  string
	gotResourceID string
}

func (p *recordingPDP) Evaluate(_ context.Context, _ *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{Decision: true}, nil
}

func (p *recordingPDP) SearchSubjects(_ context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	p.gotSubjectID = req.Subject.ID
	return &authzen.SubjectSearchResponse{Results: []authzen.Subject{{Type: "user", ID: "alice@example.com"}}}, nil
}

func (p *recordingPDP) SearchResources(_ context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	p.gotResourceID = req.Resource.ID
	return &authzen.ResourceSearchResponse{Results: []authzen.Resource{{Type: "account", ID: "123"}}}, nil
}

func (p *recordingPDP) SearchActions(_ context.Context, _ *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	return &authzen.ActionSearchResponse{Results: []authzen.Action{{Name: "can_read"}}}, nil
}

// errorPDP fails every method, used to test 500 mapping for search endpoints
// and the request-wide failure path of the batch loop.
type errorPDP struct{}

func (errorPDP) Evaluate(_ context.Context, _ *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return nil, errors.New("backend down")
}
func (errorPDP) SearchSubjects(_ context.Context, _ *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	return nil, errors.New("backend down")
}
func (errorPDP) SearchResources(_ context.Context, _ *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	return nil, errors.New("backend down")
}
func (errorPDP) SearchActions(_ context.Context, _ *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	return nil, errors.New("backend down")
}

// TestSubjectSearchIgnoresID verifies the handler strips a supplied subject id
// before invoking the PDP. Spec Section 8.4 (searched subject carries type only;
// id MUST be ignored).
func TestSubjectSearchIgnoresID(t *testing.T) {
	pdp := &recordingPDP{}
	srv := httptest.NewServer(server.NewHandler(pdp))
	defer srv.Close()

	c := client.New(srv.URL)
	// Send a body with an id present on the searched subject (bypassing the
	// client's typed request, which would normally omit it).
	body := `{"subject":{"type":"user","id":"should-be-ignored"},"action":{"name":"can_read"},"resource":{"type":"account","id":"123"}}`
	resp, err := http.Post(c.BaseURL+authzen.DefaultSearchSubjectPath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if pdp.gotSubjectID != "" {
		t.Fatalf("PDP received subject id %q, want it stripped to empty", pdp.gotSubjectID)
	}
}

// TestResourceSearchIgnoresID verifies the handler strips a supplied resource id
// before invoking the PDP. Spec Section 8.5 (searched resource carries type
// only; id MUST be ignored).
func TestResourceSearchIgnoresID(t *testing.T) {
	pdp := &recordingPDP{}
	srv := httptest.NewServer(server.NewHandler(pdp))
	defer srv.Close()

	body := `{"subject":{"type":"user","id":"alice@example.com"},"action":{"name":"can_read"},"resource":{"type":"account","id":"should-be-ignored"}}`
	resp, err := http.Post(srv.URL+authzen.DefaultSearchResourcePath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if pdp.gotResourceID != "" {
		t.Fatalf("PDP received resource id %q, want it stripped to empty", pdp.gotResourceID)
	}
}

// TestBatchPerMemberErrorExecuteAll verifies that under execute_all a single
// member's backend error becomes a fail-safe closed decision with the error in
// that item's context, while the other members still evaluate. Spec Section
// 7.2.1.
func TestBatchPerMemberErrorExecuteAll(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticExecuteAll},
		Evaluations: []authzen.EvaluationRequest{
			{Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"}, Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Subject: &authzen.Subject{Type: "user", ID: "boom"}, Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"}, Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch must not fail the whole batch for a per-member error: %v", err)
	}
	if len(resp.Evaluations) != 3 {
		t.Fatalf("len = %d, want 3 (all members evaluated)", len(resp.Evaluations))
	}
	if got := []bool{resp.Evaluations[0].Decision, resp.Evaluations[1].Decision, resp.Evaluations[2].Decision}; got[0] != true || got[1] != false || got[2] != true {
		t.Fatalf("decisions = %v, want [true false true]", got)
	}
	if resp.Evaluations[1].Context == nil {
		t.Fatal("errored member should carry an error context")
	}
	if _, ok := resp.Evaluations[1].Context["error"]; !ok {
		t.Fatalf("errored member context = %v, want an 'error' key", resp.Evaluations[1].Context)
	}
}

// TestBatchPerMemberErrorDenyOnFirstDeny verifies that an errored member counts
// as a deny and short-circuits under deny_on_first_deny. Spec Section 7.1.2.1 /
// 7.2.1.
func TestBatchPerMemberErrorDenyOnFirstDeny(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticDenyOnFirstDeny},
		Evaluations: []authzen.EvaluationRequest{
			{Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"}, Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Subject: &authzen.Subject{Type: "user", ID: "boom"}, Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"}, Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	if len(resp.Evaluations) != 2 {
		t.Fatalf("len = %d, want 2 (short-circuit at errored deny)", len(resp.Evaluations))
	}
	if resp.Evaluations[1].Decision {
		t.Fatal("errored member should be a deny (false)")
	}
}

// TestBatchPerMemberErrorPermitOnFirstPermit verifies that an errored member is
// not a permit, so evaluation continues to the next permit. Spec Section
// 7.1.2.1.
func TestBatchPerMemberErrorPermitOnFirstPermit(t *testing.T) {
	c, closeFn := newTestServer(t, stubPDP{})
	defer closeFn()

	req := &authzen.EvaluationsRequest{
		Action:  &authzen.Action{Name: "read"},
		Options: &authzen.Options{EvaluationsSemantic: authzen.SemanticPermitOnFirstPermit},
		Evaluations: []authzen.EvaluationRequest{
			{Subject: &authzen.Subject{Type: "user", ID: "boom"}, Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"}, Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	}
	resp, err := c.EvaluateBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	if len(resp.Evaluations) != 2 {
		t.Fatalf("len = %d, want 2 (errored member not a permit, continue to next)", len(resp.Evaluations))
	}
	if !resp.Evaluations[1].Decision {
		t.Fatal("second member should permit")
	}
}

// TestEvaluateBatchCancelledContextReturnsError verifies that a request-wide
// failure (a cancelled context) aborts the whole batch with an error (HTTP 500
// at the handler), distinct from per-member errors. Spec Section 7.2.1.
func TestEvaluateBatchCancelledContextReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"},
		Action:  &authzen.Action{Name: "read"},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
		},
	}
	_, err := server.EvaluateBatch(ctx, errorPDP{}, req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// --- Negative HTTP tests for the batch endpoint (handleEvaluations) ---

// TestEvaluationsMalformedJSON400 exercises handleEvaluations' decode branch.
// Spec Section 10.1.1.
func TestEvaluationsMalformedJSON400(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "application/json", "{bad json")
	defer resp.Body.Close()
	requireStatusJSON(t, resp, http.StatusBadRequest)
}

// TestEvaluationsMissingFields400 exercises handleEvaluations' validation branch
// (a member with no subject/action). Spec Section 7.1.1 / 10.1.1.
func TestEvaluationsMissingFields400(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "application/json",
		`{"evaluations":[{"resource":{"type":"document","id":"1"}}]}`)
	defer resp.Body.Close()
	requireStatusJSON(t, resp, http.StatusBadRequest)
}

// TestEvaluationsGet405 exercises the method guard on the batch endpoint. Spec
// Section 10.1.
func TestEvaluationsGet405(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	resp, err := http.Get(srv.URL + authzen.DefaultEvaluationsPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	requireStatusJSON(t, resp, http.StatusMethodNotAllowed)
}

// TestEvaluationsWrongContentType415 exercises the media-type guard on the batch
// endpoint. Spec Section 10.1.
func TestEvaluationsWrongContentType415(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "text/plain", `{}`)
	defer resp.Body.Close()
	requireStatusJSON(t, resp, http.StatusUnsupportedMediaType)
}

// --- Negative HTTP tests for the search endpoints (handleSearch*) ---

// TestSearchMalformedJSON400 exercises the decode branch of all three search
// handlers. Spec Section 10.1.1.
func TestSearchMalformedJSON400(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	for _, path := range []string{
		authzen.DefaultSearchSubjectPath,
		authzen.DefaultSearchResourcePath,
		authzen.DefaultSearchActionPath,
	} {
		resp := mustPost(t, srv.URL+path, "application/json", "{bad")
		requireStatusJSON(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	}
}

// TestSearchMissingFields400 exercises the validation branch of all three search
// handlers (empty bodies miss the required entities). Spec Sections 8.4-8.6.
func TestSearchMissingFields400(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	for _, path := range []string{
		authzen.DefaultSearchSubjectPath,
		authzen.DefaultSearchResourcePath,
		authzen.DefaultSearchActionPath,
	} {
		resp := mustPost(t, srv.URL+path, "application/json", "{}")
		requireStatusJSON(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	}
}

// TestSearchGet405 exercises the method guard on the search endpoints. Spec
// Section 10.1.
func TestSearchGet405(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	for _, path := range []string{
		authzen.DefaultSearchSubjectPath,
		authzen.DefaultSearchResourcePath,
		authzen.DefaultSearchActionPath,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		requireStatusJSON(t, resp, http.StatusMethodNotAllowed)
		resp.Body.Close()
	}
}

// TestSearchWrongContentType415 exercises the media-type guard on the search
// endpoints. Spec Section 10.1.
func TestSearchWrongContentType415(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()
	for _, path := range []string{
		authzen.DefaultSearchSubjectPath,
		authzen.DefaultSearchResourcePath,
		authzen.DefaultSearchActionPath,
	} {
		resp := mustPost(t, srv.URL+path, "application/xml", "{}")
		requireStatusJSON(t, resp, http.StatusUnsupportedMediaType)
		resp.Body.Close()
	}
}

// TestSearchPDPError500 verifies that a PDP error on each search endpoint maps
// to HTTP 500. Spec Section 10.1.2.
func TestSearchPDPError500(t *testing.T) {
	srv := httptest.NewServer(server.NewHandler(errorPDP{}))
	defer srv.Close()

	cases := []struct {
		path, body string
	}{
		{authzen.DefaultSearchSubjectPath, `{"subject":{"type":"user"},"action":{"name":"can_read"},"resource":{"type":"account","id":"123"}}`},
		{authzen.DefaultSearchResourcePath, `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"account"}}`},
		{authzen.DefaultSearchActionPath, `{"subject":{"type":"user","id":"a"},"resource":{"type":"account","id":"123"}}`},
	}
	for _, tc := range cases {
		resp := mustPost(t, srv.URL+tc.path, "application/json", tc.body)
		requireStatusJSON(t, resp, http.StatusInternalServerError)
		resp.Body.Close()
	}
}

// mustPost performs a POST and fails the test on a transport error.
func mustPost(t *testing.T, url, contentType, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, contentType, strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

// requireStatusJSON asserts the response status and that the body is JSON.
func requireStatusJSON(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d", resp.StatusCode, want)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 && !json.Valid(data) {
		t.Fatalf("response body is not valid JSON: %s", data)
	}
}
