package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/server"
)

// newRawServer returns an httptest server fronting a real PDP handler, for the
// transport-level negative tests that drive raw HTTP.
func newRawServer(t *testing.T, opts ...server.HandlerOption) (*httptest.Server, func()) {
	t.Helper()
	srv := httptest.NewServer(server.NewHandler(stubPDP{}, opts...))
	return srv, srv.Close
}

// assertJSONContentType fails the test unless the response is application/json,
// enforcing the rule that the PDP always answers with JSON. Spec Section 10.1.
func assertJSONContentType(t *testing.T, resp *http.Response) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// TestMalformedJSONReturns400 verifies that a syntactically invalid body yields
// HTTP 400. Spec Section 10.1.1 (missing/invalid input MUST be rejected).
func TestMalformedJSONReturns400(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	resp, err := http.Post(srv.URL+authzen.DefaultEvaluationPath, "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	assertJSONContentType(t, resp)
}

// TestMissingRequiredFieldReturns400 verifies that a structurally valid JSON
// object missing a REQUIRED field (here action) yields HTTP 400. Spec Section
// 10.1.1 (missing required attribute MUST return 400).
func TestMissingRequiredFieldReturns400(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	// subject + resource present, action omitted -> invalid.
	body := `{"subject":{"type":"user","id":"alice@example.com"},"resource":{"type":"todo","id":"1"}}`
	resp, err := http.Post(srv.URL+authzen.DefaultEvaluationPath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	assertJSONContentType(t, resp)

	var eb struct {
		Error string `json:"error"`
	}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &eb); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, data)
	}
	if eb.Error == "" {
		t.Fatalf("expected non-empty error message, got %q", data)
	}
}

// TestGetOnPostEndpointReturns405 verifies that GET on a POST-only endpoint
// yields HTTP 405. Spec Section 10.1 (API requests are POST).
func TestGetOnPostEndpointReturns405(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	resp, err := http.Get(srv.URL + authzen.DefaultEvaluationPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	assertJSONContentType(t, resp)
}

// TestWrongContentTypeReturns415 verifies that a POST without the
// application/json media type yields HTTP 415. Spec Section 10.1 (request
// Content-Type MUST be application/json).
func TestWrongContentTypeReturns415(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`
	resp, err := http.Post(srv.URL+authzen.DefaultEvaluationPath, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", resp.StatusCode)
	}
	assertJSONContentType(t, resp)
}

// TestMissingContentTypeReturns415 verifies that a POST with no Content-Type at
// all yields HTTP 415. Spec Section 10.1.
func TestMissingContentTypeReturns415(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+authzen.DefaultEvaluationPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Explicitly clear any default Content-Type.
	req.Header.Del("Content-Type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", resp.StatusCode)
	}
}

// TestContentTypeWithCharsetAccepted verifies that a parameterized media type
// such as "application/json; charset=utf-8" is accepted. Spec Section 10.1.
func TestContentTypeWithCharsetAccepted(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`
	resp, err := http.Post(srv.URL+authzen.DefaultEvaluationPath, "application/json; charset=utf-8", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestUnknownPathReturns404 verifies that an unregistered path yields a JSON
// HTTP 404. Spec Section 10.1 / Table 1 (only the defined endpoints exist).
func TestUnknownPathReturns404(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	resp, err := http.Post(srv.URL+"/access/v1/nope", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	assertJSONContentType(t, resp)
}

// TestMetadataNotConfiguredReturns404 verifies that the well-known endpoint
// responds 404 when no metadata is configured (discovery unsupported). Spec
// Section 9 (absent metadata).
func TestMetadataNotConfiguredReturns404(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	resp, err := http.Get(srv.URL + authzen.WellKnownConfigurationPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestPostOnMetadataReturns405 verifies that POST on the GET-only metadata
// endpoint yields HTTP 405. Spec Section 9.2.1 (metadata retrieved via GET).
func TestPostOnMetadataReturns405(t *testing.T) {
	md := &authzen.Metadata{
		PolicyDecisionPoint:      "https://pdp.example.com",
		AccessEvaluationEndpoint: "https://pdp.example.com/access/v1/evaluation",
	}
	srv, closeFn := newRawServer(t, server.WithMetadata(md))
	defer closeFn()

	resp, err := http.Post(srv.URL+authzen.WellKnownConfigurationPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// TestXRequestIDEchoed verifies that the PDP echoes a PEP-supplied X-Request-ID
// header in the response. Spec Section 10.1.3.
func TestXRequestIDEchoed(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	const id = "bfe9eb29-ab87-4ca3-be83-a1d5d8305716"
	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+authzen.DefaultEvaluationPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", id)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Request-ID"); got != id {
		t.Fatalf("X-Request-ID = %q, want %q", got, id)
	}
}

// loopBatchOnlyPDP implements PDP but not BatchEvaluator, exercising the default
// EvaluateBatch loop wired by the handler. (stubPDP already lacks
// EvaluateBatch, so this is a focused compile-time check of the contract.)
var _ server.PDP = stubPDP{}

// TestEvaluateBatchDefaultLoopDirect exercises the exported default batch loop
// directly, independent of HTTP. Spec Section 7.1.2.1.
func TestEvaluateBatchDefaultLoopDirect(t *testing.T) {
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
	resp, err := server.EvaluateBatch(context.Background(), stubPDP{}, req)
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	if len(resp.Evaluations) != 2 {
		t.Fatalf("len = %d, want 2 (short-circuit at first deny)", len(resp.Evaluations))
	}
}
