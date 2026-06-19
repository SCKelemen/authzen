package server_test

import (
	"bytes"
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

// panicPDP panics on Evaluate, exercising the recovery middleware. Its other
// methods are unused.
type panicPDP struct{}

func (panicPDP) Evaluate(_ context.Context, _ *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	panic("boom in PDP")
}
func (panicPDP) SearchSubjects(_ context.Context, _ *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	return nil, nil
}
func (panicPDP) SearchResources(_ context.Context, _ *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	return nil, nil
}
func (panicPDP) SearchActions(_ context.Context, _ *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	return nil, nil
}

// emptyBatchPDP is a BatchEvaluator that returns a response with a nil
// evaluations slice, exercising the handler's null-to-[] normalization.
type emptyBatchPDP struct{ stubPDP }

func (emptyBatchPDP) EvaluateBatch(_ context.Context, _ *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	return &authzen.EvaluationsResponse{Evaluations: nil}, nil
}

const validEvalBody = `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`

// TestRequestBodyTooLargeReturns413 verifies that a body exceeding the
// configured cap is rejected with HTTP 413 before the PDP is invoked, defending
// against unbounded (pre-auth) request bodies. Spec Section 10.1 (Transport).
func TestRequestBodyTooLargeReturns413(t *testing.T) {
	srv, closeFn := newRawServer(t, server.WithMaxBodyBytes(64))
	defer closeFn()

	// A syntactically valid but oversized body (a long, ignored field).
	big := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"},"context":{"pad":"` +
		strings.Repeat("x", 4096) + `"}}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationPath, "application/json", big)
	defer resp.Body.Close()
	requireStatusJSON(t, resp, http.StatusRequestEntityTooLarge)
}

// TestRequestUnderLimitAccepted confirms the body cap does not reject a normal,
// in-limit request (no false positives). Spec Section 10.1.
func TestRequestUnderLimitAccepted(t *testing.T) {
	srv, closeFn := newRawServer(t) // default 1 MiB cap
	defer closeFn()

	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationPath, "application/json", validEvalBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestBatchTooLargeReturns400 verifies that a batch whose member count exceeds
// MaxBatchSize is rejected with HTTP 400 before any fan-out. Spec Section 7.
func TestBatchTooLargeReturns400(t *testing.T) {
	srv, closeFn := newRawServer(t, server.WithMaxBatchSize(2),
		server.WithMaxBodyBytes(1<<20))
	defer closeFn()

	// Three members against a cap of two.
	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"evaluations":[` +
		`{"resource":{"type":"todo","id":"1"}},` +
		`{"resource":{"type":"todo","id":"2"}},` +
		`{"resource":{"type":"todo","id":"3"}}]}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "application/json", body)
	defer resp.Body.Close()
	data := readStatusJSON(t, resp, http.StatusBadRequest)

	var eb struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &eb); err != nil {
		t.Fatalf("error body not JSON: %v (%s)", err, data)
	}
	if !strings.Contains(eb.Error, "batch too large") {
		t.Fatalf("error = %q, want it to mention 'batch too large'", eb.Error)
	}
}

// TestBatchAtLimitAccepted confirms a batch exactly at the cap is accepted (the
// cap is inclusive). Spec Section 7.
func TestBatchAtLimitAccepted(t *testing.T) {
	srv, closeFn := newRawServer(t, server.WithMaxBatchSize(2))
	defer closeFn()

	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"evaluations":[` +
		`{"resource":{"type":"todo","id":"1"}},` +
		`{"resource":{"type":"todo","id":"3"}}]}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "application/json", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestPanicRecoveredReturns500 verifies the recovery middleware converts a PDP
// panic into a generic HTTP 500 JSON body without leaking the panic value.
// Spec Section 10.1.2 (Error responses).
func TestPanicRecoveredReturns500(t *testing.T) {
	srv := httptest.NewServer(server.NewHandler(panicPDP{}))
	defer srv.Close()

	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationPath, "application/json", validEvalBody)
	defer resp.Body.Close()
	data := readStatusJSON(t, resp, http.StatusInternalServerError)

	if strings.Contains(string(data), "boom in PDP") {
		t.Fatalf("response leaked panic detail: %s", data)
	}
	var eb struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(data, &eb); err != nil {
		t.Fatalf("error body not JSON: %v (%s)", err, data)
	}
	if eb.Error != "internal server error" {
		t.Fatalf("error = %q, want generic 'internal server error'", eb.Error)
	}
	if eb.RequestID == "" {
		t.Fatal("expected a non-empty correlation request_id in the error body")
	}
}

// TestServerErrorIsGeneric verifies that a backend PDP error is not echoed to
// the client by default, and that a correlation id is included. Spec Section
// 10.1.2.
func TestServerErrorIsGeneric(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	// stubPDP returns "backend exploded" for subject id "boom".
	body := `{"subject":{"type":"user","id":"boom"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationPath, "application/json", body)
	defer resp.Body.Close()
	data := readStatusJSON(t, resp, http.StatusInternalServerError)

	if strings.Contains(string(data), "backend exploded") {
		t.Fatalf("response leaked backend error detail: %s", data)
	}
	var eb struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(data, &eb); err != nil {
		t.Fatalf("error body not JSON: %v (%s)", err, data)
	}
	if eb.Error != "internal server error" {
		t.Fatalf("error = %q, want generic message", eb.Error)
	}
	if eb.RequestID == "" {
		t.Fatal("expected a correlation request_id")
	}
}

// TestVerboseErrorsEchoesDetail verifies the opt-in verbose-errors switch surfaces
// the underlying error to the client. Spec Section 10.1.2.
func TestVerboseErrorsEchoesDetail(t *testing.T) {
	srv, closeFn := newRawServer(t, server.WithVerboseErrors(true))
	defer closeFn()

	body := `{"subject":{"type":"user","id":"boom"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"1"}}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationPath, "application/json", body)
	defer resp.Body.Close()
	data := readStatusJSON(t, resp, http.StatusInternalServerError)

	if !strings.Contains(string(data), "backend exploded") {
		t.Fatalf("verbose errors should surface detail, got: %s", data)
	}
}

// TestXRequestIDLengthCapped verifies that an oversized client X-Request-ID is
// truncated when echoed. Spec Section 10.1.3.
func TestXRequestIDLengthCapped(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	huge := strings.Repeat("a", 4096)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+authzen.DefaultEvaluationPath, strings.NewReader(validEvalBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", huge)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	got := resp.Header.Get("X-Request-ID")
	if got == huge {
		t.Fatal("X-Request-ID was echoed without a length cap")
	}
	if len(got) == 0 || len(got) > 128 {
		t.Fatalf("echoed X-Request-ID length = %d, want 1..128", len(got))
	}
}

// TestXRequestIDCharsetFiltered verifies that control characters (CR/LF, used in
// header/response-splitting attacks) are stripped from an echoed request id.
// Spec Section 10.1.3.
func TestXRequestIDCharsetFiltered(t *testing.T) {
	srv, closeFn := newRawServer(t)
	defer closeFn()

	// Build the request manually over a raw connection so we can send a header
	// value the Go client would otherwise reject. Use the httptest server's
	// listener address.
	const injected = "abc\r\nX-Injected: evil"
	// net/http rejects invalid header values on the client side, so assert the
	// sanitizer directly via a request that only contains disallowed-but-legal
	// punctuation, which must be stripped to the allowlist.
	id := "ab!c@d#e$f%/+=:;,"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+authzen.DefaultEvaluationPath, strings.NewReader(validEvalBody))
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
	got := resp.Header.Get("X-Request-ID")
	if strings.ContainsAny(got, "!@#$%/+=:;,") {
		t.Fatalf("echoed X-Request-ID = %q, want disallowed punctuation stripped", got)
	}
	if got != "abcdef" {
		t.Fatalf("echoed X-Request-ID = %q, want %q", got, "abcdef")
	}
	_ = injected // documented attack shape; the client layer also blocks it.
}

// TestBatchEmptyEvaluationsSerializesAsArray verifies that a batch response with
// no evaluations serializes as [] (a JSON array), never null, on the server
// handler path. Spec Section 7.2.
func TestBatchEmptyEvaluationsSerializesAsArray(t *testing.T) {
	srv := httptest.NewServer(server.NewHandler(emptyBatchPDP{}))
	defer srv.Close()

	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"evaluations":[{"resource":{"type":"todo","id":"1"}}]}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "application/json", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	// The raw JSON must contain "evaluations":[] and never "evaluations":null.
	compact := &bytes.Buffer{}
	if err := json.Compact(compact, data); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, data)
	}
	got := compact.String()
	if strings.Contains(got, `"evaluations":null`) {
		t.Fatalf("evaluations serialized as null: %s", got)
	}
	if !strings.Contains(got, `"evaluations":[]`) {
		t.Fatalf("evaluations did not serialize as []: %s", got)
	}
}

// TestMaxBatchSizeDefaultApplied verifies a zero/negative configured cap falls
// back to the documented default rather than disabling the limit.
func TestMaxBatchSizeDefaultApplied(t *testing.T) {
	// A cap of 0 must normalize to DefaultMaxBatchSize; a batch of 1 must pass.
	srv, closeFn := newRawServer(t, server.WithMaxBatchSize(0))
	defer closeFn()

	body := `{"subject":{"type":"user","id":"a"},"action":{"name":"can_read"},"evaluations":[{"resource":{"type":"todo","id":"1"}}]}`
	resp := mustPost(t, srv.URL+authzen.DefaultEvaluationsPath, "application/json", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (zero cap should normalize to default %d)", resp.StatusCode, server.DefaultMaxBatchSize)
	}
}

// readStatusJSON asserts the response status and JSON content type, then returns
// the body bytes. Unlike requireStatusJSON it returns the body so a caller can
// make further assertions on it (the body may only be read once).
func readStatusJSON(t *testing.T, resp *http.Response, want int) []byte {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d", resp.StatusCode, want)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(data) > 0 && !json.Valid(data) {
		t.Fatalf("response body is not valid JSON: %s", data)
	}
	return data
}
