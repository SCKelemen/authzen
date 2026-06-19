package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// validEval returns a minimal valid Access Evaluation request for tests.
func validEval() *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	}
}

// TestEvaluateValidatesBeforeSend verifies that the client rejects an invalid
// request locally (no HTTP call) and returns a ValidationError. Spec Section
// 6.1 (required fields).
func TestEvaluateValidatesBeforeSend(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := New(srv.URL)
	// Missing action -> invalid.
	_, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	var ve *authzen.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *authzen.ValidationError, got %T: %v", err, err)
	}
	if called {
		t.Fatal("client sent an HTTP request despite local validation failure")
	}
}

// TestNon2xxMapsToAPIError verifies that a non-2xx PDP response is mapped to an
// *APIError carrying the status code and body. Spec Section 10.1.2.
func TestNon2xxMapsToAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Evaluate(context.Background(), validEval())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", apiErr.StatusCode)
	}
	if string(apiErr.Body) != `{"error":"boom"}` {
		t.Fatalf("body = %q", apiErr.Body)
	}
}

// TestRequestHeadersAndAuth verifies that the client sends Content-Type and
// Accept of application/json and applies the configured bearer token. Spec
// Section 10.1 and Section 11.2 (RECOMMENDED OAuth 2.0 bearer auth).
func TestRequestHeadersAndAuth(t *testing.T) {
	var (
		gotContentType string
		gotAccept      string
		gotAuth        string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true})
	}))
	defer srv.Close()

	c := New(srv.URL, WithBearerToken("myoauthtoken"))
	if _, err := c.Evaluate(context.Background(), validEval()); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", gotAccept)
	}
	if gotAuth != "Bearer myoauthtoken" {
		t.Fatalf("Authorization = %q, want Bearer myoauthtoken", gotAuth)
	}
}

// TestAuthFuncApplied verifies that a custom auth hook runs and can set headers.
func TestAuthFuncApplied(t *testing.T) {
	var gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true})
	}))
	defer srv.Close()

	c := New(srv.URL, WithAuthFunc(func(req *http.Request) error {
		req.Header.Set("X-API-Key", "secret")
		return nil
	}))
	if _, err := c.Evaluate(context.Background(), validEval()); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if gotAPIKey != "secret" {
		t.Fatalf("X-API-Key = %q, want secret", gotAPIKey)
	}
}

// TestAuthFuncErrorPropagates verifies that an auth hook error aborts the call.
func TestAuthFuncErrorPropagates(t *testing.T) {
	sentinel := errors.New("token refresh failed")
	c := New("http://example.invalid", WithAuthFunc(func(*http.Request) error {
		return sentinel
	}))
	_, err := c.Evaluate(context.Background(), validEval())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
}

// TestEndpointResolution verifies the URL resolution rules: default path appended
// to BaseURL, custom path override, and absolute URL used verbatim. Spec Section
// 10.1 / Table 1.
func TestEndpointResolution(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		custom  string
		def     string
		want    string
	}{
		{"default path", "https://pdp.example.com", "", authzen.DefaultEvaluationPath, "https://pdp.example.com/access/v1/evaluation"},
		{"trailing slash base", "https://pdp.example.com/", "", authzen.DefaultEvaluationPath, "https://pdp.example.com/access/v1/evaluation"},
		{"custom path", "https://pdp.example.com", "/custom/eval", authzen.DefaultEvaluationPath, "https://pdp.example.com/custom/eval"},
		{"absolute url", "https://pdp.example.com", "https://other.example.com/eval", authzen.DefaultEvaluationPath, "https://other.example.com/eval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{BaseURL: tc.baseURL}
			if got := c.endpoint(tc.custom, tc.def); got != tc.want {
				t.Fatalf("endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAPIErrorMessage verifies the human-readable APIError formatting.
func TestAPIErrorMessage(t *testing.T) {
	e := &APIError{StatusCode: 400, Body: []byte("bad request")}
	if got := e.Error(); got == "" {
		t.Fatal("empty error message")
	}
	empty := &APIError{StatusCode: 401}
	if got := empty.Error(); got == "" {
		t.Fatal("empty error message for body-less APIError")
	}
}
