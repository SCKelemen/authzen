package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// fixtureMux returns a handler that answers every AuthZEN endpoint with the
// verbatim spec fixtures (SPEC_NOTES Figures 21/23/25/29/31). The well-known
// document's policy_decision_point is derived from the request Host so it
// matches the discovery origin and passes the Section 9.2.3 check.
func fixtureMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(authzen.DefaultEvaluationPath, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.EvaluationResponse{Decision: true})
	})
	mux.HandleFunc(authzen.DefaultEvaluationsPath, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.EvaluationsResponse{Evaluations: []authzen.EvaluationResponse{
			{Decision: true}, {Decision: false}, {Decision: true},
		}})
	})
	mux.HandleFunc(authzen.DefaultSearchSubjectPath, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.SubjectSearchResponse{Results: []authzen.Subject{
			{Type: "user", ID: "alice@example.com"}, {Type: "user", ID: "bob@example.com"},
		}})
	})
	mux.HandleFunc(authzen.DefaultSearchResourcePath, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.ResourceSearchResponse{Results: []authzen.Resource{
			{Type: "account", ID: "123"}, {Type: "account", ID: "456"},
		}})
	})
	mux.HandleFunc(authzen.DefaultSearchActionPath, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.ActionSearchResponse{Results: []authzen.Action{
			{Name: "can_read"}, {Name: "can_write"},
		}})
	})
	mux.HandleFunc(authzen.WellKnownConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.Metadata{
			PolicyDecisionPoint:      "http://" + r.Host,
			AccessEvaluationEndpoint: "http://" + r.Host + authzen.DefaultEvaluationPath,
		})
	})
	return mux
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// status500Handler always responds 500, used to test non-2xx -> *APIError
// mapping for every method (Section 10.1.2).
func status500Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
}

// TestEvaluateBatchHappyPath exercises the client EvaluateBatch happy path.
// Spec Section 7.
func TestEvaluateBatchHappyPath(t *testing.T) {
	srv := httptest.NewServer(fixtureMux())
	defer srv.Close()

	c := New(srv.URL)
	resp, err := c.EvaluateBatch(context.Background(), &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:  &authzen.Action{Name: "read"},
		Evaluations: []authzen.EvaluationRequest{
			{Resource: &authzen.Resource{Type: "document", ID: "1"}},
			{Resource: &authzen.Resource{Type: "document", ID: "2"}},
			{Resource: &authzen.Resource{Type: "document", ID: "3"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	if len(resp.Evaluations) != 3 {
		t.Fatalf("len = %d, want 3", len(resp.Evaluations))
	}
}

// TestSearchHappyPaths exercises SearchSubjects/SearchResources/SearchActions
// happy paths. Spec Sections 8.4-8.6.
func TestSearchHappyPaths(t *testing.T) {
	srv := httptest.NewServer(fixtureMux())
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()

	subs, err := c.SearchSubjects(ctx, &authzen.SubjectSearchRequest{
		Subject:  &authzen.Subject{Type: "user"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	if err != nil || len(subs.Results) != 2 {
		t.Fatalf("SearchSubjects: %v results=%v", err, subs)
	}

	res, err := c.SearchResources(ctx, &authzen.ResourceSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account"},
	})
	if err != nil || len(res.Results) != 2 {
		t.Fatalf("SearchResources: %v results=%v", err, res)
	}

	acts, err := c.SearchActions(ctx, &authzen.ActionSearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	if err != nil || len(acts.Results) != 2 {
		t.Fatalf("SearchActions: %v results=%v", err, acts)
	}
}

// TestMetadataHappyPath exercises Metadata discovery with a matching
// policy_decision_point. Spec Section 9.2 / 9.2.3.
func TestMetadataHappyPath(t *testing.T) {
	srv := httptest.NewServer(fixtureMux())
	defer srv.Close()

	c := New(srv.URL)
	md, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.PolicyDecisionPoint != srv.URL {
		t.Fatalf("policy_decision_point = %q, want %q", md.PolicyDecisionPoint, srv.URL)
	}
}

// TestAllMethodsMapNon2xxToAPIError verifies every method maps a non-2xx PDP
// response to *APIError. Spec Section 10.1.2.
func TestAllMethodsMapNon2xxToAPIError(t *testing.T) {
	srv := httptest.NewServer(status500Handler())
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()

	assertAPIError := func(t *testing.T, name string, err error) {
		t.Helper()
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("%s: expected *APIError, got %T: %v", name, err, err)
		}
		if apiErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("%s: status = %d, want 500", name, apiErr.StatusCode)
		}
	}

	_, err := c.Evaluate(ctx, validEval())
	assertAPIError(t, "Evaluate", err)

	_, err = c.EvaluateBatch(ctx, &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"}, Action: &authzen.Action{Name: "read"},
		Evaluations: []authzen.EvaluationRequest{{Resource: &authzen.Resource{Type: "doc", ID: "1"}}},
	})
	assertAPIError(t, "EvaluateBatch", err)

	_, err = c.SearchSubjects(ctx, &authzen.SubjectSearchRequest{
		Subject: &authzen.Subject{Type: "user"}, Action: &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	assertAPIError(t, "SearchSubjects", err)

	_, err = c.SearchResources(ctx, &authzen.ResourceSearchRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"}, Action: &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "account"},
	})
	assertAPIError(t, "SearchResources", err)

	_, err = c.SearchActions(ctx, &authzen.ActionSearchRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"}, Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	assertAPIError(t, "SearchActions", err)

	_, err = c.Metadata(ctx)
	assertAPIError(t, "Metadata", err)
}

// TestAllMethodsValidateBeforeSend verifies every POST method validates client
// side and does not perform an HTTP request on invalid input. Spec Sections 6-8.
func TestAllMethodsValidateBeforeSend(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()

	expectValidationErr := func(t *testing.T, name string, err error) {
		t.Helper()
		var ve *authzen.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("%s: expected *authzen.ValidationError, got %T: %v", name, err, err)
		}
	}

	// Evaluate: missing action.
	_, err := c.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"}, Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	expectValidationErr(t, "Evaluate", err)

	// EvaluateBatch: invalid options.evaluations_semantic.
	_, err = c.EvaluateBatch(ctx, &authzen.EvaluationsRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"}, Action: &authzen.Action{Name: "read"},
		Resource: &authzen.Resource{Type: "doc", ID: "1"},
		Options:  &authzen.Options{EvaluationsSemantic: "bogus"},
	})
	if !errors.Is(err, authzen.ErrInvalidSemantic) {
		t.Fatalf("EvaluateBatch: expected ErrInvalidSemantic, got %v", err)
	}

	// SearchSubjects: missing subject.
	_, err = c.SearchSubjects(ctx, &authzen.SubjectSearchRequest{
		Action: &authzen.Action{Name: "can_read"}, Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	expectValidationErr(t, "SearchSubjects", err)

	// SearchResources: missing resource.
	_, err = c.SearchResources(ctx, &authzen.ResourceSearchRequest{
		Subject: &authzen.Subject{Type: "user", ID: "a"}, Action: &authzen.Action{Name: "can_read"},
	})
	expectValidationErr(t, "SearchResources", err)

	// SearchActions: missing subject.
	_, err = c.SearchActions(ctx, &authzen.ActionSearchRequest{
		Resource: &authzen.Resource{Type: "account", ID: "123"},
	})
	expectValidationErr(t, "SearchActions", err)

	if called {
		t.Fatal("client performed an HTTP request despite invalid input")
	}
}

// TestNilRequestsRejected verifies that each method rejects a nil request.
func TestNilRequestsRejected(t *testing.T) {
	c := New("http://example.invalid")
	ctx := context.Background()
	if _, err := c.Evaluate(ctx, nil); err == nil {
		t.Fatal("Evaluate(nil) should error")
	}
	if _, err := c.EvaluateBatch(ctx, nil); err == nil {
		t.Fatal("EvaluateBatch(nil) should error")
	}
	if _, err := c.SearchSubjects(ctx, nil); err == nil {
		t.Fatal("SearchSubjects(nil) should error")
	}
	if _, err := c.SearchResources(ctx, nil); err == nil {
		t.Fatal("SearchResources(nil) should error")
	}
	if _, err := c.SearchActions(ctx, nil); err == nil {
		t.Fatal("SearchActions(nil) should error")
	}
}

// TestMetadataValidationMismatch verifies that a policy_decision_point not
// matching the discovery origin is rejected with *MetadataValidationError and
// the document is discarded. Spec Section 9.2.3 (MUST).
func TestMetadataValidationMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.Metadata{
			PolicyDecisionPoint:      "https://evil.example.com",
			AccessEvaluationEndpoint: "https://evil.example.com/access/v1/evaluation",
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	md, err := c.Metadata(context.Background())
	if md != nil {
		t.Fatalf("expected discarded metadata (nil), got %+v", md)
	}
	var mvErr *MetadataValidationError
	if !errors.As(err, &mvErr) {
		t.Fatalf("expected *MetadataValidationError, got %T: %v", err, err)
	}
	if mvErr.Got != "https://evil.example.com" {
		t.Fatalf("Got = %q", mvErr.Got)
	}
}

// TestMetadataValidationSkip verifies that WithInsecureSkipMetadataValidation
// relaxes the Section 9.2.3 check. Spec Section 9.2.3.
func TestMetadataValidationSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.Metadata{
			PolicyDecisionPoint:      "https://evil.example.com",
			AccessEvaluationEndpoint: "https://evil.example.com/access/v1/evaluation",
		})
	}))
	defer srv.Close()

	c := New(srv.URL, WithInsecureSkipMetadataValidation())
	md, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata with skip: %v", err)
	}
	if md.PolicyDecisionPoint != "https://evil.example.com" {
		t.Fatalf("policy_decision_point = %q", md.PolicyDecisionPoint)
	}
}

// TestMetadataExpectedIssuerOverride verifies that WithExpectedIssuer changes
// the identifier the document is validated against. Spec Section 9.2.3.
func TestMetadataExpectedIssuerOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, authzen.Metadata{
			PolicyDecisionPoint:      "https://pdp.example.com",
			AccessEvaluationEndpoint: "https://pdp.example.com/access/v1/evaluation",
		})
	}))
	defer srv.Close()

	c := New(srv.URL, WithExpectedIssuer("https://pdp.example.com"))
	md, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata with expected issuer: %v", err)
	}
	if md.PolicyDecisionPoint != "https://pdp.example.com" {
		t.Fatalf("policy_decision_point = %q", md.PolicyDecisionPoint)
	}
}

// TestSameIssuer covers the origin-comparison helper directly. Spec Section
// 9.2.3.
func TestSameIssuer(t *testing.T) {
	cases := []struct {
		expected, got string
		want          bool
	}{
		{"https://pdp.example.com", "https://pdp.example.com", true},
		{"https://pdp.example.com/", "https://pdp.example.com", true},
		{"https://pdp.example.com", "https://PDP.EXAMPLE.COM", true},
		{"https://pdp.example.com", "http://pdp.example.com", false},
		{"https://pdp.example.com", "https://evil.example.com", false},
		{"https://pdp.example.com/tenant1", "https://pdp.example.com/tenant1/", true},
		{"://bad", "https://pdp.example.com", false},
	}
	for _, tc := range cases {
		if got := sameIssuer(tc.expected, tc.got); got != tc.want {
			t.Errorf("sameIssuer(%q,%q) = %v, want %v", tc.expected, tc.got, got, tc.want)
		}
	}
}

// TestContextCancellationPropagates verifies that a request honors context
// deadlines. Spec Section 10.1 (transport).
func TestContextCancellationPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		writeTestJSON(w, authzen.EvaluationResponse{Decision: true})
	}))
	defer srv.Close()

	c := New(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, err := c.Evaluate(ctx, validEval())
	if err == nil {
		t.Fatal("expected a context deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

// TestPostBadURL covers the request-build error path (an unparseable URL).
func TestPostBadURL(t *testing.T) {
	c := &Client{BaseURL: "http://foo bar.example.com"}
	_, err := c.Evaluate(context.Background(), validEval())
	if err == nil {
		t.Fatal("expected a build-request error for a malformed URL")
	}
}

// TestPostUnreachable covers the transport error path (connection refused).
func TestPostUnreachable(t *testing.T) {
	srv := httptest.NewServer(fixtureMux())
	url := srv.URL
	srv.Close() // close immediately so the port is unreachable

	c := New(url)
	_, err := c.Evaluate(context.Background(), validEval())
	if err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
	// It must not be an APIError (no HTTP response was received).
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("did not expect *APIError for a transport failure, got %v", err)
	}
}

// TestPostNonJSONBody covers the response-decode error path (a 200 whose body
// is not valid JSON). Spec Section 10.1.1.
func TestPostNonJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("}{ not json"))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Evaluate(context.Background(), validEval())
	if err == nil {
		t.Fatal("expected a decode error for a non-JSON 200 body")
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("a 200 with bad JSON should be a decode error, not *APIError: %v", err)
	}
}

// TestGetMetadataBadURL covers the GET request-build error path.
func TestGetMetadataBadURL(t *testing.T) {
	c := &Client{BaseURL: "http://foo bar.example.com"}
	_, err := c.Metadata(context.Background())
	if err == nil {
		t.Fatal("expected a build-request error for a malformed URL")
	}
}

// TestOptionsConfigureClient verifies every functional option mutates the
// Client and that path overrides drive endpoint resolution. Spec Table 1.
func TestOptionsConfigureClient(t *testing.T) {
	hc := &http.Client{}
	c := New("https://pdp.example.com",
		WithHTTPClient(hc),
		WithBearerToken("tok"),
		WithEvaluationPath("/e"),
		WithEvaluationsPath("/es"),
		WithSearchSubjectPath("/ss"),
		WithSearchResourcePath("/sr"),
		WithSearchActionPath("/sa"),
	)
	if c.HTTPClient != hc {
		t.Fatal("WithHTTPClient not applied")
	}
	if c.BearerToken != "tok" {
		t.Fatal("WithBearerToken not applied")
	}
	checks := map[string]string{
		c.EvaluationPath:     "/e",
		c.EvaluationsPath:    "/es",
		c.SearchSubjectPath:  "/ss",
		c.SearchResourcePath: "/sr",
		c.SearchActionPath:   "/sa",
	}
	for got, want := range checks {
		if got != want {
			t.Fatalf("path override = %q, want %q", got, want)
		}
	}
}

// TestMetadataValidationErrorString covers the error message formatting.
func TestMetadataValidationErrorString(t *testing.T) {
	err := &MetadataValidationError{Expected: "https://pdp.example.com", Got: "https://evil.example.com"}
	msg := err.Error()
	if !strings.Contains(msg, "https://evil.example.com") || !strings.Contains(msg, "https://pdp.example.com") {
		t.Fatalf("error message missing identifiers: %q", msg)
	}
	if !strings.Contains(msg, "9.2.3") {
		t.Fatalf("error message should cite Section 9.2.3: %q", msg)
	}
}
