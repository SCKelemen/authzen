package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// recordingTransport is a stub http.RoundTripper that records whether it was
// invoked and the Authorization header it observed, returning a canned allow
// response. It lets the transport-security tests assert behavior without a real
// network or a reachable (non-loopback) host.
type recordingTransport struct {
	called  bool
	gotAuth string
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.called = true
	rt.gotAuth = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"decision":true}`)),
		Request:    req,
	}, nil
}

// TestBearerTokenRejectedOverHTTP verifies the P0 fix: with a credential
// configured, a non-https, non-loopback base URL is rejected before any request
// is sent (the token is never put on the wire). Spec Section 11.1 (TLS).
func TestBearerTokenRejectedOverHTTP(t *testing.T) {
	rt := &recordingTransport{}
	c := New("http://pdp.example.com",
		WithBearerToken("supersecret"),
		WithHTTPClient(&http.Client{Transport: rt}),
	)
	_, err := c.Evaluate(context.Background(), validEval())
	if err == nil {
		t.Fatal("expected refusal to send bearer token over http")
	}
	if !strings.Contains(err.Error(), "refusing to send bearer token") {
		t.Fatalf("error = %v, want a refusal message", err)
	}
	if rt.called {
		t.Fatal("transport was invoked despite the http+token refusal")
	}
}

// TestBearerTokenAllowedOverHTTPWithOptOut verifies the explicit opt-out:
// WithInsecureAllowHTTP re-enables sending the token over http, and the token is
// then forwarded in the Authorization header.
func TestBearerTokenAllowedOverHTTPWithOptOut(t *testing.T) {
	rt := &recordingTransport{}
	c := New("http://pdp.example.com",
		WithBearerToken("supersecret"),
		WithInsecureAllowHTTP(),
		WithHTTPClient(&http.Client{Transport: rt}),
	)
	resp, err := c.Evaluate(context.Background(), validEval())
	if err != nil {
		t.Fatalf("Evaluate with opt-out: %v", err)
	}
	if !resp.Decision {
		t.Fatal("decision = false, want true")
	}
	if !rt.called {
		t.Fatal("transport was not invoked despite opt-out")
	}
	if rt.gotAuth != "Bearer supersecret" {
		t.Fatalf("Authorization = %q, want Bearer supersecret", rt.gotAuth)
	}
}

// TestBearerTokenAllowedOverLoopbackHTTP documents the loopback exception: a
// token may be sent to a loopback http origin (it never leaves the host), so
// local development and tests work without the opt-out.
func TestBearerTokenAllowedOverLoopbackHTTP(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeTestJSON(w, authzen.EvaluationResponse{Decision: true})
	}))
	defer srv.Close()

	c := New(srv.URL, WithBearerToken("looptoken"))
	if _, err := c.Evaluate(context.Background(), validEval()); err != nil {
		t.Fatalf("Evaluate over loopback http: %v", err)
	}
	if gotAuth != "Bearer looptoken" {
		t.Fatalf("Authorization = %q, want Bearer looptoken", gotAuth)
	}
}

// TestStripSensitiveOnRedirect unit-tests the CheckRedirect hook: it strips the
// Authorization header on a scheme downgrade or a cross-host redirect, keeps it
// on a same-origin redirect, and re-imposes the 10-redirect bound.
func TestStripSensitiveOnRedirect(t *testing.T) {
	newReq := func(rawurl string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, rawurl, nil)
		if err != nil {
			t.Fatalf("build request %q: %v", rawurl, err)
		}
		r.Header.Set("Authorization", "Bearer tok")
		return r
	}

	t.Run("downgrade strips", func(t *testing.T) {
		via := []*http.Request{newReq("https://pdp.example.com/a")}
		next := newReq("http://pdp.example.com/b")
		if err := stripSensitiveOnRedirect(next, via); err != nil {
			t.Fatalf("hook err: %v", err)
		}
		if next.Header.Get("Authorization") != "" {
			t.Fatal("Authorization not stripped on https->http downgrade")
		}
	})

	t.Run("cross-host strips", func(t *testing.T) {
		via := []*http.Request{newReq("https://pdp.example.com/a")}
		next := newReq("https://evil.example.com/a")
		if err := stripSensitiveOnRedirect(next, via); err != nil {
			t.Fatalf("hook err: %v", err)
		}
		if next.Header.Get("Authorization") != "" {
			t.Fatal("Authorization not stripped on cross-host redirect")
		}
	})

	t.Run("same-origin keeps", func(t *testing.T) {
		via := []*http.Request{newReq("https://pdp.example.com/a")}
		next := newReq("https://pdp.example.com/b")
		if err := stripSensitiveOnRedirect(next, via); err != nil {
			t.Fatalf("hook err: %v", err)
		}
		if next.Header.Get("Authorization") != "Bearer tok" {
			t.Fatal("Authorization wrongly stripped on same-origin redirect")
		}
	})

	t.Run("redirect bound", func(t *testing.T) {
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = newReq("https://pdp.example.com/")
		}
		if err := stripSensitiveOnRedirect(newReq("https://pdp.example.com/x"), via); err == nil {
			t.Fatal("expected an error after 10 redirects")
		}
	})
}

// TestRedirectStripsAuthorizationEndToEnd verifies the hook is wired into the
// client: a cross-host redirect drops the bearer token before the second hop,
// so the redirect target never sees the Authorization header. Both servers are
// loopback http (different ports => different hosts), which both permits the
// token (loopback) and triggers the cross-host strip.
func TestRedirectStripsAuthorizationEndToEnd(t *testing.T) {
	var targetAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetAuth = r.Header.Get("Authorization")
		writeTestJSON(w, authzen.EvaluationResponse{Decision: true})
	}))
	defer target.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redir.Close()

	c := New(redir.URL, WithBearerToken("tok"))
	if _, err := c.Evaluate(context.Background(), validEval()); err != nil {
		t.Fatalf("Evaluate through redirect: %v", err)
	}
	if targetAuth != "" {
		t.Fatalf("redirect target saw Authorization %q, want it stripped", targetAuth)
	}
}

// TestRedirectKeepsAuthorizationSameOrigin verifies the hook does not over-strip:
// a same-origin redirect preserves the Authorization header so legitimate
// in-PDP redirects keep working.
func TestRedirectKeepsAuthorizationSameOrigin(t *testing.T) {
	var finalAuth string
	mux := http.NewServeMux()
	mux.HandleFunc(authzen.DefaultEvaluationPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalAuth = r.Header.Get("Authorization")
		writeTestJSON(w, authzen.EvaluationResponse{Decision: true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, WithBearerToken("tok"))
	if _, err := c.Evaluate(context.Background(), validEval()); err != nil {
		t.Fatalf("Evaluate through same-origin redirect: %v", err)
	}
	if finalAuth != "Bearer tok" {
		t.Fatalf("same-origin redirect target Authorization = %q, want Bearer tok", finalAuth)
	}
}

// TestResponseBodyLimited verifies the read is bounded by MaxResponseBytes: a
// 200 body larger than the cap is truncated, which here corrupts the JSON and
// surfaces as a decode error rather than an unbounded read into memory.
func TestResponseBodyLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":true,"reason":"`+strings.Repeat("x", 4096)+`"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxResponseBytes(8))
	_, err := c.Evaluate(context.Background(), validEval())
	if err == nil {
		t.Fatal("expected a decode error from a truncated (capped) body")
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("a capped 200 body should be a decode error, not *APIError: %v", err)
	}
}

// TestAPIErrorBodyCapped verifies that the bytes retained in APIError.Body are
// bounded by maxAPIErrorBodyBytes even when the PDP returns a large error body.
func TestAPIErrorBodyCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("e", maxAPIErrorBodyBytes*4))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Evaluate(context.Background(), validEval())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if len(apiErr.Body) != maxAPIErrorBodyBytes {
		t.Fatalf("APIError.Body length = %d, want capped at %d", len(apiErr.Body), maxAPIErrorBodyBytes)
	}
}

// TestFallbackClientTimeout verifies the fallback HTTP client enforces a finite
// timeout (no infinite hang): a slow PDP trips WithTimeout and the call fails.
func TestFallbackClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		writeTestJSON(w, authzen.EvaluationResponse{Decision: true})
	}))
	defer srv.Close()

	c := New(srv.URL, WithTimeout(10*time.Millisecond))
	_, err := c.Evaluate(context.Background(), validEval())
	if err == nil {
		t.Fatal("expected a timeout error from the fallback client")
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("a timeout should not be an *APIError: %v", err)
	}
}

// TestSameIssuerHardened covers the Section 9.2.3 hardening: userinfo rejected,
// default ports normalized, https required (loopback http allowed), and the
// behavior stays fail-closed for unexpected schemes.
func TestSameIssuerHardened(t *testing.T) {
	cases := []struct {
		name          string
		expected, got string
		want          bool
	}{
		{"userinfo in expected", "https://user:pass@pdp.example.com", "https://pdp.example.com", false},
		{"userinfo in got", "https://pdp.example.com", "https://user@pdp.example.com", false},
		{"default port on got", "https://pdp.example.com", "https://pdp.example.com:443", true},
		{"default port on expected", "https://pdp.example.com:443", "https://pdp.example.com", true},
		{"non-default port differs", "https://pdp.example.com:8443", "https://pdp.example.com", false},
		{"loopback ip http", "http://127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"loopback localhost http", "http://localhost", "http://localhost", true},
		{"http non-loopback rejected", "http://pdp.example.com", "http://pdp.example.com", false},
		{"unsupported scheme", "ftp://pdp.example.com", "ftp://pdp.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameIssuer(tc.expected, tc.got); got != tc.want {
				t.Fatalf("sameIssuer(%q,%q) = %v, want %v", tc.expected, tc.got, got, tc.want)
			}
		})
	}
}
