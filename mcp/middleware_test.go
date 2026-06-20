package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

const testPRM = "https://api.example.com/.well-known/oauth-protected-resource"

// permit is an Authorizer that always allows.
func permit() Authorizer {
	return AuthorizerFunc(func(context.Context, authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
		return authzen.EvaluationResponse{Decision: true}, nil
	})
}

// denyWith is an Authorizer that always denies with the given decision context.
func denyWith(ctx map[string]any) Authorizer {
	return AuthorizerFunc(func(context.Context, authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
		return authzen.EvaluationResponse{Decision: false, Context: ctx}, nil
	})
}

// failWith is an Authorizer that always returns an infrastructure error.
func failWith(err error) Authorizer {
	return AuthorizerFunc(func(context.Context, authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
		return authzen.EvaluationResponse{}, err
	})
}

// fixedExtractor returns a constant Request (or error) regardless of input.
func fixedExtractor(req Request, err error) RequestExtractor {
	return func(*http.Request) (Request, error) { return req, err }
}

// validRequest is a well-formed authenticated MCP request.
func validRequest() Request {
	return Request{
		Method:            "tools/call",
		ToolName:          "search",
		ServerURI:         "https://mcp.example.com",
		ResourceIndicator: "https://mcp.example.com",
		Token:             TokenClaims{Subject: "alice@example.com", Scopes: []string{"mcp:tools"}},
	}
}

// spyNext records whether the wrapped handler was invoked.
func spyNext() (http.Handler, *bool) {
	called := new(bool)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "next-called")
	})
	return h, called
}

func serve(e *Enforcer, next http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.Handler(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	return rec
}

// TestEnforcerPermit verifies a permit decision passes through to next and
// writes no challenge.
func TestEnforcerPermit(t *testing.T) {
	e := New(permit(), fixedExtractor(validRequest(), nil))
	next, called := spyNext()
	rec := serve(e, next)

	if !*called {
		t.Fatal("next handler was not called on permit")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("unexpected WWW-Authenticate on permit: %q", got)
	}
	if body := rec.Body.String(); body != "next-called" {
		t.Errorf("body = %q, want %q", body, "next-called")
	}
}

// TestEnforcerDeny verifies policy denials emit the correct status, an OAuth
// challenge, and never call next.
func TestEnforcerDeny(t *testing.T) {
	cases := []struct {
		name          string
		opts          []Option
		ctx           map[string]any
		wantStatus    int
		wantContains  []string // substrings required in the WWW-Authenticate header
		wantBodyError string
	}{
		{
			name:          "insufficient_scope from deny context",
			ctx:           DenyContext(InsufficientScope("mcp:tools", testPRM)),
			wantStatus:    http.StatusForbidden,
			wantContains:  []string{`error="insufficient_scope"`, `scope="mcp:tools"`, `resource_metadata="` + testPRM + `"`},
			wantBodyError: ErrorInsufficientScope,
		},
		{
			name:          "unauthorized from deny context",
			ctx:           DenyContext(Unauthorized(testPRM)),
			wantStatus:    http.StatusUnauthorized,
			wantContains:  []string{`resource_metadata="` + testPRM + `"`},
			wantBodyError: ErrorInvalidToken,
		},
		{
			name:          "no context falls back to configured defaults",
			opts:          []Option{WithScope("mcp:tools"), WithResourceMetadata(testPRM)},
			ctx:           nil,
			wantStatus:    http.StatusForbidden,
			wantContains:  []string{`error="insufficient_scope"`, `scope="mcp:tools"`, `resource_metadata="` + testPRM + `"`},
			wantBodyError: ErrorInsufficientScope,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(denyWith(tc.ctx), fixedExtractor(validRequest(), nil), tc.opts...)
			next, called := spyNext()
			rec := serve(e, next)

			if *called {
				t.Fatal("next handler was called on deny (must fail closed)")
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			hdr := rec.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(hdr, "Bearer") {
				t.Errorf("WWW-Authenticate missing Bearer scheme: %q", hdr)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(hdr, want) {
					t.Errorf("WWW-Authenticate %q missing %q", hdr, want)
				}
			}
			var body errorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v (body=%q)", err, rec.Body.String())
			}
			if body.Error != tc.wantBodyError {
				t.Errorf("body error = %q, want %q", body.Error, tc.wantBodyError)
			}
		})
	}
}

// TestEnforcerFailClosed asserts the fail-closed matrix: every pre-evaluation
// error and every Authorizer error denies (with the documented status) and
// never invokes next.
func TestEnforcerFailClosed(t *testing.T) {
	cases := []struct {
		name       string
		authorizer Authorizer
		extract    RequestExtractor
		wantStatus int
	}{
		{
			name:       "extractor ErrNoToken -> 401",
			authorizer: permit(),
			extract:    fixedExtractor(Request{}, ErrNoToken),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "extractor wrapped ErrNoToken -> 401",
			authorizer: permit(),
			extract:    fixedExtractor(Request{}, fmt.Errorf("decode auth header: %w", ErrNoToken)),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "extractor generic error -> 403",
			authorizer: permit(),
			extract:    fixedExtractor(Request{}, errors.New("boom")),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "assembly ErrMissingSubject -> 401",
			authorizer: permit(),
			// Valid method, but the token yields no subject id.
			extract:    fixedExtractor(Request{Method: "tools/list", ServerURI: "https://mcp.example.com"}, nil),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "assembly ErrUnknownMethod -> 403",
			authorizer: permit(),
			extract:    fixedExtractor(Request{Method: "bogus/method", Token: TokenClaims{Subject: "alice@example.com"}}, nil),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "authorizer error -> 403",
			authorizer: failWith(errors.New("pdp unavailable")),
			extract:    fixedExtractor(validRequest(), nil),
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(tc.authorizer, tc.extract, WithResourceMetadata(testPRM))
			next, called := spyNext()
			rec := serve(e, next)

			if *called {
				t.Fatal("next handler was called on a fail-closed error (must deny)")
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if hdr := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(hdr, "Bearer") {
				t.Errorf("WWW-Authenticate missing Bearer scheme: %q", hdr)
			}
		})
	}
}

// TestEnforcerNoHeaderInjection is a security regression: even when the PDP's
// deny context carries CR/LF in a challenge field, the emitted WWW-Authenticate
// header is a single line (control characters are stripped by Challenge.String)
// and no extra header is injected into the response.
//
// RFC 7230 Section 3.2.6 - Field Value Components.
// https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6
func TestEnforcerNoHeaderInjection(t *testing.T) {
	malicious := DenyContext(InsufficientScope("read\r\nX-Injected: 1", testPRM))
	e := New(denyWith(malicious), fixedExtractor(validRequest(), nil))
	next, called := spyNext()
	rec := serve(e, next)

	if *called {
		t.Fatal("next handler was called on deny")
	}
	hdr := rec.Header().Get("WWW-Authenticate")
	if strings.ContainsAny(hdr, "\r\n") {
		t.Fatalf("WWW-Authenticate contains CR/LF: %q", hdr)
	}
	if got := rec.Header().Get("X-Injected"); got != "" {
		t.Fatalf("smuggled header X-Injected was set: %q", got)
	}
}

// TestEnforcerCustomResponder verifies WithErrorResponder fully replaces the
// wire response while enforcement (deny + no pass-through) still holds.
func TestEnforcerCustomResponder(t *testing.T) {
	var gotInfo DenyInfo
	responder := func(w http.ResponseWriter, _ *http.Request, info DenyInfo) {
		gotInfo = info
		w.Header().Set("X-Custom", "1")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "denied")
	}
	e := New(denyWith(DenyContext(InsufficientScope("mcp:tools", testPRM))),
		fixedExtractor(validRequest(), nil),
		WithErrorResponder(responder))
	next, called := spyNext()
	rec := serve(e, next)

	if *called {
		t.Fatal("next handler was called on deny")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if rec.Header().Get("X-Custom") != "1" {
		t.Error("custom responder header not applied")
	}
	if rec.Body.String() != "denied" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "denied")
	}
	if gotInfo.Challenge.Error != ErrorInsufficientScope {
		t.Errorf("DenyInfo.Challenge.Error = %q, want %q", gotInfo.Challenge.Error, ErrorInsufficientScope)
	}
}

// TestNewPanicsOnNilDeps documents that construction fails fast rather than
// silently failing open.
func TestNewPanicsOnNilDeps(t *testing.T) {
	t.Run("nil authorizer", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic on nil Authorizer")
			}
		}()
		New(nil, fixedExtractor(validRequest(), nil))
	})
	t.Run("nil extractor", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic on nil RequestExtractor")
			}
		}()
		New(permit(), nil)
	})
}

// TestChallengeFromDenyContext verifies the inverse of DenyContext, including a
// JSON round trip (numbers decode to float64) and the no-mcp fallback.
func TestChallengeFromDenyContext(t *testing.T) {
	t.Run("round trip in-process", func(t *testing.T) {
		ctx := DenyContext(InsufficientScope("mcp:tools", testPRM))
		got, ok := ChallengeFromDenyContext(ctx)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got.Status != http.StatusForbidden {
			t.Errorf("status = %d, want %d", got.Status, http.StatusForbidden)
		}
		if got.Error != ErrorInsufficientScope || got.Scope != "mcp:tools" || got.ResourceMetadata != testPRM {
			t.Errorf("fields not recovered: %#v", got)
		}
	})

	t.Run("round trip through JSON (float64 status)", func(t *testing.T) {
		raw, err := json.Marshal(DenyContext(Unauthorized(testPRM)))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var ctx map[string]any
		if err := json.Unmarshal(raw, &ctx); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got, ok := ChallengeFromDenyContext(ctx)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got.Status != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", got.Status, http.StatusUnauthorized)
		}
		if got.ResourceMetadata != testPRM {
			t.Errorf("resource_metadata = %q, want %q", got.ResourceMetadata, testPRM)
		}
	})

	t.Run("no mcp object", func(t *testing.T) {
		if _, ok := ChallengeFromDenyContext(map[string]any{"other": 1}); ok {
			t.Error("ok = true, want false for context without mcp object")
		}
		if _, ok := ChallengeFromDenyContext(nil); ok {
			t.Error("ok = true, want false for nil context")
		}
	})

	t.Run("structured fields without header", func(t *testing.T) {
		ctx := map[string]any{"mcp": map[string]any{"status": 401, "error": ErrorInvalidToken}}
		got, ok := ChallengeFromDenyContext(ctx)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got.Status != http.StatusUnauthorized || got.Error != ErrorInvalidToken {
			t.Errorf("fields not recovered: %#v", got)
		}
	})
}
