package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// denyCtxWithStatus builds a deny decision context whose context.mcp.status is
// set to the given (possibly invalid) value, simulating an untrusted
// PDP-supplied status.
func denyCtxWithStatus(status int) map[string]any {
	c := InsufficientScope("mcp:tools", testPRM)
	c.Status = status
	return DenyContext(c)
}

// TestEnforcerDenyStatusClamp verifies that a PDP-supplied deny status is
// clamped to a 4xx/5xx code: a success/redirect or an out-of-range value must
// never reach the wire (the latter would otherwise panic WriteHeader). Values
// outside [400, 599] fall back to 403.
//
// RFC 9110 Section 15 - Status Codes.
// https://www.rfc-editor.org/rfc/rfc9110#section-15
func TestEnforcerDenyStatusClamp(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantStatus int
	}{
		{"ok-200-clamped", 200, http.StatusForbidden},
		{"redirect-302-clamped", 302, http.StatusForbidden},
		{"too-large-1000-clamped", 1000, http.StatusForbidden},
		{"too-small-99-clamped", 99, http.StatusForbidden},
		{"negative-clamped", -1, http.StatusForbidden},
		{"valid-403-kept", http.StatusForbidden, http.StatusForbidden},
		{"valid-503-kept", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(denyWith(denyCtxWithStatus(tc.status)), fixedExtractor(validRequest(), nil))
			next, called := spyNext()

			// A failure to clamp an out-of-range code would panic WriteHeader;
			// serve must complete cleanly.
			rec := serve(e, next)

			if *called {
				t.Fatal("next handler was called on deny")
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("missing WWW-Authenticate header on deny")
			}
		})
	}
}

// TestEnforcerDenyNoStore verifies the default responder marks auth error
// responses as non-cacheable.
//
// RFC 9111 Section 5.2.1.5 - no-store.
// https://www.rfc-editor.org/rfc/rfc9111#section-5.2.1.5
func TestEnforcerDenyNoStore(t *testing.T) {
	e := New(denyWith(DenyContext(InsufficientScope("mcp:tools", testPRM))), fixedExtractor(validRequest(), nil))
	rec := serve(e, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}
}

// TestEnforcerPanicRecover verifies a panic in the extractor or the wrapped
// handler is recovered and converted to a fail-closed 403 deny: a panicking
// authorization path must never escape as an unhandled panic or fall through.
func TestEnforcerPanicRecover(t *testing.T) {
	t.Run("extractor panics", func(t *testing.T) {
		extract := func(*http.Request) (Request, error) { panic("boom in extractor") }
		e := New(permit(), extract)
		next, called := spyNext()

		var rec *httptest.ResponseRecorder
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic escaped Handler: %v", r)
				}
			}()
			rec = serve(e, next)
		}()

		if *called {
			t.Fatal("next handler was called after extractor panic")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got == "" {
			t.Error("missing WWW-Authenticate header on recovered panic")
		}
	})

	t.Run("next panics", func(t *testing.T) {
		e := New(permit(), fixedExtractor(validRequest(), nil))
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom in handler") })

		var rec *httptest.ResponseRecorder
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic escaped Handler: %v", r)
				}
			}()
			rec = serve(e, next)
		}()

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})
}

// TestClampDenyStatus unit-checks the clamp boundaries directly.
func TestClampDenyStatus(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, http.StatusForbidden},
		{200, http.StatusForbidden},
		{399, http.StatusForbidden},
		{400, 400},
		{401, 401},
		{403, 403},
		{599, 599},
		{600, http.StatusForbidden},
		{1000, http.StatusForbidden},
		{-1, http.StatusForbidden},
	}
	for _, tc := range cases {
		if got := clampDenyStatus(tc.in); got != tc.want {
			t.Errorf("clampDenyStatus(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
