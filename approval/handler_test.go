package approval

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// serve issues a request against a Handler and returns the recorder.
func serve(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) authzen.EvaluationResponse {
	t.Helper()
	var resp authzen.EvaluationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return resp
}

func TestHandlerPollPending(t *testing.T) {
	s := NewStore()
	h := NewHandler(s)
	created, err := s.Create(NewPending(&RequestRef{Type: "payment"}))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec := serve(t, h, http.MethodGet, "/access/v1/approval/"+created.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if ra := rec.Header().Get("Retry-After"); ra != strconv.Itoa(DefaultInterval) {
		t.Fatalf("Retry-After = %q, want %d", ra, DefaultInterval)
	}
	// (L8) A decision must not be cached by clients or intermediaries.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if p := rec.Header().Get("Pragma"); p != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", p)
	}

	resp := decodeResponse(t, rec)
	if resp.Decision {
		t.Fatalf("pending Decision = true, want false")
	}
	a, ok := FromContext(resp.Context)
	if !ok {
		t.Fatalf("response context missing approval")
	}
	if a.Status != StatusPending {
		t.Fatalf("status = %q, want pending", a.Status)
	}
}

func TestHandlerPollTerminalStates(t *testing.T) {
	cases := []struct {
		name         string
		resolve      func(s *Store, id string) error
		wantDecision bool
		wantStatus   Status
		wantRetry    bool
	}{
		{
			name:         "approved",
			resolve:      func(s *Store, id string) error { _, err := s.Approve(id, "m", nil); return err },
			wantDecision: true,
			wantStatus:   StatusApproved,
		},
		{
			name:         "denied",
			resolve:      func(s *Store, id string) error { _, err := s.Deny(id, "m", nil); return err },
			wantDecision: false,
			wantStatus:   StatusDenied,
		},
		{
			name:         "canceled",
			resolve:      func(s *Store, id string) error { _, err := s.Cancel(id); return err },
			wantDecision: false,
			wantStatus:   StatusCanceled,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			h := NewHandler(s)
			created, err := s.Create(nil)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := tc.resolve(s, created.ID); err != nil {
				t.Fatalf("resolve: %v", err)
			}

			rec := serve(t, h, http.MethodGet, "/access/v1/approval/"+created.ID)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Retry-After"); (got != "") != tc.wantRetry {
				t.Fatalf("Retry-After = %q, want present=%v", got, tc.wantRetry)
			}
			resp := decodeResponse(t, rec)
			if resp.Decision != tc.wantDecision {
				t.Fatalf("Decision = %v, want %v", resp.Decision, tc.wantDecision)
			}
			a, ok := FromContext(resp.Context)
			if !ok {
				t.Fatalf("response context missing approval")
			}
			if a.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", a.Status, tc.wantStatus)
			}
		})
	}
}

func TestHandlerNotFound(t *testing.T) {
	s := NewStore()
	h := NewHandler(s)

	rec := serve(t, h, http.MethodGet, "/access/v1/approval/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var e authzen.EvaluationError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if e.Status != http.StatusNotFound {
		t.Fatalf("error.status = %d, want 404", e.Status)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	s := NewStore()
	h := NewHandler(s)
	created, err := s.Create(nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec := serve(t, h, http.MethodPost, "/access/v1/approval/"+created.ID)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandlerPollAfterApproveTransition(t *testing.T) {
	// A poll before approval is pending (deny); after approval is permit. This
	// is the core asynchronous flow.
	s := NewStore()
	h := NewHandler(s)
	created, err := s.Create(nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	first := decodeResponse(t, serve(t, h, http.MethodGet, "/access/v1/approval/"+created.ID))
	if first.Decision {
		t.Fatalf("first poll Decision = true, want false")
	}

	if _, err := s.Approve(created.ID, "mgr@example.com", &Grant{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	second := decodeResponse(t, serve(t, h, http.MethodGet, "/access/v1/approval/"+created.ID))
	if !second.Decision {
		t.Fatalf("second poll Decision = false, want true")
	}
}
