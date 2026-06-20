package approval

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// allowAny is a permissive validator used by tests that point at an httptest
// server (which speaks http, not https). Production callers should use
// AllowList or an equivalently strict validator.
func allowAny(*url.URL) error { return nil }

// observed is an immutable snapshot of what a callback server recorded.
type observed struct {
	hits        int
	method      string
	contentType string
	accept      string
	body        []byte
}

// capture records what a callback server observed. All access is guarded by mu
// so test assertions and the server goroutine are synchronized under -race.
type capture struct {
	mu  sync.Mutex
	obs observed
}

func (c *capture) snapshot() observed {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.obs
}

// newCaptureServer returns a server that records each request and replies with
// the given status code.
func newCaptureServer(t *testing.T, status int) (*httptest.Server, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c := cap
		c.mu.Lock()
		c.obs.hits++
		c.obs.method = r.Method
		c.obs.contentType = r.Header.Get("Content-Type")
		c.obs.accept = r.Header.Get("Accept")
		c.obs.body = b
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// TestNotifyPing verifies the ping callback: exactly one POST, JSON headers, and
// a minimal {approval_id, status} body (NOT the full decision/context).
//
// OpenID CIBA Core 1.0, Section 10.2 (Ping Callback).
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
func TestNotifyPing(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusNoContent)
	n := NewNotifier(allowAny)

	a := &Approval{
		Status:      StatusApproved,
		ID:          "abc123",
		Delivery:    []string{"ping"},
		CallbackURL: srv.URL + "/cb",
	}
	if err := n.Notify(context.Background(), a); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	obs := cap.snapshot()
	if obs.hits != 1 {
		t.Fatalf("callback hits = %d, want 1", obs.hits)
	}
	if obs.method != http.MethodPost {
		t.Fatalf("method = %q, want POST", obs.method)
	}
	if obs.contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", obs.contentType)
	}
	if obs.accept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", obs.accept)
	}

	var ping pingNotification
	if err := json.Unmarshal(obs.body, &ping); err != nil {
		t.Fatalf("decode ping body %q: %v", obs.body, err)
	}
	if ping.ID != "abc123" || ping.Status != StatusApproved {
		t.Fatalf("ping body = %+v, want {abc123 approved}", ping)
	}
	// The ping notification must NOT carry the full decision/context.
	var generic map[string]any
	if err := json.Unmarshal(obs.body, &generic); err != nil {
		t.Fatalf("decode generic: %v", err)
	}
	if _, leaked := generic["decision"]; leaked {
		t.Fatalf("ping body leaked decision/context: %s", obs.body)
	}
}

// TestNotifyPush verifies the push callback posts the full
// authzen.EvaluationResponse (decision + approval context).
//
// OpenID CIBA Core 1.0, Section 10.3 (Push Callback).
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
func TestNotifyPush(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK)
	n := NewNotifier(allowAny)

	a := &Approval{
		Status:      StatusApproved,
		ID:          "push-1",
		Delivery:    []string{"push"},
		CallbackURL: srv.URL + "/cb",
	}
	if err := n.Notify(context.Background(), a); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	obs := cap.snapshot()
	if obs.hits != 1 {
		t.Fatalf("callback hits = %d, want 1", obs.hits)
	}

	var resp authzen.EvaluationResponse
	if err := json.Unmarshal(obs.body, &resp); err != nil {
		t.Fatalf("decode push body %q: %v", obs.body, err)
	}
	if !resp.Decision {
		t.Fatalf("push decision = false, want true (approved)")
	}
	got, ok := FromContext(resp.Context)
	if !ok {
		t.Fatalf("push body missing approval context: %s", obs.body)
	}
	if got.Status != StatusApproved || got.ID != "push-1" {
		t.Fatalf("push approval = %+v, want approved/push-1", got)
	}
}

// TestNotifyPollIsNoop verifies poll mode (and absent delivery) performs no
// network request.
func TestNotifyPollIsNoop(t *testing.T) {
	cases := map[string][]string{
		"explicit poll": {"poll"},
		"empty":         nil,
		"unknown only":  {"carrier-pigeon"},
	}
	for name, delivery := range cases {
		t.Run(name, func(t *testing.T) {
			srv, cap := newCaptureServer(t, http.StatusOK)
			n := NewNotifier(allowAny)
			a := &Approval{Status: StatusApproved, ID: "x", Delivery: delivery, CallbackURL: srv.URL}
			if err := n.Notify(context.Background(), a); err != nil {
				t.Fatalf("Notify: %v", err)
			}
			if got := cap.snapshot().hits; got != 0 {
				t.Fatalf("poll/none made %d request(s), want 0", got)
			}
		})
	}
}

// TestNotifyFailClosed covers the safe-by-default posture: a nil validator and a
// rejecting validator both refuse to make any network request.
func TestNotifyFailClosed(t *testing.T) {
	cases := map[string]struct {
		validate func(*url.URL) error
		wantErr  error // errors.Is target, or nil to just require non-nil
	}{
		"nil validator (reject-all)": {validate: nil, wantErr: ErrNoValidator},
		"validator rejects":          {validate: func(*url.URL) error { return errors.New("denied by policy") }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, cap := newCaptureServer(t, http.StatusOK)
			n := &Notifier{HTTPClient: srv.Client(), Validate: tc.validate}
			a := &Approval{Status: StatusApproved, ID: "x", Delivery: []string{"push"}, CallbackURL: srv.URL + "/cb"}

			err := n.Notify(context.Background(), a)
			if err == nil {
				t.Fatalf("Notify returned nil error, want fail-closed error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want errors.Is %v", err, tc.wantErr)
			}
			if got := cap.snapshot().hits; got != 0 {
				t.Fatalf("fail-closed still made %d request(s), want 0", got)
			}
		})
	}
}

// TestNotifyMissingCallbackURL verifies a ping/push with no callback_url errors
// without any network I/O.
func TestNotifyMissingCallbackURL(t *testing.T) {
	n := NewNotifier(allowAny)
	a := &Approval{Status: StatusApproved, ID: "x", Delivery: []string{"ping"}}
	if err := n.Notify(context.Background(), a); !errors.Is(err, ErrNoCallbackURL) {
		t.Fatalf("error = %v, want ErrNoCallbackURL", err)
	}
}

// TestNotifyNon2xx verifies a non-2xx callback response is reported as an error.
func TestNotifyNon2xx(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusInternalServerError)
	n := NewNotifier(allowAny)
	a := &Approval{Status: StatusApproved, ID: "x", Delivery: []string{"push"}, CallbackURL: srv.URL + "/cb"}

	err := n.Notify(context.Background(), a)
	if err == nil {
		t.Fatalf("Notify on 500 returned nil error")
	}
	if got := cap.snapshot().hits; got != 1 {
		t.Fatalf("callback hits = %d, want 1", got)
	}
}

// TestNotifyContextCancel verifies Notify honors context cancellation and does
// not hang when the callback endpoint is slow.
func TestNotifyContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stall the response. Return when the client disconnects, or after a
		// bounded fallback so the server's Close() can never hang the test even
		// if cancellation does not propagate to the request context.
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	n := &Notifier{HTTPClient: srv.Client(), Validate: allowAny}
	a := &Approval{Status: StatusApproved, ID: "x", Delivery: []string{"push"}, CallbackURL: srv.URL + "/cb"}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- n.Notify(ctx, a) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("Notify returned nil error on canceled context")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Notify took %v, expected prompt cancellation", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Notify hung past context deadline")
	}
}

// TestNotifyDoesNotFollowRedirects verifies the default client does not follow a
// redirect (an SSRF bypass vector): the redirect target receives zero requests
// and the 3xx is surfaced as a non-2xx error.
func TestNotifyDoesNotFollowRedirects(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/internal", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	// Use the default client (nil HTTPClient) so the default no-follow redirect
	// policy applies.
	n := NewNotifier(allowAny)
	a := &Approval{Status: StatusApproved, ID: "x", Delivery: []string{"push"}, CallbackURL: redirector.URL + "/cb"}

	if err := n.Notify(context.Background(), a); err == nil {
		t.Fatalf("Notify followed redirect / accepted 3xx, want error")
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("redirect target was dereferenced %d time(s), want 0", got)
	}
}

// TestAllowList exercises the recommended baseline validator.
func TestAllowList(t *testing.T) {
	validate := AllowList("hooks.example.com")
	cases := map[string]struct {
		raw     string
		wantErr bool
	}{
		"https allowed host":  {"https://hooks.example.com/cb", false},
		"https case-insens":   {"https://Hooks.Example.COM/cb", false},
		"http rejected":       {"http://hooks.example.com/cb", true},
		"other host rejected": {"https://evil.example.com/cb", true},
		"loopback rejected":   {"https://127.0.0.1/cb", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = validate(u)
			if tc.wantErr != (err != nil) {
				t.Fatalf("validate(%q) err = %v, wantErr = %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

// TestNotifyNilApproval verifies a defensive guard.
func TestNotifyNilApproval(t *testing.T) {
	n := NewNotifier(allowAny)
	if err := n.Notify(context.Background(), nil); !errors.Is(err, ErrNilApproval) {
		t.Fatalf("error = %v, want ErrNilApproval", err)
	}
}
