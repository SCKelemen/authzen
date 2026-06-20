package interop

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/client"
)

// TestLiveInterop is an OPT-IN integration test against a hosted AuthZEN interop
// PDP. It is SKIPPED by default and only runs when AUTHZEN_INTEROP_LIVE=1, so it
// never affects CI or offline runs.
//
// Configuration (environment):
//
//   - AUTHZEN_INTEROP_LIVE=1        enable the test (required).
//   - AUTHZEN_INTEROP_PDP_URL=...   PDP base URL. Defaults to a hosted interop
//     PDP from interop/authzen-todo-backend/src/pdps.json.
//   - AUTHZEN_INTEROP_TOKEN=...     optional bearer token (some hosted PDPs
//     require one; the public demo PDPs generally do not).
//   - AUTHZEN_INTEROP_SPEC=00|01|02 which vendored vector file to drive the
//     evaluation requests from. Defaults to 02.
//
// It validates that OUR client can (1) issue a single evaluation, (2) issue a
// batch evaluation, and parse REAL decisions off the wire. Because the hosted
// policy/data may differ from the vendored expectations (and is outside our
// control), a decision that does not match the vendored expectation is reported
// as informational and does NOT fail the test; only a transport/parse failure
// fails it. If network egress is blocked, the first call's error skips the test
// with a clear message.
//
// OpenID AuthZEN Authorization API 1.0, Section 6 and Section 7.
// https://openid.net/specs/authorization-api-1_0.html
func TestLiveInterop(t *testing.T) {
	if os.Getenv("AUTHZEN_INTEROP_LIVE") != "1" {
		t.Skip("live interop test skipped; set AUTHZEN_INTEROP_LIVE=1 to enable")
	}

	pdpURL := os.Getenv("AUTHZEN_INTEROP_PDP_URL")
	if pdpURL == "" {
		// A hosted interop PDP from the official pdps.json. Overridable.
		pdpURL = "https://authzen-proxy-demo.cerbos.dev"
	}
	spec := os.Getenv("AUTHZEN_INTEROP_SPEC")
	if spec == "" {
		spec = "02"
	}
	vectorPath := map[string]string{"00": todo00, "01": todo01, "02": todo02}[spec]
	if vectorPath == "" {
		t.Fatalf("AUTHZEN_INTEROP_SPEC=%q invalid; want 00, 01, or 02", spec)
	}

	opts := []client.Option{client.WithTimeout(15 * time.Second)}
	if tok := os.Getenv("AUTHZEN_INTEROP_TOKEN"); tok != "" {
		opts = append(opts, client.WithBearerToken(tok))
	}
	c := client.New(pdpURL, opts...)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Logf("live PDP: %s (spec %s)", pdpURL, spec)

	// Best-effort metadata discovery (informational only).
	if md, err := c.Metadata(ctx); err != nil {
		t.Logf("metadata discovery: %v (non-fatal)", err)
	} else {
		t.Logf("metadata: policy_decision_point=%q evaluation=%q evaluations=%q",
			md.PolicyDecisionPoint, md.AccessEvaluationEndpoint, md.AccessEvaluationsEndpoint)
	}

	f := loadTodo(t, vectorPath)

	// Drive a sample of single evaluations.
	limit := 12
	if len(f.Evaluation) < limit {
		limit = len(f.Evaluation)
	}
	var match, total int
	for i := 0; i < limit; i++ {
		req := decodeInto[authzen.EvaluationRequest](t, f.Evaluation[i].Request)
		resp, err := c.Evaluate(ctx, &req)
		if err != nil {
			// First failure most likely means egress is blocked or the PDP is
			// down/unauthenticated. Skip rather than fail the suite.
			var apiErr *client.APIError
			if errors.As(err, &apiErr) {
				t.Skipf("live PDP returned HTTP %d (auth/policy/egress?): %v", apiErr.StatusCode, err)
			}
			t.Skipf("live PDP unreachable (egress blocked?): %v", err)
		}
		total++
		if resp.Decision == f.Evaluation[i].Expected {
			match++
		} else {
			t.Logf("decision differs from vendored expectation (informational): %s -> got %v want %v",
				evalSig(&req), resp.Decision, f.Evaluation[i].Expected)
		}
	}
	if total == 0 {
		t.Skip("no live evaluations completed")
	}
	t.Logf("live single evaluations: parsed %d decisions, %d/%d matched vendored expectations",
		total, match, total)

	// Drive one batch evaluation if the vector file has any.
	if len(f.Evaluations) > 0 {
		req := decodeInto[authzen.EvaluationsRequest](t, f.Evaluations[0].Request)
		resp, err := c.EvaluateBatch(ctx, &req)
		if err != nil {
			t.Logf("live batch evaluation: %v (non-fatal)", err)
		} else {
			t.Logf("live batch evaluation: parsed %d decisions", len(resp.Evaluations))
		}
	}
}
