package approval

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

func TestStatusTerminal(t *testing.T) {
	cases := []struct {
		status Status
		want   bool
	}{
		{StatusPending, false},
		{StatusApproved, true},
		{StatusDenied, true},
		{StatusExpired, true},
		{StatusCanceled, true},
		{Status("unknown"), false},
		{Status(""), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			if got := tc.status.Terminal(); got != tc.want {
				t.Fatalf("Status(%q).Terminal() = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestToContextFromContextRoundTrip(t *testing.T) {
	decidedAt := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	grantExp := time.Date(2025, 1, 2, 4, 4, 5, 0, time.UTC)

	cases := map[string]*Approval{
		"minimal pending": {
			Status:    StatusPending,
			ID:        "abc123",
			ExpiresIn: 300,
			Interval:  5,
		},
		"full approved": {
			Status:      StatusApproved,
			ID:          "xyz789",
			ExpiresIn:   0,
			Interval:    5,
			PollURL:     "https://pdp.example.com/access/v1/approval/xyz789",
			Delivery:    []string{"poll", "ping"},
			CallbackURL: "https://pep.example.com/cb",
			RequestRef: &RequestRef{
				Type:       "payment_initiation",
				Identifier: "acct-42",
				Locations:  []string{"https://api.example.com/accounts"},
				Actions:    []string{"transfer"},
				Datatypes:  []string{"balance"},
				Privileges: []string{"admin"},
			},
			Approvers:  &Approvers{Operator: "all", Stage: 1, StageCount: 2},
			Grant:      &Grant{ExpiresAt: &grantExp},
			DecidedBy:  "manager@example.com",
			DecidedAt:  &decidedAt,
			ReasonUser: authzen.Reasons{"0": "approved by manager"},
		},
		"denied with reason": {
			Status:     StatusDenied,
			ID:         "deny1",
			Interval:   5,
			DecidedBy:  "manager@example.com",
			DecidedAt:  &decidedAt,
			ReasonUser: authzen.Reasons{"403": "policy forbids"},
		},
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := in.ToContext()
			if _, ok := ctx[ContextKey]; !ok {
				t.Fatalf("ToContext() missing key %q", ContextKey)
			}
			// No optional time field that is unset may surface as a zero
			// timestamp on the wire.
			if b, err := json.Marshal(ctx); err != nil {
				t.Fatalf("json.Marshal(ctx): %v", err)
			} else if in.DecidedAt == nil && bytes.Contains(b, []byte("0001-01-01T00:00:00Z")) {
				t.Fatalf("serialized a zero timestamp for an undecided approval: %s", b)
			}
			got, ok := FromContext(ctx)
			if !ok {
				t.Fatalf("FromContext() ok = false, want true")
			}
			assertApprovalEqual(t, in, got)

			// Round-trip through JSON (the wire form) as well.
			b, err := json.Marshal(ctx)
			if err != nil {
				t.Fatalf("json.Marshal(ctx): %v", err)
			}
			var wire map[string]any
			if err := json.Unmarshal(b, &wire); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			got2, ok := FromContext(wire)
			if !ok {
				t.Fatalf("FromContext(wire) ok = false, want true")
			}
			assertApprovalEqual(t, in, got2)
		})
	}
}

func TestFromContextNegative(t *testing.T) {
	cases := map[string]map[string]any{
		"nil context":      nil,
		"missing key":      {"other": 1},
		"nil value":        {ContextKey: nil},
		"wrong type":       {ContextKey: 42},
		"empty status obj": {ContextKey: map[string]any{"approval_id": "x"}},
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			if a, ok := FromContext(ctx); ok {
				t.Fatalf("FromContext() = (%+v, true), want ok=false", a)
			}
		})
	}
}

func TestResponseBuilders(t *testing.T) {
	a := &Approval{Status: StatusPending, ID: "id1", Interval: 5, ExpiresIn: 300}

	cases := []struct {
		name         string
		resp         authzen.EvaluationResponse
		wantDecision bool
		wantStatus   Status
	}{
		{"pending", PendingResponse(withStatus(a, StatusPending)), false, StatusPending},
		{"approved", ApprovedResponse(withStatus(a, StatusApproved)), true, StatusApproved},
		{"denied", DeniedResponse(withStatus(a, StatusDenied)), false, StatusDenied},
		{"expired", ExpiredResponse(withStatus(a, StatusExpired)), false, StatusExpired},
		{"canceled", CanceledResponse(withStatus(a, StatusCanceled)), false, StatusCanceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.resp.Decision != tc.wantDecision {
				t.Fatalf("Decision = %v, want %v", tc.resp.Decision, tc.wantDecision)
			}
			got, ok := FromContext(tc.resp.Context)
			if !ok {
				t.Fatalf("FromContext(resp.Context) ok = false")
			}
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tc.wantStatus)
			}
		})
	}
}

func TestResponseReflectsStatus(t *testing.T) {
	cases := []struct {
		status       Status
		wantDecision bool
	}{
		{StatusPending, false},
		{StatusApproved, true},
		{StatusDenied, false},
		{StatusExpired, false},
		{StatusCanceled, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			resp := Response(&Approval{Status: tc.status, ID: "x"})
			if resp.Decision != tc.wantDecision {
				t.Fatalf("Response(%q).Decision = %v, want %v", tc.status, resp.Decision, tc.wantDecision)
			}
		})
	}
}

func TestNewPendingDefaults(t *testing.T) {
	ref := &RequestRef{Type: "payment_initiation"}
	a := NewPending(ref)
	if a.Status != StatusPending {
		t.Fatalf("Status = %q, want %q", a.Status, StatusPending)
	}
	if a.ExpiresIn != DefaultExpiresIn {
		t.Fatalf("ExpiresIn = %d, want %d", a.ExpiresIn, DefaultExpiresIn)
	}
	if a.Interval != DefaultInterval {
		t.Fatalf("Interval = %d, want %d", a.Interval, DefaultInterval)
	}
	if a.RequestRef != ref {
		t.Fatalf("RequestRef not set")
	}
}

// withStatus returns a shallow copy of a with the given status, so the table
// cases do not mutate the shared base value.
func withStatus(a *Approval, s Status) *Approval {
	c := *a
	c.Status = s
	return &c
}

// assertApprovalEqual compares two approvals, using time.Equal for the time
// fields to avoid spurious monotonic-clock / location mismatches.
func assertApprovalEqual(t *testing.T, want, got *Approval) {
	t.Helper()
	assertTimePtrEqual(t, "DecidedAt", want.DecidedAt, got.DecidedAt)
	if (want.Grant == nil) != (got.Grant == nil) {
		t.Fatalf("Grant presence mismatch: want %v got %v", want.Grant, got.Grant)
	}
	if want.Grant != nil {
		assertTimePtrEqual(t, "Grant.ExpiresAt", want.Grant.ExpiresAt, got.Grant.ExpiresAt)
	}

	// Compare everything else by clearing the time fields already checked above.
	wc, gc := *want, *got
	wc.DecidedAt, gc.DecidedAt = nil, nil
	if wc.Grant != nil {
		g := *wc.Grant
		g.ExpiresAt = nil
		wc.Grant = &g
	}
	if gc.Grant != nil {
		g := *gc.Grant
		g.ExpiresAt = nil
		gc.Grant = &g
	}
	if !reflect.DeepEqual(wc, gc) {
		t.Fatalf("approval mismatch:\n want %+v\n  got %+v", wc, gc)
	}
}

// assertTimePtrEqual compares two *time.Time, treating nil as "unset" and using
// time.Equal for non-nil instants.
func assertTimePtrEqual(t *testing.T, field string, want, got *time.Time) {
	t.Helper()
	if (want == nil) != (got == nil) {
		t.Fatalf("%s presence mismatch: want %v got %v", field, want, got)
	}
	if want != nil && !got.Equal(*want) {
		t.Fatalf("%s = %v, want %v", field, got, want)
	}
}
