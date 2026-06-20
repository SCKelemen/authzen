package approval

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// normalizeJSON parses arbitrary JSON into a generic value so two encodings can
// be compared independently of key ordering and insignificant whitespace.
func normalizeJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("normalize: %v\ninput: %s", err, b)
	}
	return v
}

// TestApprovalWireFormatConformance asserts the literal on-the-wire field names
// of a fully-populated Approval against a verbatim expected JSON fixture, so a
// regression in any json tag (a renamed or dropped field) fails the test. This
// matches the repo convention of pinning the wire format to the cited specs
// rather than relying solely on a symmetric round-trip.
//
// Field provenance:
//   - expires_in / interval: RFC 8628 Section 3.2 (Device Authorization
//     Response). https://www.rfc-editor.org/rfc/rfc8628#section-3.2
//   - approval_id: the opaque poll handle, analogous to RFC 8628 device_code
//     and CIBA auth_req_id. CIBA Section 7.3.
//     https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
//   - request_ref{type,identifier,locations,actions,datatypes,privileges}:
//     the RFC 9396 authorization_details element shape. RFC 9396 Section 2.
//     https://www.rfc-editor.org/rfc/rfc9396#section-2
//   - reason_user: AuthZEN reason_user convention, Section 5.5.
//     https://openid.net/specs/authorization-api-1_0.html
func TestApprovalWireFormatConformance(t *testing.T) {
	decidedAt := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	expiresAt := time.Date(2025, 1, 2, 4, 4, 5, 0, time.UTC)

	full := &Approval{
		Status:      StatusApproved,
		ID:          "ZXhhbXBsZS1vcGFxdWUtaWQ",
		ExpiresIn:   300,
		Interval:    5,
		PollURL:     "https://pdp.example.com/access/v1/approval/ZXhhbXBsZS1vcGFxdWUtaWQ",
		Delivery:    []string{"poll", "ping", "push"},
		CallbackURL: "https://client.example.com/callback",
		RequestRef: &RequestRef{
			Type:       "payment_initiation",
			Identifier: "acct-123",
			Locations:  []string{"https://api.example.com/accounts/123"},
			Actions:    []string{"transfer"},
			Datatypes:  []string{"balance"},
			Privileges: []string{"admin"},
		},
		Approvers: &Approvers{
			Operator:   "all",
			Stage:      1,
			StageCount: 2,
		},
		Grant:      &Grant{ExpiresAt: &expiresAt},
		DecidedBy:  "manager@example.com",
		DecidedAt:  &decidedAt,
		ReasonUser: authzen.Reasons{"0": "approved by manager"},
	}

	// Verbatim expected wire form. Compared structurally (key order/whitespace
	// insensitive) so this pins every json tag to its exact field name.
	const fixture = `{
  "status": "approved",
  "approval_id": "ZXhhbXBsZS1vcGFxdWUtaWQ",
  "expires_in": 300,
  "interval": 5,
  "poll_url": "https://pdp.example.com/access/v1/approval/ZXhhbXBsZS1vcGFxdWUtaWQ",
  "delivery": ["poll", "ping", "push"],
  "callback_url": "https://client.example.com/callback",
  "request_ref": {
    "type": "payment_initiation",
    "identifier": "acct-123",
    "locations": ["https://api.example.com/accounts/123"],
    "actions": ["transfer"],
    "datatypes": ["balance"],
    "privileges": ["admin"]
  },
  "approvers": {
    "operator": "all",
    "stage": 1,
    "stage_count": 2
  },
  "grant": {
    "expires_at": "2025-01-02T04:04:05Z"
  },
  "decided_by": "manager@example.com",
  "decided_at": "2025-01-02T03:04:05Z",
  "reason_user": {
    "0": "approved by manager"
  }
}`

	out, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if got, want := normalizeJSON(t, out), normalizeJSON(t, []byte(fixture)); !reflect.DeepEqual(got, want) {
		t.Errorf("wire format mismatch\n want: %s\n got:  %s", fixture, out)
	}

	// Belt-and-suspenders: assert each literal field-name token is present, so a
	// silently renamed tag is caught even if a future fixture edit drifts.
	for _, name := range []string{
		`"status"`, `"approval_id"`, `"expires_in"`, `"interval"`, `"poll_url"`,
		`"delivery"`, `"callback_url"`, `"request_ref"`, `"type"`, `"identifier"`,
		`"locations"`, `"actions"`, `"datatypes"`, `"privileges"`, `"approvers"`,
		`"operator"`, `"stage"`, `"stage_count"`, `"grant"`, `"expires_at"`,
		`"decided_by"`, `"decided_at"`, `"reason_user"`,
	} {
		if !bytes.Contains(out, []byte(name)) {
			t.Errorf("expected field name %s missing from wire form: %s", name, out)
		}
	}
}

// TestApprovalOmitsUnsetOptionalFields asserts that a still-pending approval
// (no decision, no grant) omits the optional time-bearing fields entirely
// rather than emitting a zero timestamp. This guards the *time.Time
// omitempty contract: a zero time.Time would otherwise serialize as
// "0001-01-01T00:00:00Z".
func TestApprovalOmitsUnsetOptionalFields(t *testing.T) {
	pending := NewPending(&RequestRef{Type: "payment_initiation", Actions: []string{"transfer"}})

	out, err := json.Marshal(pending)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for _, absent := range []string{
		`"decided_at"`, `"decided_by"`, `"grant"`, `"approvers"`, `"poll_url"`,
		`"callback_url"`, `"reason_user"`, "0001-01-01",
	} {
		if bytes.Contains(out, []byte(absent)) {
			t.Errorf("pending approval should omit %s, got: %s", absent, out)
		}
	}

	// The required and defaulted fields must still be present.
	for _, present := range []string{`"status":"pending"`, `"expires_in":300`, `"interval":5`} {
		if !bytes.Contains(out, []byte(present)) {
			t.Errorf("pending approval missing %s, got: %s", present, out)
		}
	}
}
