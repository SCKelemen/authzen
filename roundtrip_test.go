package authzen

import (
	"encoding/json"
	"reflect"
	"testing"
)

// normalizeJSON parses arbitrary JSON into a generic value so that two encodings
// can be compared independently of key ordering and insignificant whitespace.
func normalizeJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("normalize: %v\ninput: %s", err, b)
	}
	return v
}

// roundTrip unmarshals a verbatim spec fixture into T, marshals it back, and
// asserts the re-encoded JSON is semantically identical to the fixture. This
// proves the Go types are faithful to the specification's wire format.
func roundTrip[T any](t *testing.T, fixture string) {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(fixture), &v); err != nil {
		t.Fatalf("unmarshal into %T: %v", v, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	want := normalizeJSON(t, []byte(fixture))
	got := normalizeJSON(t, out)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("round-trip mismatch for %T\n fixture: %s\n re-enc:  %s", v, fixture, out)
	}
}

// TestSubjectRoundTrip exercises the Subject information model using the
// verbatim spec fixtures.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.1 (Subject), Figures 1-3.
// https://openid.net/specs/authorization-api-1_0.html
func TestSubjectRoundTrip(t *testing.T) {
	cases := map[string]string{
		"minimal (Figure 1)": `{
  "type": "user",
  "id": "alice@example.com"
}`,
		"with property (Figure 2)": `{
  "type": "user",
  "id": "alice@example.com",
  "properties": {
    "department": "Sales"
  }
}`,
		"ip and device (Figure 3)": `{
  "type": "user",
  "id": "alice@example.com",
  "properties": {
    "ip_address": "172.217.22.14",
    "device_id": "8:65:ee:17:7e:0b"
  }
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[Subject](t, fixture) })
	}
}

// TestResourceRoundTrip exercises the Resource information model.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.2 (Resource), Figures 4-5.
// https://openid.net/specs/authorization-api-1_0.html
func TestResourceRoundTrip(t *testing.T) {
	cases := map[string]string{
		"minimal (Figure 4)": `{
  "type": "book",
  "id": "123"
}`,
		"nested property (Figure 5)": `{
  "type": "book",
  "id": "123",
  "properties": {
    "library_record":{
      "title": "AuthZEN in Action",
      "isbn": "978-0593383322"
    }
  }
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[Resource](t, fixture) })
	}
}

// TestActionRoundTrip exercises the Action information model.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.3 (Action), Figures 6-7.
// https://openid.net/specs/authorization-api-1_0.html
func TestActionRoundTrip(t *testing.T) {
	cases := map[string]string{
		"minimal (Figure 6)": `{
  "name": "can_read"
}`,
		"with properties (Figure 7)": `{
  "name": "extend-loan",
  "properties": {
    "period": "2W"
  }
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[Action](t, fixture) })
	}
}

// TestContextRoundTrip exercises the free-form Context object.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.4 (Context), Figures 8-9.
// https://openid.net/specs/authorization-api-1_0.html
func TestContextRoundTrip(t *testing.T) {
	cases := map[string]string{
		"minimal (Figure 8)": `{
  "time": "1985-10-26T01:22-07:00"
}`,
		"with schema ref (Figure 9)": `{
  "time": "1985-10-26T01:22-07:00",
  "schema": "https://schema.example.com/access-request.schema.json"
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[Context](t, fixture) })
	}
}

// TestEvaluationRequestRoundTrip exercises the full Access Evaluation request.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.1 (Access Evaluation
// Request), Figures 14 and 28.
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-request
func TestEvaluationRequestRoundTrip(t *testing.T) {
	cases := map[string]string{
		"full request (Figure 14)": `{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "resource": {
    "type": "account",
    "id": "123"
  },
  "action": {
    "name": "can_read",
    "properties": {
      "method": "GET"
    }
  },
  "context": {
    "time": "1985-10-26T01:22-07:00"
  }
}`,
		"http body (Figure 28)": `{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "resource": {
    "type": "todo",
    "id": "1"
  },
  "action": {
    "name": "can_read"
  },
  "context": {
    "time": "1985-10-26T01:22-07:00"
  }
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[EvaluationRequest](t, fixture) })
	}
}

// TestEvaluationResponseRoundTrip exercises the Decision response, including the
// non-normative decision-context conventions illustrated by the spec.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5 (Decision) and Section 6.2,
// Figures 10-13 and 29.
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-response
func TestEvaluationResponseRoundTrip(t *testing.T) {
	cases := map[string]string{
		"minimal allow (Figure 10)": `{
  "decision": true
}`,
		"reason admin/user (Figure 11)": `{
  "decision": false,
  "context": {
    "reason_admin": {
      "403": "Request failed policy C076E82F"
    },
    "reason_user": {
      "403": "Insufficient privileges. Contact your administrator"
    }
  }
}`,
		"metadata + environment (Figure 12)": `{
  "decision": false,
  "context": {
    "metadata": {
      "response_time": 60,
      "response_time_unit": "ms"
    },
    "environment": {
      "ip": "10.10.0.1",
      "datetime": "2025-06-27T18:03-07:00",
      "os": "ubuntu24.04.2LTS-AMDx64"
    }
  }
}`,
		"step-up authentication (Figure 13)": `{
  "decision": false,
  "context": {
    "acr_values": "urn:com:example:loa:3",
    "amr_values": "mfa hwk"
  }
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[EvaluationResponse](t, fixture) })
	}
}
