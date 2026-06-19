package authzen

import (
	"encoding/json"
	"testing"
)

// TestMetadataRoundTrip exercises the PDP configuration document using the
// verbatim spec example.
//
// OpenID AuthZEN Authorization API 1.0, Section 9.2.2 (Metadata response).
// https://openid.net/specs/authorization-api-1_0.html
func TestMetadataRoundTrip(t *testing.T) {
	roundTrip[Metadata](t, `{
  "policy_decision_point": "https://pdp.example.com",
  "access_evaluation_endpoint": "https://pdp.example.com/access/v1/evaluation",
  "search_subject_endpoint": "https://pdp.example.com/access/v1/search/subject",
  "search_resource_endpoint": "https://pdp.example.com/access/v1/search/resource"
}`)
}

// TestMetadataOmitsUnsupportedEndpoints verifies that endpoints with no value
// are omitted from the JSON rather than serialized as null, matching the rule
// that an absent parameter signals an unsupported API.
//
// OpenID AuthZEN Authorization API 1.0, Section 9.1 (Metadata).
// https://openid.net/specs/authorization-api-1_0.html
func TestMetadataOmitsUnsupportedEndpoints(t *testing.T) {
	m := Metadata{
		PolicyDecisionPoint:      "https://pdp.example.com",
		AccessEvaluationEndpoint: "https://pdp.example.com" + DefaultEvaluationPath,
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"access_evaluations_endpoint",
		"search_subject_endpoint",
		"search_resource_endpoint",
		"search_action_endpoint",
		"capabilities",
		"signed_metadata",
	} {
		if _, ok := generic[key]; ok {
			t.Errorf("unset optional field %q should be omitted, got %s", key, out)
		}
	}
	if _, ok := generic["policy_decision_point"]; !ok {
		t.Errorf("required policy_decision_point missing from %s", out)
	}
	if _, ok := generic["access_evaluation_endpoint"]; !ok {
		t.Errorf("required access_evaluation_endpoint missing from %s", out)
	}
}

// TestDefaultPathConstants pins the default request paths defined by Table 1.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport), Table 1.
// https://openid.net/specs/authorization-api-1_0.html
func TestDefaultPathConstants(t *testing.T) {
	want := map[string]string{
		DefaultEvaluationPath:      "/access/v1/evaluation",
		DefaultEvaluationsPath:     "/access/v1/evaluations",
		DefaultSearchSubjectPath:   "/access/v1/search/subject",
		DefaultSearchResourcePath:  "/access/v1/search/resource",
		DefaultSearchActionPath:    "/access/v1/search/action",
		WellKnownConfigurationPath: "/.well-known/authzen-configuration",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("path constant = %q, want %q", got, expected)
		}
	}
	if WellKnownConfigurationSuffix != "authzen-configuration" {
		t.Errorf("suffix = %q, want authzen-configuration", WellKnownConfigurationSuffix)
	}
}
