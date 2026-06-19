package authzen

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestEvaluationRequestValidate covers the REQUIRED-field rules for a single
// Access Evaluation request: subject (type+id), action (name), resource
// (type+id) MUST all be present.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.1 (Access Evaluation Request)
// and Section 10.1.1 (missing required attribute MUST be rejected).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-request
func TestEvaluationRequestValidate(t *testing.T) {
	valid := func() EvaluationRequest {
		return EvaluationRequest{
			Subject:  &Subject{Type: "user", ID: "alice@example.com"},
			Action:   &Action{Name: "can_read"},
			Resource: &Resource{Type: "account", ID: "123"},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*EvaluationRequest)
		wantErr error // nil means valid
	}{
		{"valid", func(*EvaluationRequest) {}, nil},
		{"missing subject", func(r *EvaluationRequest) { r.Subject = nil }, ErrMissingSubject},
		{"missing subject.type", func(r *EvaluationRequest) { r.Subject.Type = "" }, ErrMissingType},
		{"missing subject.id", func(r *EvaluationRequest) { r.Subject.ID = "" }, ErrMissingID},
		{"missing action", func(r *EvaluationRequest) { r.Action = nil }, ErrMissingAction},
		{"missing action.name", func(r *EvaluationRequest) { r.Action.Name = "" }, ErrMissingName},
		{"missing resource", func(r *EvaluationRequest) { r.Resource = nil }, ErrMissingResource},
		{"missing resource.type", func(r *EvaluationRequest) { r.Resource.Type = "" }, ErrMissingType},
		{"missing resource.id", func(r *EvaluationRequest) { r.Resource.ID = "" }, ErrMissingID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid()
			tc.mutate(&req)
			err := req.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want errors.Is %v", err, tc.wantErr)
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("Validate() error is not a *ValidationError: %v", err)
			}
			if ve.Field == "" {
				t.Errorf("ValidationError.Field is empty for %v", err)
			}
		})
	}
}

// TestEvaluationsRequestValidate covers the batch defaulting/validation rules:
// a member missing subject/action/resource that is not supplied by a top-level
// default MUST fail, and an invalid options.evaluations_semantic MUST fail.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.1 (Defaulting rules) and
// Section 7.1.2.1 (evaluations_semantic).
// https://openid.net/specs/authorization-api-1_0.html
func TestEvaluationsRequestValidate(t *testing.T) {
	t.Run("member missing resource, no default", func(t *testing.T) {
		req := EvaluationsRequest{
			Subject: &Subject{Type: "user", ID: "alice@example.com"},
			Action:  &Action{Name: "can_read"},
			Evaluations: []EvaluationRequest{
				{Resource: &Resource{Type: "document", ID: "1"}},
				{}, // inherits subject+action but has no resource anywhere
			},
		}
		err := req.Validate()
		if !errors.Is(err, ErrMissingResource) {
			t.Fatalf("Validate() = %v, want errors.Is ErrMissingResource", err)
		}
	})

	t.Run("top-level defaults satisfy all members", func(t *testing.T) {
		req := EvaluationsRequest{
			Subject:  &Subject{Type: "user", ID: "alice@example.com"},
			Action:   &Action{Name: "can_read"},
			Resource: &Resource{Type: "document", ID: "default"},
			Evaluations: []EvaluationRequest{
				{Resource: &Resource{Type: "document", ID: "1"}},
				{},
			},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("invalid semantic", func(t *testing.T) {
		req := EvaluationsRequest{
			Subject:     &Subject{Type: "user", ID: "alice@example.com"},
			Action:      &Action{Name: "can_read"},
			Resource:    &Resource{Type: "document", ID: "1"},
			Evaluations: []EvaluationRequest{{}},
			Options:     &Options{EvaluationsSemantic: "sometimes_maybe"},
		}
		if err := req.Validate(); !errors.Is(err, ErrInvalidSemantic) {
			t.Fatalf("Validate() = %v, want errors.Is ErrInvalidSemantic", err)
		}
	})
}

// TestSearchRequestValidate covers the REQUIRED-field rules of each Search API,
// including the type-only requirements and the absence of action in Action
// Search.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.4-8.6 (Search APIs).
// https://openid.net/specs/authorization-api-1_0.html
func TestSearchRequestValidate(t *testing.T) {
	t.Run("subject search valid (type-only subject)", func(t *testing.T) {
		req := SubjectSearchRequest{
			Subject:  &Subject{Type: "user"},
			Action:   &Action{Name: "can_read"},
			Resource: &Resource{Type: "account", ID: "123"},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})
	t.Run("subject search missing subject.type", func(t *testing.T) {
		req := SubjectSearchRequest{
			Subject:  &Subject{},
			Action:   &Action{Name: "can_read"},
			Resource: &Resource{Type: "account", ID: "123"},
		}
		if err := req.Validate(); !errors.Is(err, ErrMissingType) {
			t.Fatalf("Validate() = %v, want errors.Is ErrMissingType", err)
		}
	})
	t.Run("resource search valid (type-only resource)", func(t *testing.T) {
		req := ResourceSearchRequest{
			Subject:  &Subject{Type: "user", ID: "alice@example.com"},
			Action:   &Action{Name: "can_read"},
			Resource: &Resource{Type: "account"},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})
	t.Run("resource search missing action", func(t *testing.T) {
		req := ResourceSearchRequest{
			Subject:  &Subject{Type: "user", ID: "alice@example.com"},
			Resource: &Resource{Type: "account"},
		}
		if err := req.Validate(); !errors.Is(err, ErrMissingAction) {
			t.Fatalf("Validate() = %v, want errors.Is ErrMissingAction", err)
		}
	})
	t.Run("action search valid (no action)", func(t *testing.T) {
		req := ActionSearchRequest{
			Subject:  &Subject{Type: "user", ID: "alice@example.com"},
			Resource: &Resource{Type: "account", ID: "123"},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})
	t.Run("action search missing resource.id", func(t *testing.T) {
		req := ActionSearchRequest{
			Subject:  &Subject{Type: "user", ID: "alice@example.com"},
			Resource: &Resource{Type: "account"},
		}
		if err := req.Validate(); !errors.Is(err, ErrMissingID) {
			t.Fatalf("Validate() = %v, want errors.Is ErrMissingID", err)
		}
	})
}

// TestUnknownFieldsIgnored verifies the forward-compatibility rule: receivers
// MUST ignore unknown members rather than fail.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html
func TestUnknownFieldsIgnored(t *testing.T) {
	const fixture = `{
  "subject": {"type": "user", "id": "alice@example.com", "future_field": 1},
  "action": {"name": "can_read"},
  "resource": {"type": "account", "id": "123"},
  "this_is_unknown": {"nested": true}
}`
	var req EvaluationRequest
	if err := json.Unmarshal([]byte(fixture), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if req.Subject.ID != "alice@example.com" {
		t.Errorf("subject.id = %q, want alice@example.com", req.Subject.ID)
	}
}

// TestValidationErrorMessage verifies the ValidationError surfaces the offending
// field path in its message.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html
func TestValidationErrorMessage(t *testing.T) {
	req := EvaluationRequest{
		Subject:  &Subject{Type: "user"}, // missing id
		Action:   &Action{Name: "can_read"},
		Resource: &Resource{Type: "account", ID: "123"},
	}
	err := req.Validate()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %v", err)
	}
	if ve.Field != "subject.id" {
		t.Errorf("Field = %q, want subject.id", ve.Field)
	}
}
