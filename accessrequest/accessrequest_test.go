package accessrequest

import (
	"encoding/json"
	"errors"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// validSubmission returns a single-target submission that satisfies every
// REQUIRED-field rule of Section 10.1, used as the baseline for mutation tests.
//
// AuthZEN Access Request and Approval Profile, Section 10.1 (Access Request
// Submission).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func validSubmission() Submission {
	return Submission{
		Subject:  &Subject{Type: "user", ID: "alice@example.com"},
		Resource: &Resource{Type: "document", ID: "q4-plan"},
		Action:   &Action{Name: "can_read"},
		Denial: &DenialBinding{
			EvaluationID: "eval_01HX4Y2P8BQ4Y3F0V0K9D6Z7M1",
			ExpiresAt:    "2026-04-30T20:25:00Z",
		},
	}
}

// TestSubmissionValidate covers the structural MUST rules: subject is REQUIRED,
// resource/action and items are mutually exclusive with exactly one present,
// and a denial binding MUST cover the request.
//
// AuthZEN Access Request and Approval Profile, Section 10.1.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func TestSubmissionValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Submission)
		wantErr error
	}{
		{"valid", func(*Submission) {}, nil},
		{"missing subject", func(s *Submission) { s.Subject = nil }, authzen.ErrMissingSubject},
		{"missing resource", func(s *Submission) { s.Resource = nil }, authzen.ErrMissingResource},
		{"no target at all", func(s *Submission) { s.Resource = nil; s.Action = nil }, ErrMissingTarget},
		{"missing denial", func(s *Submission) { s.Denial = nil }, ErrMissingDenial},
		{"denial without binding material", func(s *Submission) {
			s.Denial = &DenialBinding{ExpiresAt: "2026-04-30T20:25:00Z"}
		}, ErrMissingDenialBinding},
		{"denial without expires_at", func(s *Submission) {
			s.Denial = &DenialBinding{EvaluationID: "eval_1"}
		}, ErrMissingExpiresAt},
		{"binding_token alone is sufficient", func(s *Submission) {
			s.Denial = &DenialBinding{BindingToken: "ey...", ExpiresAt: "2026-04-30T20:25:00Z"}
		}, nil},
		{"resource and items are exclusive", func(s *Submission) {
			s.Items = []Item{{Resource: s.Resource, Action: s.Action}}
		}, ErrConflictingTargets},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSubmission()
			tc.mutate(&s)
			err := s.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want errors.Is %v", err, tc.wantErr)
			}
			var ve *authzen.ValidationError
			if !errors.As(err, &ve) || ve.Field == "" {
				t.Fatalf("Validate() error is not a populated *authzen.ValidationError: %v", err)
			}
		})
	}
}

// TestBundledSubmissionValidate covers the bundled (items) form: a top-level
// denial may cover items lacking their own binding, and each item MUST carry a
// resource and action.
//
// AuthZEN Access Request and Approval Profile, Section 10.1, items array.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func TestBundledSubmissionValidate(t *testing.T) {
	base := func() Submission {
		return Submission{
			Subject: &Subject{Type: "user", ID: "alice@example.com"},
			Items: []Item{
				{Resource: &Resource{Type: "document", ID: "q4-plan"}, Action: &Action{Name: "can_read"}},
				{Resource: &Resource{Type: "channel", ID: "eng"}, Action: &Action{Name: "can_post"}},
			},
			Denial: &DenialBinding{EvaluationID: "eval_bundle", ExpiresAt: "2026-04-30T20:25:00Z"},
		}
	}

	t.Run("top-level denial covers all items", func(t *testing.T) {
		s := base()
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("per-item denial allows omitted top-level", func(t *testing.T) {
		s := base()
		s.Denial = nil
		for i := range s.Items {
			s.Items[i].Denial = &DenialBinding{EvaluationID: "eval_item", ExpiresAt: "2026-04-30T20:25:00Z"}
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("item without denial and no top-level denial fails", func(t *testing.T) {
		s := base()
		s.Denial = nil
		if err := s.Validate(); !errors.Is(err, ErrMissingDenial) {
			t.Fatalf("Validate() = %v, want errors.Is ErrMissingDenial", err)
		}
	})

	t.Run("item missing action fails", func(t *testing.T) {
		s := base()
		s.Items[1].Action = nil
		if !errors.Is(s.Validate(), authzen.ErrMissingAction) {
			t.Fatalf("Validate() did not reject item missing action")
		}
	})
}

// TestResponseValidate covers the response/task/result/approval REQUIRED-field
// rules, including that an approved item MUST carry an enforceable result.
//
// AuthZEN Access Request and Approval Profile, Sections 10.2, 11.3, and 12.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
func TestResponseValidate(t *testing.T) {
	t.Run("valid synchronous approval", func(t *testing.T) {
		r := Response{
			Task: &Task{ID: "arq_1", Status: StatusApproved, StatusEndpoint: "https://pdp.example.com/r/arq_1"},
			Result: &Result{Mode: ModeReevaluate, Approval: &Approval{
				ID: "apr_1", ApprovedUntil: "2026-05-01T00:42:00Z",
			}},
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("missing task", func(t *testing.T) {
		if !errors.Is((&Response{}).Validate(), ErrMissingTask) {
			t.Fatal("expected ErrMissingTask")
		}
	})

	t.Run("reevaluate result requires approval", func(t *testing.T) {
		if !errors.Is((&Result{Mode: ModeReevaluate}).Validate(), ErrMissingApproval) {
			t.Fatal("expected ErrMissingApproval")
		}
	})

	t.Run("approval requires approved_until", func(t *testing.T) {
		if !errors.Is((&Approval{ID: "apr_1"}).Validate(), ErrMissingApprovedUntil) {
			t.Fatal("expected ErrMissingApprovedUntil")
		}
	})
}

// TestTaskStatusIsTerminal covers the terminal-state classification used by PEP
// polling loops.
//
// AuthZEN Access Request and Approval Profile, Section 11.1.1 (State
// Transitions).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-11.1.1
func TestTaskStatusIsTerminal(t *testing.T) {
	terminal := []TaskStatus{StatusApproved, StatusDenied, StatusExpired, StatusCancelled, StatusFailed, StatusPartial}
	for _, s := range terminal {
		if !s.IsTerminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
	for _, s := range []TaskStatus{StatusPending, TaskStatus("escalated"), ""} {
		if s.IsTerminal() {
			t.Errorf("%q should not be terminal", s)
		}
	}
}

// TestHintAndDenialFromContext covers extraction of the requestable-denial hint
// from a Decision Context and construction of the echoed denial binding, using
// the values echoed unchanged per Section 16.
//
// AuthZEN Access Request and Approval Profile, Sections 7 and 16.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-16
func TestHintAndDenialFromContext(t *testing.T) {
	ctx := map[string]any{
		MemberEvaluationID: "eval_01HX4Y2P8BQ4Y3F0V0K9D6Z7M1",
		MemberEvaluatedAt:  "2026-04-30T20:15:00Z",
		MemberReason:       "approval_required",
		MemberAccessRequest: map[string]any{
			"template":      "manager_approval",
			"expires_at":    "2026-04-30T20:25:00Z",
			"binding_token": "ey.payload.sig",
		},
	}

	h, ok := HintFromContext(ctx)
	if !ok {
		t.Fatal("HintFromContext returned ok=false for a present access_request")
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("Hint.Validate() = %v, want nil", err)
	}

	d := DenialFromHint(h, ctx)
	if d.EvaluationID != "eval_01HX4Y2P8BQ4Y3F0V0K9D6Z7M1" || d.ExpiresAt != "2026-04-30T20:25:00Z" {
		t.Fatalf("DenialFromHint echoed unexpected values: %+v", d)
	}
	if d.Reason != "approval_required" || d.BindingToken != "ey.payload.sig" {
		t.Fatalf("DenialFromHint dropped echoed members: %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("DenialBinding.Validate() = %v, want nil", err)
	}

	if _, ok := HintFromContext(map[string]any{"reason": "denied"}); ok {
		t.Fatal("HintFromContext returned ok=true for a non-requestable denial")
	}
}

// TestSubmissionRoundTrip checks that a submission serializes to the wire shape
// defined by Section 10.1 and decodes back losslessly.
//
// AuthZEN Access Request and Approval Profile, Section 10.1.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func TestSubmissionRoundTrip(t *testing.T) {
	in := validSubmission()
	in.RequestedAccess = &RequestedAccess{RequestedUntil: "2026-05-01T00:15:00Z"}
	in.Context = map[string]any{"business_justification": "renewal review"}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Top-level resource/action must be present and items absent on the wire.
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("Unmarshal generic: %v", err)
	}
	if _, present := generic["items"]; present {
		t.Errorf("single-target submission unexpectedly serialized an items member")
	}
	if _, present := generic["resource"]; !present {
		t.Errorf("submission missing resource on the wire: %s", b)
	}

	var out Submission
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("round-tripped submission failed Validate(): %v", err)
	}
	if out.Denial.EvaluationID != in.Denial.EvaluationID {
		t.Errorf("evaluation_id changed across round-trip: %q != %q", out.Denial.EvaluationID, in.Denial.EvaluationID)
	}
}

// TestProblemError covers the RFC 9457 problem-details error string.
//
// AuthZEN Access Request and Approval Profile, Section 14 (Error Responses).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-14
func TestProblemError(t *testing.T) {
	p := &Problem{Type: ProblemExpiredDenial, Status: 410, Detail: "the requestable denial has expired"}
	if got := p.Error(); got == "" {
		t.Fatal("Problem.Error() returned empty string")
	}
	if p.Type != "urn:openid:authzen:access-request:error:expired_denial" {
		t.Errorf("unexpected expired-denial URN: %q", p.Type)
	}
}
