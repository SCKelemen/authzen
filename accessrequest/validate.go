package accessrequest

import authzen "github.com/SCKelemen/authzen"

// Validate reports whether the requestable-denial Hint carries the field
// REQUIRED by the profile: a non-empty expires_at. The remaining binding
// material (binding_token or context.evaluation_id) lives outside the Hint and
// is checked by DenialBinding.Validate on the echoed submission.
//
// AuthZEN Access Request and Approval Profile, Section 7 (Requestable Denial
// Context).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-7
func (h *Hint) Validate() error {
	if h == nil {
		return newValidationError("access_request", ErrMissingExpiresAt)
	}
	if h.ExpiresAt == "" {
		return newValidationError("access_request.expires_at", ErrMissingExpiresAt)
	}
	return nil
}

// Validate reports whether the DenialBinding carries the material REQUIRED by
// the profile: a non-empty expires_at, and at least one of evaluation_id or
// binding_token (an Access Request whose denial lacks verifiable binding
// material MUST be rejected with invalid_denial_binding).
//
// AuthZEN Access Request and Approval Profile, Section 10.1 (Access Request
// Submission), denial object.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func (d *DenialBinding) Validate() error {
	return d.validate("denial")
}

func (d *DenialBinding) validate(field string) error {
	if d == nil {
		return newValidationError(field, ErrMissingDenial)
	}
	if d.ExpiresAt == "" {
		return newValidationError(field+".expires_at", ErrMissingExpiresAt)
	}
	if d.EvaluationID == "" && d.BindingToken == "" {
		return newValidationError(field, ErrMissingDenialBinding)
	}
	return nil
}

// Validate reports whether the Submission satisfies the structural MUST rules
// of Section 10.1: a subject is REQUIRED; the top-level resource/action pair
// and the items array are mutually exclusive and exactly one form MUST be
// present; each item carries a resource and an action; and verifiable denial
// binding MUST cover every requested item, supplied either by a top-level
// denial or by per-item denials.
//
// AuthZEN Access Request and Approval Profile, Section 10.1.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func (s *Submission) Validate() error {
	if s == nil {
		return newValidationError("subject", authzen.ErrMissingSubject)
	}
	if err := s.Subject.Validate(); err != nil {
		return err
	}

	hasSingle := s.Resource != nil || s.Action != nil
	hasItems := len(s.Items) > 0

	switch {
	case hasSingle && hasItems:
		return newValidationError("items", ErrConflictingTargets)
	case !hasSingle && !hasItems:
		return newValidationError("items", ErrMissingTarget)
	case hasSingle:
		if err := s.Resource.Validate(); err != nil {
			return err
		}
		if err := s.Action.Validate(); err != nil {
			return err
		}
		// A single-target submission MUST bind the denied Decision.
		if err := s.Denial.validate("denial"); err != nil {
			return err
		}
	default: // hasItems
		if err := s.validateItems(); err != nil {
			return err
		}
	}

	if s.Callback != nil {
		if err := s.Callback.Validate(); err != nil {
			return err
		}
	}
	if s.Client != nil && s.Client.Actor != nil {
		if err := s.Client.Actor.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Submission) validateItems() error {
	// When any item lacks its own denial, the top-level denial is REQUIRED and
	// must cover the bundle.
	topLevelValid := s.Denial != nil && s.Denial.validate("denial") == nil
	for i := range s.Items {
		it := &s.Items[i]
		field := "items"
		if err := it.validate(field); err != nil {
			return err
		}
		if it.Denial == nil && !topLevelValid {
			// Surface the underlying denial defect if a top-level denial was
			// supplied but invalid; otherwise report the missing binding.
			if s.Denial != nil {
				if err := s.Denial.validate("denial"); err != nil {
					return err
				}
			}
			return newValidationError("denial", ErrMissingDenial)
		}
	}
	return nil
}

// Validate reports whether the Item carries the resource and action REQUIRED by
// the profile, and that any per-item denial binding is well formed.
//
// AuthZEN Access Request and Approval Profile, Section 10.1, items array.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
func (it *Item) Validate() error { return it.validate("items") }

func (it *Item) validate(field string) error {
	if err := it.Resource.Validate(); err != nil {
		return err
	}
	if err := it.Action.Validate(); err != nil {
		return err
	}
	if it.Denial != nil {
		if err := it.Denial.validate(field + ".denial"); err != nil {
			return err
		}
	}
	return nil
}

// Validate reports whether the Callback carries the HTTPS endpoint REQUIRED by
// Section 13.
//
// AuthZEN Access Request and Approval Profile, Section 13 (Callback Completion).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-13
func (c *Callback) Validate() error {
	if c == nil || c.Endpoint == "" {
		return newValidationError("callback.endpoint", ErrMissingEndpoint)
	}
	return nil
}

// Validate reports whether the Actor carries the id REQUIRED by Section 19.1.
//
// AuthZEN Access Request and Approval Profile, Section 19.1 (Delegation and
// On-Behalf-Of).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-19.1
func (a *Actor) Validate() error {
	if a == nil || a.ID == "" {
		return newValidationError("client.actor.id", ErrMissingID)
	}
	return nil
}

// Validate reports whether the Response carries the task object REQUIRED by
// Section 10.2, and that the task and any enforceable result are well formed.
//
// AuthZEN Access Request and Approval Profile, Section 10.2 (Access Request
// Response).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.2
func (r *Response) Validate() error {
	if r == nil || r.Task == nil {
		return newValidationError("task", ErrMissingTask)
	}
	if err := r.Task.Validate(); err != nil {
		return err
	}
	if r.Result != nil {
		if err := r.Result.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate reports whether the Task carries the id, status, and status_endpoint
// REQUIRED by Section 10.2, and that any per-item progress is well formed.
//
// AuthZEN Access Request and Approval Profile, Section 10.2, task object.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.2
func (t *Task) Validate() error {
	if t == nil {
		return newValidationError("task", ErrMissingTask)
	}
	if t.ID == "" {
		return newValidationError("task.id", ErrMissingID)
	}
	if t.Status == "" {
		return newValidationError("task.status", ErrMissingStatus)
	}
	if t.StatusEndpoint == "" {
		return newValidationError("task.status_endpoint", ErrMissingStatusEndpoint)
	}
	for i := range t.Items {
		if err := t.Items[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate reports whether the TaskItem carries the resource, action, and
// status REQUIRED by Section 10.2, and that an approved item carries an
// enforceable result.
//
// AuthZEN Access Request and Approval Profile, Section 10.2 and Section 11.3
// (Completed Task Response).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-11.3
func (ti *TaskItem) Validate() error {
	if err := ti.Resource.Validate(); err != nil {
		return err
	}
	if err := ti.Action.Validate(); err != nil {
		return err
	}
	if ti.Status == "" {
		return newValidationError("task.items.status", ErrMissingStatus)
	}
	if ti.Status == StatusApproved {
		if ti.Result == nil {
			return newValidationError("task.items.result", ErrMissingApproval)
		}
		if err := ti.Result.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate reports whether the Result carries the mode REQUIRED by Section 12,
// and, for reevaluate mode, the approval object REQUIRED with it.
//
// AuthZEN Access Request and Approval Profile, Section 12 (Completion
// Semantics).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
func (r *Result) Validate() error {
	if r == nil || r.Mode == "" {
		return newValidationError("result.mode", ErrMissingMode)
	}
	if r.Mode == ModeReevaluate {
		if r.Approval == nil {
			return newValidationError("result.approval", ErrMissingApproval)
		}
		if err := r.Approval.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate reports whether the Approval carries the id and approved_until
// REQUIRED by Section 12.
//
// AuthZEN Access Request and Approval Profile, Section 12, approval object.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
func (a *Approval) Validate() error {
	if a == nil {
		return newValidationError("result.approval", ErrMissingApproval)
	}
	if a.ID == "" {
		return newValidationError("result.approval.id", ErrMissingID)
	}
	if a.ApprovedUntil == "" {
		return newValidationError("result.approval.approved_until", ErrMissingApprovedUntil)
	}
	return nil
}
