package authzen

// Validate reports whether the Subject carries the fields REQUIRED by the
// specification: a non-empty type and id. It returns a *ValidationError
// wrapping a package sentinel error otherwise.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.1 (Subject).
// https://openid.net/specs/authorization-api-1_0.html
func (s *Subject) Validate() error {
	if s == nil {
		return newValidationError("subject", ErrMissingSubject)
	}
	if s.Type == "" {
		return newValidationError("subject.type", ErrMissingType)
	}
	if s.ID == "" {
		return newValidationError("subject.id", ErrMissingID)
	}
	return nil
}

// Validate reports whether the Resource carries the fields REQUIRED by the
// specification: a non-empty type and id.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.2 (Resource).
// https://openid.net/specs/authorization-api-1_0.html
func (r *Resource) Validate() error {
	if r == nil {
		return newValidationError("resource", ErrMissingResource)
	}
	if r.Type == "" {
		return newValidationError("resource.type", ErrMissingType)
	}
	if r.ID == "" {
		return newValidationError("resource.id", ErrMissingID)
	}
	return nil
}

// Validate reports whether the Action carries the field REQUIRED by the
// specification: a non-empty name.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.3 (Action).
// https://openid.net/specs/authorization-api-1_0.html
func (a *Action) Validate() error {
	if a == nil {
		return newValidationError("action", ErrMissingAction)
	}
	if a.Name == "" {
		return newValidationError("action.name", ErrMissingName)
	}
	return nil
}

// EvaluationRequest is the body of an Access Evaluation request: it asks whether
// the subject may perform the action on the resource within the optional
// context. It is also the element type of the Access Evaluations batch array
// (Section 7.1), where individual fields may be omitted and inherited from the
// top-level defaults; the fields are therefore pointers so that omission can be
// distinguished from a zero value on the wire.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.1 (Access Evaluation Request).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-request
type EvaluationRequest struct {
	// Subject is the principal. REQUIRED for a standalone evaluation.
	Subject *Subject `json:"subject,omitempty"`
	// Action is the operation. REQUIRED for a standalone evaluation.
	Action *Action `json:"action,omitempty"`
	// Resource is the target. REQUIRED for a standalone evaluation.
	Resource *Resource `json:"resource,omitempty"`
	// Context carries optional environment/request attributes. OPTIONAL.
	Context Context `json:"context,omitempty"`
}

// Validate reports whether the request carries the subject, action, and
// resource REQUIRED by the specification, each with its own required fields.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.1 (Access Evaluation Request).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-request
func (r *EvaluationRequest) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if err := r.Action.Validate(); err != nil {
		return err
	}
	if err := r.Resource.Validate(); err != nil {
		return err
	}
	return nil
}

// EvaluationResponse is the body of an Access Evaluation response. The decision
// is REQUIRED (true permits, false denies; a deny is fail-safe/closed). The
// context is OPTIONAL and carries reasons, advice/obligations, UI hints, or
// step-up instructions whose semantics are implementation-specific.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.2 (Access Evaluation Response)
// and Section 5.5 (Decision).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-response
type EvaluationResponse struct {
	// Decision is true to permit and false to deny the request. REQUIRED.
	Decision bool `json:"decision"`
	// Context carries optional, implementation-specific reasons or advice.
	// OPTIONAL.
	Context map[string]any `json:"context,omitempty"`
}

// Reasons is a map of code to human-readable explanation, used by the
// non-normative reason_admin and reason_user decision-context conventions
// illustrated by the specification.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5 (Decision), Figure 11.
// https://openid.net/specs/authorization-api-1_0.html
type Reasons map[string]string

// ReasonContext is a typed helper for the non-normative decision-context
// convention that splits explanations into an administrator-facing and a
// user-facing map, each keyed by a code (for example an HTTP status code). It
// is provided for convenience; the decision context is a free-form object and
// implementations are free to use other shapes.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5 (Decision), Figure 11.
// https://openid.net/specs/authorization-api-1_0.html
type ReasonContext struct {
	// ReasonAdmin holds administrator-facing explanations keyed by code.
	// OPTIONAL.
	ReasonAdmin Reasons `json:"reason_admin,omitempty"`
	// ReasonUser holds user-facing explanations keyed by code. OPTIONAL.
	ReasonUser Reasons `json:"reason_user,omitempty"`
}

// EvaluationError is a typed helper for the non-normative per-evaluation error
// object that a PDP may place inside a decision context to explain why an
// individual decision failed (most often within a batch response). It is not an
// HTTP transport error; transport errors are reported with HTTP status codes.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2.1 (Errors in batch).
// https://openid.net/specs/authorization-api-1_0.html
type EvaluationError struct {
	// Status is an implementation-specific status code (for example an HTTP
	// status such as 404).
	Status int `json:"status"`
	// Message is a human-readable description of the failure.
	Message string `json:"message"`
}
