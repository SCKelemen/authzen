package accessrequest

import (
	"errors"

	authzen "github.com/SCKelemen/authzen"
)

// Sentinel errors returned (wrapped in an authzen.ValidationError) by the
// Validate methods when a field REQUIRED by the profile is missing or when a
// MUST-level structural rule is violated. Callers can test for them with
// errors.Is, and can extract the offending field path with errors.As against
// *authzen.ValidationError.
//
// AuthZEN Access Request and Approval Profile, Section 10 (Access Request
// Endpoint) and Section 12 (Completion Semantics).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
var (
	// ErrMissingExpiresAt indicates a required RFC 3339 "expires_at" was empty,
	// in either a requestable-denial Hint or a submission denial binding.
	ErrMissingExpiresAt = errors.New(`accessrequest: missing required field "expires_at"`)
	// ErrMissingDenialBinding indicates a denial binding carried neither an
	// "evaluation_id" nor a "binding_token"; Section 7 and Section 10.1 require
	// at least one.
	ErrMissingDenialBinding = errors.New(`accessrequest: denial binding requires evaluation_id or binding_token`)
	// ErrMissingDenial indicates a submission (or bundled item) lacked the
	// "denial" object REQUIRED to bind it to the denied Decision.
	ErrMissingDenial = errors.New(`accessrequest: missing required field "denial"`)
	// ErrConflictingTargets indicates a submission set both the top-level
	// resource/action pair and the items array, which Section 10.1 forbids.
	ErrConflictingTargets = errors.New(`accessrequest: "resource"/"action" and "items" are mutually exclusive`)
	// ErrMissingTarget indicates a submission carried neither a top-level
	// resource/action pair nor a non-empty items array.
	ErrMissingTarget = errors.New(`accessrequest: missing "resource"/"action" or "items"`)
	// ErrMissingEndpoint indicates a callback object lacked the required HTTPS
	// "endpoint".
	ErrMissingEndpoint = errors.New(`accessrequest: missing required field "endpoint"`)
	// ErrMissingID indicates a required opaque identifier ("id") was empty.
	ErrMissingID = errors.New(`accessrequest: missing required field "id"`)
	// ErrMissingStatus indicates a task or task item lacked the required
	// "status".
	ErrMissingStatus = errors.New(`accessrequest: missing required field "status"`)
	// ErrMissingStatusEndpoint indicates a task lacked the required HTTPS
	// "status_endpoint".
	ErrMissingStatusEndpoint = errors.New(`accessrequest: missing required field "status_endpoint"`)
	// ErrMissingTask indicates a response lacked the required "task" object.
	ErrMissingTask = errors.New(`accessrequest: missing required field "task"`)
	// ErrMissingMode indicates a completion result lacked the required "mode".
	ErrMissingMode = errors.New(`accessrequest: missing required field "mode"`)
	// ErrMissingApproval indicates a reevaluate-mode result lacked the required
	// "approval" object.
	ErrMissingApproval = errors.New(`accessrequest: missing required field "approval"`)
	// ErrMissingApprovedUntil indicates an approval lacked the required RFC 3339
	// "approved_until".
	ErrMissingApprovedUntil = errors.New(`accessrequest: missing required field "approved_until"`)
)

// newValidationError builds an *authzen.ValidationError for the given field path
// and cause, reusing the core error type so errors.Is and errors.As behave
// uniformly across the module.
func newValidationError(field string, err error) error {
	return &authzen.ValidationError{Field: field, Err: err}
}
