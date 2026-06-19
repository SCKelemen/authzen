package authzen

import (
	"errors"
	"fmt"
)

// Sentinel errors returned (wrapped) by the Validate methods when a REQUIRED
// field defined by the specification is missing or invalid. Callers can test
// for them with errors.Is.
//
// The specification mandates that a missing required attribute MUST be rejected
// (in the HTTPS binding, with HTTP 400).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization) and
// Section 8 (Required vs optional fields).
// https://openid.net/specs/authorization-api-1_0.html
var (
	// ErrMissingType indicates a required "type" field was empty.
	ErrMissingType = errors.New(`authzen: missing required field "type"`)
	// ErrMissingID indicates a required "id" field was empty.
	ErrMissingID = errors.New(`authzen: missing required field "id"`)
	// ErrMissingName indicates a required "name" field was empty.
	ErrMissingName = errors.New(`authzen: missing required field "name"`)
	// ErrMissingSubject indicates a required "subject" object was absent.
	ErrMissingSubject = errors.New(`authzen: missing required field "subject"`)
	// ErrMissingAction indicates a required "action" object was absent.
	ErrMissingAction = errors.New(`authzen: missing required field "action"`)
	// ErrMissingResource indicates a required "resource" object was absent.
	ErrMissingResource = errors.New(`authzen: missing required field "resource"`)
	// ErrMissingEvaluationFields indicates a batch member resolves to a
	// request that is missing a subject, action, or resource even after
	// top-level defaults are applied.
	ErrMissingEvaluationFields = errors.New(`authzen: evaluation is missing subject, action, or resource`)
	// ErrInvalidSemantic indicates options.evaluations_semantic held a value
	// other than the three defined by the specification.
	ErrInvalidSemantic = errors.New("authzen: invalid evaluations_semantic")
)

// ValidationError reports a specific field that failed validation. It wraps one
// of the package sentinel errors so that errors.Is and errors.As can be used to
// distinguish the cause while still surfacing the offending field path.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html
type ValidationError struct {
	// Field is the dotted JSON path of the offending field, for example
	// "subject.type" or "evaluations[2].resource.id".
	Field string
	// Err is the underlying sentinel error describing the failure.
	Err error
}

// Error implements the error interface.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html
func (e *ValidationError) Error() string {
	return fmt.Sprintf("authzen: %s: %v", e.Field, e.Err)
}

// Unwrap returns the wrapped sentinel error, enabling errors.Is matching.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html
func (e *ValidationError) Unwrap() error { return e.Err }

// newValidationError builds a *ValidationError for the given field path and
// cause.
func newValidationError(field string, err error) error {
	return &ValidationError{Field: field, Err: err}
}
