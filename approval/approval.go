package approval

import (
	"encoding/json"
	"time"

	authzen "github.com/SCKelemen/authzen"
)

// ContextKey is the decision-context key under which the approval object is
// carried. AuthZEN's decision context is a free-form object designated as the
// extension point (Section 5.5.1); this package reserves a single, namespaced
// key within it.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5.1 (decision context).
// https://openid.net/specs/authorization-api-1_0.html
const ContextKey = "approval"

// Default polling parameters, mirroring the OAuth Device Authorization Grant
// defaults. RFC 8628 specifies a default polling interval of 5 seconds and a
// finite expiry for the pending request.
//
// RFC 8628 Section 3.2 - Device Authorization Response (expires_in, interval)
// https://www.rfc-editor.org/rfc/rfc8628#section-3.2
const (
	// DefaultExpiresIn is the default lifetime, in seconds, of a pending
	// approval before it lazily transitions to StatusExpired.
	DefaultExpiresIn = 300
	// DefaultInterval is the default minimum number of seconds the client
	// should wait between polls, per RFC 8628's 5-second default.
	DefaultInterval = 5
)

// Status is the lifecycle state of an approval request. The values mirror the
// OAuth Device Authorization Grant token-request outcomes: a single non-terminal
// "pending" state and a set of terminal outcomes.
//
// RFC 8628 Section 3.5 - Device Access Token Response (authorization_pending,
// access_denied, expired_token).
// https://www.rfc-editor.org/rfc/rfc8628#section-3.5
type Status string

// Approval lifecycle states.
const (
	// StatusPending is the only non-terminal state: a decision is awaited.
	// Analogous to RFC 8628 "authorization_pending".
	StatusPending Status = "pending"
	// StatusApproved is the terminal granted state; the decision becomes true.
	StatusApproved Status = "approved"
	// StatusDenied is the terminal refused state. Analogous to RFC 8628
	// "access_denied".
	StatusDenied Status = "denied"
	// StatusExpired is the terminal timed-out state. Analogous to RFC 8628
	// "expired_token".
	StatusExpired Status = "expired"
	// StatusCanceled is the terminal withdrawn state (the requester or system
	// rescinded the pending request before it was decided).
	StatusCanceled Status = "canceled"
)

// Terminal reports whether the status is a final state from which no further
// transition is allowed. Only StatusPending is non-terminal.
func (s Status) Terminal() bool {
	switch s {
	case StatusApproved, StatusDenied, StatusExpired, StatusCanceled:
		return true
	default:
		return false
	}
}

// RequestRef describes WHAT is pending approval, reusing the shape of an OAuth
// Rich Authorization Requests authorization_details element. It lets the
// approval object carry a structured description of the access being requested,
// independent of the AuthZEN subject/action/resource triple that produced it.
//
// RFC 9396 Section 2 - Request Parameter "authorization_details"
// https://www.rfc-editor.org/rfc/rfc9396#section-2
type RequestRef struct {
	// Type is the authorization-details type identifier. REQUIRED by RFC 9396.
	Type string `json:"type"`
	// Identifier optionally identifies a specific resource (RFC 9396 §2.2).
	Identifier string `json:"identifier,omitempty"`
	// Locations are the resource locations/URIs the request applies to.
	Locations []string `json:"locations,omitempty"`
	// Actions are the actions to be taken at the resource.
	Actions []string `json:"actions,omitempty"`
	// Datatypes are the kinds of data being requested.
	Datatypes []string `json:"datatypes,omitempty"`
	// Privileges are the privileges being requested.
	Privileges []string `json:"privileges,omitempty"`
}

// Approvers describes the human approval policy: how many approvers and in what
// arrangement must act for the request to be granted. Stage/StageCount support
// multi-stage (sequential) approval chains.
type Approvers struct {
	// Operator is "any" (a single approver suffices) or "all" (every approver
	// in the current stage must approve).
	Operator string `json:"operator,omitempty"`
	// Stage is the 1-based index of the current approval stage.
	Stage int `json:"stage,omitempty"`
	// StageCount is the total number of sequential approval stages.
	StageCount int `json:"stage_count,omitempty"`
}

// Grant describes the access granted once an approval reaches StatusApproved,
// most importantly when that grant expires (a just-in-time, time-boxed grant).
type Grant struct {
	// ExpiresAt is the instant after which the granted access is no longer
	// valid. A nil pointer indicates no explicit expiry; it is a pointer so
	// that json:",omitempty" actually omits it (a zero time.Time value is not
	// considered empty by encoding/json and would otherwise serialize as
	// "0001-01-01T00:00:00Z").
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Approval is the object carried in the decision context to represent an
// asynchronous, human-in-the-loop access decision. Its polling fields
// (expires_in, interval, poll_url, delivery) follow RFC 8628 and CIBA; its
// description of the requested access (request_ref) follows RFC 9396.
//
//   - RFC 8628 Section 3.2 (expires_in, interval) and Section 3.5 (statuses).
//     https://www.rfc-editor.org/rfc/rfc8628#section-3.2
//   - CIBA Section 7.3 (interval, auth_req_id) and Section 7.1 (delivery modes).
//     https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
type Approval struct {
	// Status is the current lifecycle state. REQUIRED.
	Status Status `json:"status"`
	// ID is the opaque, high-entropy handle used to poll for the decision,
	// analogous to RFC 8628 device_code / CIBA auth_req_id.
	ID string `json:"approval_id,omitempty"`
	// ExpiresIn is the remaining lifetime of the pending request, in seconds
	// (RFC 8628 expires_in).
	ExpiresIn int `json:"expires_in,omitempty"`
	// Interval is the minimum number of seconds to wait between polls
	// (RFC 8628 / CIBA interval).
	Interval int `json:"interval,omitempty"`
	// PollURL is the absolute URL the client polls for the current decision.
	PollURL string `json:"poll_url,omitempty"`
	// Delivery lists the supported result-delivery modes ("poll", "ping",
	// "push"), mirroring CIBA's backchannel delivery modes.
	Delivery []string `json:"delivery,omitempty"`
	// CallbackURL is the client endpoint to notify for ping/push delivery.
	CallbackURL string `json:"callback_url,omitempty"`
	// RequestRef describes what is pending approval (RFC 9396 shape). OPTIONAL.
	RequestRef *RequestRef `json:"request_ref,omitempty"`
	// Approvers describes the human approval policy. OPTIONAL.
	Approvers *Approvers `json:"approvers,omitempty"`
	// Grant describes the access granted once approved. OPTIONAL.
	Grant *Grant `json:"grant,omitempty"`
	// DecidedBy identifies the principal that approved or denied the request.
	DecidedBy string `json:"decided_by,omitempty"`
	// DecidedAt is when the request was approved or denied. A nil pointer means
	// undecided; it is a pointer so that json:",omitempty" actually omits it (a
	// zero time.Time value is not considered empty by encoding/json and would
	// otherwise serialize as "0001-01-01T00:00:00Z" on a still-pending
	// approval).
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	// ReasonUser carries user-facing explanation(s), reusing the AuthZEN
	// reason_user convention (Section 5.5, Figure 11).
	ReasonUser authzen.Reasons `json:"reason_user,omitempty"`
}

// NewPending builds a pending Approval for the given requested access, applying
// the default expires_in and interval. The returned value has no ID yet; a
// Store assigns the opaque identifier on Create.
//
// RFC 8628 Section 3.2 - Device Authorization Response (defaults).
// https://www.rfc-editor.org/rfc/rfc8628#section-3.2
func NewPending(ref *RequestRef) *Approval {
	return &Approval{
		Status:     StatusPending,
		ExpiresIn:  DefaultExpiresIn,
		Interval:   DefaultInterval,
		RequestRef: ref,
	}
}

// toMap renders the Approval to a plain JSON-compatible map using its json
// tags. It round-trips through encoding/json so the result is identical to what
// the value serializes to on the wire, regardless of whether callers later hand
// it a *Approval or a decoded map[string]any.
func (a *Approval) toMap() map[string]any {
	if a == nil {
		return nil
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// ToContext returns a decision-context object carrying the approval under
// ContextKey, suitable for use as EvaluationResponse.Context.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5.1 (decision context).
// https://openid.net/specs/authorization-api-1_0.html
func (a *Approval) ToContext() map[string]any {
	return map[string]any{ContextKey: a.toMap()}
}

// FromContext extracts an Approval from a decision context produced by
// ToContext (or received over the wire). It reports false when the context is
// nil, lacks the approval key, or carries a value that is not a valid approval
// object. The lookup tolerates either a *Approval or a decoded map[string]any
// under ContextKey.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5.1 (decision context).
// https://openid.net/specs/authorization-api-1_0.html
func FromContext(ctx map[string]any) (*Approval, bool) {
	if ctx == nil {
		return nil, false
	}
	raw, ok := ctx[ContextKey]
	if !ok || raw == nil {
		return nil, false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var a Approval
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, false
	}
	if a.Status == "" {
		return nil, false
	}
	return &a, true
}

// PendingResponse builds the AuthZEN response for a pending approval: a
// fail-safe deny (decision=false) carrying the approval object so the PEP can
// poll for the eventual decision. This mirrors RFC 8628's authorization_pending
// "not yet successful" response.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.2 (decision is REQUIRED bool).
// RFC 8628 Section 3.5 (authorization_pending).
// https://openid.net/specs/authorization-api-1_0.html
func PendingResponse(a *Approval) authzen.EvaluationResponse {
	return authzen.EvaluationResponse{Decision: false, Context: a.ToContext()}
}

// ApprovedResponse builds the AuthZEN response for an approved request: a permit
// (decision=true) carrying the approval object (now StatusApproved, with any
// Grant details).
//
// OpenID AuthZEN Authorization API 1.0, Section 6.2 (decision is REQUIRED bool).
// https://openid.net/specs/authorization-api-1_0.html
func ApprovedResponse(a *Approval) authzen.EvaluationResponse {
	return authzen.EvaluationResponse{Decision: true, Context: a.ToContext()}
}

// DeniedResponse builds the AuthZEN response for a denied request: a fail-safe
// deny carrying the approval object (StatusDenied).
func DeniedResponse(a *Approval) authzen.EvaluationResponse {
	return authzen.EvaluationResponse{Decision: false, Context: a.ToContext()}
}

// ExpiredResponse builds the AuthZEN response for an expired request: a
// fail-safe deny carrying the approval object (StatusExpired).
func ExpiredResponse(a *Approval) authzen.EvaluationResponse {
	return authzen.EvaluationResponse{Decision: false, Context: a.ToContext()}
}

// CanceledResponse builds the AuthZEN response for a canceled request: a
// fail-safe deny carrying the approval object (StatusCanceled).
func CanceledResponse(a *Approval) authzen.EvaluationResponse {
	return authzen.EvaluationResponse{Decision: false, Context: a.ToContext()}
}

// Response builds the AuthZEN response that reflects the approval's current
// status: a permit for StatusApproved and a fail-safe deny for every other
// state, in each case carrying the approval object in the decision context.
func Response(a *Approval) authzen.EvaluationResponse {
	if a != nil && a.Status == StatusApproved {
		return ApprovedResponse(a)
	}
	return authzen.EvaluationResponse{Decision: false, Context: a.ToContext()}
}
