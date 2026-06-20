package accessrequest

import authzen "github.com/SCKelemen/authzen"

// Capability is the PDP capability URN a PDP supporting this profile SHOULD
// advertise in the metadata "capabilities" array. Note the urn:openid:authzen
// namespace (an OpenID Foundation profile convention) rather than the
// urn:ietf:params:authzen sub-namespace used by the base Authorization API.
//
// AuthZEN Access Request and Approval Profile, Section 6 (Discovery) and
// Section 23.1.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-6
const Capability = "urn:openid:authzen:capability:access-request"

// Decision-context member names defined by this profile. They appear inside the
// AuthZEN Decision Context (the "context" object of an Access Evaluation
// response) and inside a re-evaluation request's context.
//
// AuthZEN Access Request and Approval Profile, Section 23.2 (Member Names).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-23.2
const (
	// MemberAccessRequest is context.access_request, the requestable-denial
	// object whose presence signals that a denied decision may be requested.
	MemberAccessRequest = "access_request"
	// MemberEvaluationID is context.evaluation_id, the stable identifier of the
	// evaluation, used for denial binding and audit.
	MemberEvaluationID = "evaluation_id"
	// MemberEvaluatedAt is context.evaluated_at, an RFC 3339 timestamp of when
	// the Decision was produced.
	MemberEvaluatedAt = "evaluated_at"
	// MemberReason is context.reason, a machine-readable reason code.
	MemberReason = "reason"
	// MemberApproval is context.approval, the approval reference carried during
	// re-evaluation.
	MemberApproval = "approval"
	// MemberNextAction is context.next_action, the action the PEP should take
	// after a denied re-evaluation that presented an approval reference.
	MemberNextAction = "next_action"
	// MemberRetryAfter is context.retry_after, the number of seconds the PEP
	// waits before retrying a transient re-evaluation denial.
	MemberRetryAfter = "retry_after"
)

// Hint is the context.access_request object a PDP MAY include in a denied
// Access Evaluation Decision Context. Its presence is the sole signal that the
// denial is requestable: a PEP MUST treat the absence of this object as a
// non-requestable denial regardless of any other context members.
//
// AuthZEN Access Request and Approval Profile, Section 7 (Requestable Denial
// Context).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-7
type Hint struct {
	// Endpoint is the HTTPS URI to which the PEP submits the access request. If
	// omitted, the PEP MUST use the access_request_endpoint from PDP metadata.
	// OPTIONAL.
	Endpoint string `json:"endpoint,omitempty"`
	// Template is an opaque template identifier that can guide the Access
	// Request Service. It is not a policy language and MUST NOT be interpreted
	// by the PEP except for display or request submission. OPTIONAL.
	Template string `json:"template,omitempty"`
	// ExpiresAt is the RFC 3339 time after which the requestable-denial hint
	// expires. The PEP echoes it as denial.expires_at. REQUIRED.
	ExpiresAt string `json:"expires_at"`
	// BindingToken is opaque, integrity-protected context the PEP returns
	// unchanged as denial.binding_token; the PEP MUST NOT decode, modify, or
	// interpret it. OPTIONAL (but see Validate: a requestable denial MUST carry
	// either a binding_token or context.evaluation_id).
	BindingToken string `json:"binding_token,omitempty"`
	// Display holds localizable user-interface hints (title, description, ...).
	// The PEP MAY ignore it. OPTIONAL.
	Display map[string]any `json:"display,omitempty"`
	// FormURL is the HTTPS URL of a form where a human requester supplies
	// additional submission fields. OPTIONAL.
	FormURL string `json:"form_url,omitempty"`
	// RequestSchemaURL is the HTTPS URL of a machine-readable (RECOMMENDED JSON
	// Schema) description of the augmentations the PEP must add to the
	// submission's context and requested_access objects. OPTIONAL.
	RequestSchemaURL string `json:"request_schema_url,omitempty"`
	// RequestCatalogsURL is the HTTPS URL of a Catalogs Document describing how
	// the PEP resolves form fields whose values come from a backing catalog.
	// OPTIONAL.
	RequestCatalogsURL string `json:"request_catalogs_url,omitempty"`
}

// NextAction values a PDP returns (as context.next_action) when it denies a
// re-evaluation that presented an approval reference, telling the PEP what to do
// next.
//
// AuthZEN Access Request and Approval Profile, Section 12 (Completion
// Semantics).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
const (
	// NextActionRequest instructs the PEP to submit a new Access Request. The
	// PDP MUST also include a fresh context.access_request.
	NextActionRequest = "request"
	// NextActionRetry instructs the PEP to re-evaluate the same request after a
	// delay; the denial is expected to be transient.
	NextActionRetry = "retry"
	// NextActionNone instructs the PEP not to retry or re-request; the denial is
	// terminal for this approval.
	NextActionNone = "none"
)

// Re-evaluation denial reason codes registered by the profile, with their
// default next action noted in the doc comment.
//
// AuthZEN Access Request and Approval Profile, Section 23.3 (Re-evaluation
// Denial Reason registry).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-23.3
const (
	// ReasonApprovalExpired: approval no longer valid (default: request).
	ReasonApprovalExpired = "approval_expired"
	// ReasonOutOfScope: approval valid but evaluation outside scope (default: request).
	ReasonOutOfScope = "out_of_scope"
	// ReasonGrantPending: approval valid and in scope, grant not yet present (default: retry).
	ReasonGrantPending = "grant_pending"
	// ReasonPolicyDenied: approval valid and in scope, current policy denies (default: none).
	ReasonPolicyDenied = "policy_denied"
	// ReasonApprovalUnverifiable: approval reference could not be resolved or
	// verified (default: none).
	ReasonApprovalUnverifiable = "approval_unverifiable"
)

// HintFromContext extracts the requestable-denial Hint from an Access
// Evaluation Decision Context, returning the Hint and true when a well-formed
// context.access_request object is present. It performs no validation beyond
// shape; callers SHOULD call Hint.Validate before relying on the result.
//
// AuthZEN Access Request and Approval Profile, Section 7 and Section 16 (PEP
// Processing Rules).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-16
func HintFromContext(ctx map[string]any) (*Hint, bool) {
	if ctx == nil {
		return nil, false
	}
	raw, ok := ctx[MemberAccessRequest].(map[string]any)
	if !ok {
		return nil, false
	}
	h := &Hint{}
	if v, ok := raw["endpoint"].(string); ok {
		h.Endpoint = v
	}
	if v, ok := raw["template"].(string); ok {
		h.Template = v
	}
	if v, ok := raw["expires_at"].(string); ok {
		h.ExpiresAt = v
	}
	if v, ok := raw["binding_token"].(string); ok {
		h.BindingToken = v
	}
	if v, ok := raw["display"].(map[string]any); ok {
		h.Display = v
	}
	if v, ok := raw["form_url"].(string); ok {
		h.FormURL = v
	}
	if v, ok := raw["request_schema_url"].(string); ok {
		h.RequestSchemaURL = v
	}
	if v, ok := raw["request_catalogs_url"].(string); ok {
		h.RequestCatalogsURL = v
	}
	return h, true
}

// DenialBinding binds an Access Request to the denied AuthZEN Decision it
// remediates. Each field is echoed unchanged by the PEP from the corresponding
// member of the denied evaluation response; the binding material
// (evaluation_id and binding_token) provides stronger evidence of the denial
// than a verbatim JSON echo could.
//
// AuthZEN Access Request and Approval Profile, Section 10.1 (Access Request
// Submission), denial object.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
type DenialBinding struct {
	// EvaluationID is the stable identifier of the denied evaluation, echoed
	// from context.evaluation_id. REQUIRED when BindingToken is absent;
	// otherwise RECOMMENDED.
	EvaluationID string `json:"evaluation_id,omitempty"`
	// EvaluatedAt is the RFC 3339 time the denial was produced, echoed from
	// context.evaluated_at. OPTIONAL.
	EvaluatedAt string `json:"evaluated_at,omitempty"`
	// ExpiresAt is the RFC 3339 requestable-denial expiry, echoed unchanged from
	// context.access_request.expires_at. REQUIRED.
	ExpiresAt string `json:"expires_at"`
	// Reason is the machine-readable denial reason code, echoed from
	// context.reason. OPTIONAL.
	Reason string `json:"reason,omitempty"`
	// BindingToken is integrity-protected binding material echoed byte-for-byte
	// from context.access_request.binding_token. REQUIRED when EvaluationID is
	// absent; otherwise OPTIONAL.
	BindingToken string `json:"binding_token,omitempty"`
	// Template is echoed from context.access_request.template when the PDP
	// provided one; the Access Request Service uses it to route the request.
	// OPTIONAL.
	Template string `json:"template,omitempty"`
}

// DenialFromHint builds the DenialBinding a PEP submits from the requestable
// denial Hint and the captured decision-context members (evaluation_id,
// evaluated_at, reason). It echoes values unchanged as required by Section 16.
//
// AuthZEN Access Request and Approval Profile, Section 16 (PEP Processing
// Rules).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-16
func DenialFromHint(h *Hint, ctx map[string]any) *DenialBinding {
	d := &DenialBinding{}
	if h != nil {
		d.ExpiresAt = h.ExpiresAt
		d.BindingToken = h.BindingToken
		d.Template = h.Template
	}
	if ctx != nil {
		if v, ok := ctx[MemberEvaluationID].(string); ok {
			d.EvaluationID = v
		}
		if v, ok := ctx[MemberEvaluatedAt].(string); ok {
			d.EvaluatedAt = v
		}
		if v, ok := ctx[MemberReason].(string); ok {
			d.Reason = v
		}
	}
	return d
}

// Subject, Resource, and Action are re-exported aliases of the core
// information-model types so that callers of this profile do not also need to
// import the root package for the common case.
type (
	// Subject is an AuthZEN Subject (the principal).
	Subject = authzen.Subject
	// Resource is an AuthZEN Resource (the target).
	Resource = authzen.Resource
	// Action is an AuthZEN Action (the operation).
	Action = authzen.Action
	// Context is an AuthZEN free-form Context object.
	Context = authzen.Context
)
