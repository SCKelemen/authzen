package accessrequest

// Submission is the body a PEP POSTs to the Access Request Endpoint after a
// requestable denial. A submission carries either a single (resource, action)
// pair or, for a bundled request, an items array; the two forms are mutually
// exclusive.
//
// AuthZEN Access Request and Approval Profile, Section 10.1 (Access Request
// Submission).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
type Submission struct {
	// Subject is the AuthZEN Subject from the denied evaluation. REQUIRED.
	Subject *Subject `json:"subject"`
	// Resource is the AuthZEN Resource from the denied evaluation. REQUIRED when
	// Items is absent; MUST be omitted when Items is present.
	Resource *Resource `json:"resource,omitempty"`
	// Action is the AuthZEN Action from the denied evaluation. REQUIRED when
	// Items is absent; MUST be omitted when Items is present.
	Action *Action `json:"action,omitempty"`
	// Items bundles multiple (resource, action) pairs into a single request.
	// When present, Resource and Action MUST be omitted at the top level.
	// OPTIONAL.
	Items []Item `json:"items,omitempty"`
	// Context is the AuthZEN Context from the denied evaluation, optionally
	// augmented with submission-time fields such as business justification.
	// OPTIONAL.
	Context Context `json:"context,omitempty"`
	// Denial binds the submission to the denied AuthZEN Decision. REQUIRED when
	// Items is absent, or when Items is present and any item lacks a per-item
	// Denial; OPTIONAL when every item carries its own Denial.
	Denial *DenialBinding `json:"denial,omitempty"`
	// RequestedAccess carries request-specific information (requested duration,
	// emergency flag, ...). OPTIONAL.
	RequestedAccess *RequestedAccess `json:"requested_access,omitempty"`
	// Callback describes a callback endpoint for completion notifications.
	// OPTIONAL.
	Callback *Callback `json:"callback,omitempty"`
	// Client identifies the PEP or calling application, supplementing the
	// authenticated caller identity. OPTIONAL.
	Client *Client `json:"client,omitempty"`
}

// Item is one (resource, action) member of a bundled Access Request Submission.
//
// AuthZEN Access Request and Approval Profile, Section 10.1, items array.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
type Item struct {
	// Resource is the AuthZEN Resource for this item. REQUIRED.
	Resource *Resource `json:"resource"`
	// Action is the AuthZEN Action for this item. REQUIRED.
	Action *Action `json:"action"`
	// RequestedAccess holds per-item overrides merged over the top-level
	// requested_access, with item values taking precedence. OPTIONAL.
	RequestedAccess *RequestedAccess `json:"requested_access,omitempty"`
	// Denial is per-item denial binding when items came from separate
	// evaluations. OPTIONAL.
	Denial *DenialBinding `json:"denial,omitempty"`
}

// RequestedAccess carries request-specific information interpreted by the
// Access Request Service. The well-known members below are defined by the
// profile; additional members MAY be included subject to the naming rules in
// Section 15.2.
//
// AuthZEN Access Request and Approval Profile, Section 10.1, requested_access.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
type RequestedAccess struct {
	// RequestedUntil is an RFC 3339 timestamp requesting access through a
	// specific absolute time. OPTIONAL.
	RequestedUntil string `json:"requested_until,omitempty"`
	// Emergency, when true, requests an expedited or emergency-access path
	// subject to additional auditing. OPTIONAL.
	Emergency bool `json:"emergency,omitempty"`
}

// Callback describes where the Access Request Service sends completion
// notifications.
//
// AuthZEN Access Request and Approval Profile, Section 13 (Callback Completion).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-13
type Callback struct {
	// Endpoint is the HTTPS URI for completion notifications. REQUIRED.
	Endpoint string `json:"endpoint"`
	// State is an opaque value returned unmodified in the callback. OPTIONAL.
	State string `json:"state,omitempty"`
	// Events lists requested event names: approved, denied, expired, cancelled,
	// failed, partial. OPTIONAL.
	Events []string `json:"events,omitempty"`
}

// Client identifies the PEP or calling application submitting the request,
// together with an optional delegation actor and audit source.
//
// AuthZEN Access Request and Approval Profile, Section 10.1, client object, and
// Section 19.1 (Delegation and On-Behalf-Of).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-19.1
type Client struct {
	// ID is a stable identifier for the calling application or PEP deployment.
	// OPTIONAL.
	ID string `json:"id,omitempty"`
	// Name is a human-readable name of the calling application. OPTIONAL.
	Name string `json:"name,omitempty"`
	// Actor identifies the immediate actor on whose behalf the PEP submits the
	// request, when it differs from the Subject. OPTIONAL.
	Actor *Actor `json:"actor,omitempty"`
	// Source carries audit-trail origin context. OPTIONAL.
	Source *Source `json:"source,omitempty"`
}

// Actor identifies the immediate actor in a delegation chain, following the
// conventions in the OAuth Actor Profile for Delegation. Nested Act objects
// represent multi-hop chains from the immediate actor outward toward the
// Subject.
//
// AuthZEN Access Request and Approval Profile, Section 19.1.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-19.1
type Actor struct {
	// ID is a stable identifier for the actor. REQUIRED.
	ID string `json:"id"`
	// Issuer is the authority, tenant, or identity provider for the actor
	// identifier. OPTIONAL.
	Issuer string `json:"issuer,omitempty"`
	// Type is the actor category, such as user, service, workload, or ai_agent.
	// OPTIONAL.
	Type string `json:"type,omitempty"`
	// Act is the next link in a delegation chain (sub/iss, optional
	// sub_profile), following draft-mcguinness-oauth-actor-profile. OPTIONAL.
	Act map[string]any `json:"act,omitempty"`
}

// Source describes where an Access Request originated, for audit correlation.
//
// AuthZEN Access Request and Approval Profile, Section 10.1, client.source.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.1
type Source struct {
	// SessionID identifies a bounded interaction context (chat or agent
	// conversation, application session, CLI invocation, workflow thread).
	// OPTIONAL.
	SessionID string `json:"session_id,omitempty"`
	// ExternalURL is the HTTPS URL of an external system that motivated the
	// request (ticket, document, dashboard, chat thread). OPTIONAL.
	ExternalURL string `json:"external_url,omitempty"`
	// IntegrationID identifies an upstream integration or workflow that produced
	// the request. OPTIONAL.
	IntegrationID string `json:"integration_id,omitempty"`
}
