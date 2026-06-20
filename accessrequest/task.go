package accessrequest

// Response is the body returned by the Access Request Endpoint and the Task
// Status Endpoint. The task member is authoritative; result is present only
// when the task has completed with an enforceable outcome.
//
// AuthZEN Access Request and Approval Profile, Section 10.2 (Access Request
// Response) and Section 11 (Task Status Endpoint).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.2
type Response struct {
	// Task is the Task Handle for the submitted Access Request. REQUIRED.
	Task *Task `json:"task"`
	// Result is the completion result. A PEP MUST NOT treat it as approval
	// unless the task is approved and the result is enforceable under Section
	// 12. OPTIONAL except where Section 11.3 requires it.
	Result *Result `json:"result,omitempty"`
}

// TaskStatus is the lifecycle status of an Access Request task.
//
// AuthZEN Access Request and Approval Profile, Section 11.1 (Task Status
// Values).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-11.1
type TaskStatus string

// Canonical task status values. Implementations MAY define additional values; a
// PEP that receives an unknown status MUST treat the task as not approved.
const (
	// StatusPending: accepted and awaiting processing or approval.
	StatusPending TaskStatus = "pending"
	// StatusApproved: approved (approval alone does not grant access).
	StatusApproved TaskStatus = "approved"
	// StatusDenied: rejected by the approval workflow.
	StatusDenied TaskStatus = "denied"
	// StatusExpired: expired before completion.
	StatusExpired TaskStatus = "expired"
	// StatusCancelled: cancelled by requester, approver, administrator, or system.
	StatusCancelled TaskStatus = "cancelled"
	// StatusFailed: could not complete due to an error.
	StatusFailed TaskStatus = "failed"
	// StatusPartial: bulk task whose items reached two or more distinct terminal
	// statuses. Valid only for tasks containing an items array.
	StatusPartial TaskStatus = "partial"
)

// IsTerminal reports whether the status is a terminal lifecycle state (any
// status other than pending and unknown implementation-defined non-terminal
// states). The canonical terminal states are approved, denied, expired,
// cancelled, failed, and partial.
//
// AuthZEN Access Request and Approval Profile, Section 11.1.1 (State
// Transitions).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-11.1.1
func (s TaskStatus) IsTerminal() bool {
	switch s {
	case StatusApproved, StatusDenied, StatusExpired, StatusCancelled, StatusFailed, StatusPartial:
		return true
	default:
		return false
	}
}

// Task is the opaque, portable handle representing the lifecycle of an Access
// Request.
//
// AuthZEN Access Request and Approval Profile, Section 10.2, task object.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.2
type Task struct {
	// ID is a stable, opaque, unguessable task identifier. REQUIRED.
	ID string `json:"id"`
	// Status is the current task status. REQUIRED.
	Status TaskStatus `json:"status"`
	// StatusEndpoint is the HTTPS URI used to retrieve task status. It is
	// authoritative for subsequent status retrieval. REQUIRED.
	StatusEndpoint string `json:"status_endpoint"`
	// Progress describes approval-workflow progress for multi-step approvals.
	// OPTIONAL.
	Progress *Progress `json:"progress,omitempty"`
	// ExpiresAt is the RFC 3339 time after which the task handle is no longer
	// valid. OPTIONAL.
	ExpiresAt string `json:"expires_at,omitempty"`
	// Display holds user-interface hints for the pending request. OPTIONAL.
	Display map[string]any `json:"display,omitempty"`
	// Links holds related URLs keyed by link relation type (ticket, review,
	// cancel). OPTIONAL.
	Links map[string]string `json:"links,omitempty"`
	// Items holds per-item progress for bundled Access Requests, positionally
	// corresponding to the submission's items. REQUIRED when the submission
	// carried an items array; otherwise OPTIONAL.
	Items []TaskItem `json:"items,omitempty"`
}

// Progress describes approval-workflow progress for a task with multi-step
// approvals.
//
// AuthZEN Access Request and Approval Profile, Section 10.2, task.progress.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.2
type Progress struct {
	// CurrentStep is the one-based index of the step currently in progress.
	// OPTIONAL.
	CurrentStep int `json:"current_step,omitempty"`
	// TotalSteps is the total number of approval steps configured. OPTIONAL.
	TotalSteps int `json:"total_steps,omitempty"`
	// StepName is a short identifier of the current step. OPTIONAL.
	StepName string `json:"step_name,omitempty"`
	// Awaiting lists identifiers of approvers whose action is expected.
	// OPTIONAL; subject to privacy controls (Section 20).
	Awaiting []string `json:"awaiting,omitempty"`
}

// TaskItem is the per-item progress for one member of a bundled task.
//
// AuthZEN Access Request and Approval Profile, Section 10.2, task.items.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-10.2
type TaskItem struct {
	// Resource echoes the submission's item Resource. REQUIRED.
	Resource *Resource `json:"resource"`
	// Action echoes the submission's item Action. REQUIRED.
	Action *Action `json:"action"`
	// Status is the per-item status. REQUIRED.
	Status TaskStatus `json:"status"`
	// Result is the per-item completion result. REQUIRED when the item status is
	// approved; otherwise OPTIONAL.
	Result *Result `json:"result,omitempty"`
}

// CompletionMode identifies how an approved Access Request is enforced.
//
// AuthZEN Access Request and Approval Profile, Section 12 (Completion
// Semantics).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
type CompletionMode string

// ModeReevaluate is the single completion mode defined by the base profile: the
// PEP performs a new AuthZEN Access Evaluation after approval, so the PDP
// remains authoritative at enforcement time. A PEP that receives an unknown
// result.mode MUST treat the task as not approved.
const ModeReevaluate CompletionMode = "reevaluate"

// Result is the completion result of an Access Request task.
//
// AuthZEN Access Request and Approval Profile, Section 12.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
type Result struct {
	// Mode identifies the completion mode. REQUIRED.
	Mode CompletionMode `json:"mode"`
	// Approval identifies the approval that completed the task. REQUIRED when
	// Mode is reevaluate.
	Approval *Approval `json:"approval,omitempty"`
}

// Approval is the approval reference a PEP carries into a re-evaluation at
// context.approval. It is not a bearer grant: the PDP MUST resolve or verify it
// and confirm it is bound to the authenticated caller, Subject, Resource,
// Action, relevant Context, approval scope, and approval expiry.
//
// AuthZEN Access Request and Approval Profile, Section 12, approval object.
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html#section-12
type Approval struct {
	// ID is a stable, opaque, unguessable identifier of the approval. REQUIRED.
	ID string `json:"id"`
	// ApprovedAt is the RFC 3339 time the approval completed. OPTIONAL.
	ApprovedAt string `json:"approved_at,omitempty"`
	// ApprovedUntil is the RFC 3339 latest time through which the approval
	// remains valid; the PEP MUST NOT use the approval after it. REQUIRED.
	ApprovedUntil string `json:"approved_until"`
	// State is opaque verifier state (for example a JWS) the PDP needs at
	// re-evaluation time. The PEP MUST preserve it exactly and MUST NOT modify
	// or interpret it. OPTIONAL.
	State any `json:"state,omitempty"`
}
