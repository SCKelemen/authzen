package authzen

import (
	"encoding/json"
	"fmt"
)

// EvaluationsSemantic selects how a PDP executes the members of a batch request
// and which decisions it returns.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1 (evaluations_semantic).
// https://openid.net/specs/authorization-api-1_0.html
type EvaluationsSemantic string

const (
	// SemanticExecuteAll executes every evaluation (possibly in parallel) and
	// returns all results in request order. This is the default when
	// options.evaluations_semantic is omitted.
	//
	// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1.
	// https://openid.net/specs/authorization-api-1_0.html
	SemanticExecuteAll EvaluationsSemantic = "execute_all"

	// SemanticDenyOnFirstDeny short-circuits on the first denial or failure and
	// returns the results up to and including that deny (logical AND).
	//
	// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1.
	// https://openid.net/specs/authorization-api-1_0.html
	SemanticDenyOnFirstDeny EvaluationsSemantic = "deny_on_first_deny"

	// SemanticPermitOnFirstPermit short-circuits on the first permit and
	// returns the results up to and including that permit (logical OR).
	//
	// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1.
	// https://openid.net/specs/authorization-api-1_0.html
	SemanticPermitOnFirstPermit EvaluationsSemantic = "permit_on_first_permit"
)

// Options carries PEP-supplied execution metadata for a batch request. The
// specification defines evaluations_semantic and permits arbitrary additional
// keys, which are preserved in Additional.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.2 (options).
// https://openid.net/specs/authorization-api-1_0.html
type Options struct {
	// EvaluationsSemantic selects the batch execution semantic. OPTIONAL;
	// absence means SemanticExecuteAll.
	EvaluationsSemantic EvaluationsSemantic
	// Additional holds any implementation-specific options keys other than
	// evaluations_semantic. OPTIONAL.
	Additional map[string]any
}

// MarshalJSON encodes the Options as a single JSON object, merging the
// evaluations_semantic key (when set) with any Additional keys.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.2 (options).
// https://openid.net/specs/authorization-api-1_0.html
func (o Options) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(o.Additional)+1)
	for k, v := range o.Additional {
		m[k] = v
	}
	if o.EvaluationsSemantic != "" {
		m["evaluations_semantic"] = string(o.EvaluationsSemantic)
	}
	return json.Marshal(m)
}

// UnmarshalJSON decodes a JSON options object, extracting evaluations_semantic
// and retaining every other key in Additional.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.2 (options).
// https://openid.net/specs/authorization-api-1_0.html
func (o *Options) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	o.EvaluationsSemantic = ""
	o.Additional = nil
	if v, ok := m["evaluations_semantic"]; ok {
		if s, ok := v.(string); ok {
			o.EvaluationsSemantic = EvaluationsSemantic(s)
		}
		delete(m, "evaluations_semantic")
	}
	if len(m) > 0 {
		o.Additional = m
	}
	return nil
}

// EvaluationsRequest is the body of an Access Evaluations (batch) request. The
// top-level subject, action, resource, and context provide default values for
// every member of the evaluations array; a key set inside a member overrides
// the corresponding default. When evaluations is absent or empty, the request
// behaves identically to a single Access Evaluation request.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1 (Access Evaluations
// Request).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-request
type EvaluationsRequest struct {
	// Subject is the top-level default subject. Conditionally REQUIRED: any
	// member that omits its subject inherits this value.
	Subject *Subject `json:"subject,omitempty"`
	// Action is the top-level default action. Conditionally REQUIRED.
	Action *Action `json:"action,omitempty"`
	// Resource is the top-level default resource. Conditionally REQUIRED.
	Resource *Resource `json:"resource,omitempty"`
	// Context is the top-level default context. OPTIONAL.
	Context Context `json:"context,omitempty"`
	// Evaluations holds the discrete sub-requests. OPTIONAL; when absent or
	// empty the request is treated as a single evaluation.
	Evaluations []EvaluationRequest `json:"evaluations,omitempty"`
	// Options carries execution metadata such as evaluations_semantic.
	// OPTIONAL.
	Options *Options `json:"options,omitempty"`
}

// Resolved returns the fully specified evaluation requests implied by the batch,
// applying the top-level subject/action/resource/context defaults to every
// member that omits them. A member's own value always overrides the default.
// When Evaluations is absent or empty, a single request built from the
// top-level fields is returned, matching the backwards-compatible behavior in
// Section 7.1.1.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.1 (Defaulting rules).
// https://openid.net/specs/authorization-api-1_0.html
func (r *EvaluationsRequest) Resolved() []EvaluationRequest {
	if len(r.Evaluations) == 0 {
		return []EvaluationRequest{{
			Subject:  r.Subject,
			Action:   r.Action,
			Resource: r.Resource,
			Context:  r.Context,
		}}
	}
	out := make([]EvaluationRequest, len(r.Evaluations))
	for i, e := range r.Evaluations {
		merged := e
		if merged.Subject == nil {
			merged.Subject = r.Subject
		}
		if merged.Action == nil {
			merged.Action = r.Action
		}
		if merged.Resource == nil {
			merged.Resource = r.Resource
		}
		if merged.Context == nil {
			merged.Context = r.Context
		}
		out[i] = merged
	}
	return out
}

// Validate checks that every evaluation, after the top-level defaults are
// applied, carries a valid subject, action, and resource, and that any supplied
// options.evaluations_semantic is one of the defined values. It implements the
// REQUIRED-field rules of Section 7.1.1.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1 (Access Evaluations
// Request).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-request
func (r *EvaluationsRequest) Validate() error {
	if r.Options != nil {
		switch r.Options.EvaluationsSemantic {
		case "", SemanticExecuteAll, SemanticDenyOnFirstDeny, SemanticPermitOnFirstPermit:
			// valid
		default:
			return newValidationError("options.evaluations_semantic", ErrInvalidSemantic)
		}
	}

	resolved := r.Resolved()
	single := len(r.Evaluations) == 0
	for i, e := range resolved {
		if err := e.Validate(); err != nil {
			if single {
				return err
			}
			return fmt.Errorf("authzen: evaluations[%d]: %w", i, err)
		}
	}
	return nil
}

// EvaluationsResponse is the body of an Access Evaluations (batch) response. The
// evaluations array holds the decisions in the same order as the request's
// evaluations array; for the short-circuit semantics it may be shorter, ending
// at the deciding element.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2 (Access Evaluations
// Response).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-response
type EvaluationsResponse struct {
	// Evaluations holds the per-request decisions in request order.
	Evaluations []EvaluationResponse `json:"evaluations"`
}
