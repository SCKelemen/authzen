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
		// evaluations_semantic MUST be a JSON string. A non-string value
		// (number, boolean, object, ...) is rejected rather than silently
		// swallowed; otherwise an invalid/typo'd option would be downgraded
		// to the default execute_all semantic without the caller noticing.
		//
		// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1
		// (evaluations_semantic) and Section 10.1.1 (a malformed required
		// attribute MUST be rejected).
		// https://openid.net/specs/authorization-api-1_0.html
		s, ok := v.(string)
		if !ok {
			return newValidationError("options.evaluations_semantic", ErrInvalidSemantic)
		}
		o.EvaluationsSemantic = EvaluationsSemantic(s)
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
			Subject:  cloneSubject(r.Subject),
			Action:   cloneAction(r.Action),
			Resource: cloneResource(r.Resource),
			Context:  cloneContext(r.Context),
		}}
	}
	out := make([]EvaluationRequest, len(r.Evaluations))
	for i, e := range r.Evaluations {
		// Select the member's own value where present, otherwise inherit the
		// top-level default. Each selected value is then copied so that no two
		// resolved members alias the same Subject/Action/Resource pointer or
		// Context map, and so that a PDP mutating a resolved member's
		// context/properties cannot contaminate sibling members or the caller's
		// original request.
		subject := e.Subject
		if subject == nil {
			subject = r.Subject
		}
		action := e.Action
		if action == nil {
			action = r.Action
		}
		resource := e.Resource
		if resource == nil {
			resource = r.Resource
		}
		ctx := e.Context
		if ctx == nil {
			ctx = r.Context
		}
		out[i] = EvaluationRequest{
			Subject:  cloneSubject(subject),
			Action:   cloneAction(action),
			Resource: cloneResource(resource),
			Context:  cloneContext(ctx),
		}
	}
	return out
}

// cloneSubject returns a shallow copy of s with its Properties map cloned so
// that the result shares no mutable state with s. It returns nil for a nil
// input.
func cloneSubject(s *Subject) *Subject {
	if s == nil {
		return nil
	}
	c := *s
	c.Properties = cloneAnyMap(s.Properties)
	return &c
}

// cloneAction returns a shallow copy of a with its Properties map cloned.
func cloneAction(a *Action) *Action {
	if a == nil {
		return nil
	}
	c := *a
	c.Properties = cloneAnyMap(a.Properties)
	return &c
}

// cloneResource returns a shallow copy of r with its Properties map cloned.
func cloneResource(r *Resource) *Resource {
	if r == nil {
		return nil
	}
	c := *r
	c.Properties = cloneAnyMap(r.Properties)
	return &c
}

// cloneContext returns a clone of the Context map so that resolved members do
// not share the caller's context map.
func cloneContext(c Context) Context {
	if c == nil {
		return nil
	}
	out := make(Context, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

// cloneAnyMap returns a shallow clone of a string-keyed map, copying the
// top-level entries. Nested reference values are not deep-copied.
func cloneAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
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
// For backwards compatibility, a request that carries no (or an empty)
// evaluations array MUST be answered with the single Access Evaluation response
// shape of Section 6.2 — a top-level {"decision":...,"context":...} object —
// rather than the {"evaluations":[...]} batch shape. This type encodes both
// shapes: when Decision is non-nil the value marshals in the single-decision
// mode; otherwise it marshals the (batch) evaluations array.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1 (Access Evaluations
// Request, backwards compatibility), Section 7.2 (Access Evaluations Response),
// and Section 6.2 (Access Evaluation Response).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-response
type EvaluationsResponse struct {
	// Decision, when non-nil, selects the single-decision backwards-compatible
	// response shape of Section 6.2 (true permits, false denies). It is set for
	// a request that omits the evaluations array; leave it nil for a batch
	// response. OPTIONAL.
	Decision *bool
	// Context carries the optional, implementation-specific decision context
	// accompanying a single-decision response (Section 6.2). It is only emitted
	// in the single-decision mode. OPTIONAL.
	Context map[string]any
	// Evaluations holds the per-request decisions in request order for a batch
	// response (Section 7.2).
	Evaluations []EvaluationResponse
}

// SingleDecision builds an EvaluationsResponse in the backwards-compatible
// single-decision mode (Section 6.2), as required when the originating request
// carried no evaluations array (Section 7.1).
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1 and Section 6.2.
// https://openid.net/specs/authorization-api-1_0.html
func SingleDecision(decision bool, ctx map[string]any) EvaluationsResponse {
	return EvaluationsResponse{Decision: &decision, Context: ctx}
}

// MarshalJSON encodes the response in one of two shapes. When Decision is
// non-nil it emits the single Access Evaluation response object of Section 6.2,
// {"decision":...,"context":...}, and omits the evaluations array entirely.
// Otherwise it emits the batch shape, {"evaluations":[...]}, normalizing a nil
// slice to an empty array so the key is never serialized as JSON null.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2 (Access Evaluations
// Response) and Section 6.2 (Access Evaluation Response).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-response
func (r EvaluationsResponse) MarshalJSON() ([]byte, error) {
	if r.Decision != nil {
		return json.Marshal(struct {
			Decision bool           `json:"decision"`
			Context  map[string]any `json:"context,omitempty"`
		}{Decision: *r.Decision, Context: r.Context})
	}
	evals := r.Evaluations
	if evals == nil {
		evals = []EvaluationResponse{}
	}
	return json.Marshal(struct {
		Evaluations []EvaluationResponse `json:"evaluations"`
	}{Evaluations: evals})
}

// UnmarshalJSON decodes either response shape. When an evaluations array is
// present (batch mode, Section 7.2) it is decoded into Evaluations and a nil
// array is normalized to an empty slice. Otherwise the body is treated as a
// single Access Evaluation response (Section 6.2) and decoded into Decision and
// Context.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2 (Access Evaluations
// Response) and Section 6.2 (Access Evaluation Response).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-response
func (r *EvaluationsResponse) UnmarshalJSON(data []byte) error {
	var raw struct {
		Decision    *bool                 `json:"decision"`
		Context     map[string]any        `json:"context"`
		Evaluations *[]EvaluationResponse `json:"evaluations"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Decision = nil
	r.Context = nil
	r.Evaluations = nil
	if raw.Evaluations != nil {
		// Batch mode: an evaluations array was present. A top-level decision,
		// if any, SHOULD be omitted and is ignored here (Section 7.2).
		if *raw.Evaluations == nil {
			r.Evaluations = []EvaluationResponse{}
		} else {
			r.Evaluations = *raw.Evaluations
		}
		return nil
	}
	// Single-decision backwards-compatible mode (Section 6.2).
	r.Decision = raw.Decision
	r.Context = raw.Context
	return nil
}
