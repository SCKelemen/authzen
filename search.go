package authzen

// Page is the pagination object sent in a Search request. The first request
// omits token; subsequent requests repeat the opaque next_token returned by the
// PDP until it is the empty string. When a token is supplied, all other request
// parameters MUST be identical to the prior request.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.2.1 (Request page object).
// https://openid.net/specs/authorization-api-1_0.html
type Page struct {
	// Token is the opaque cursor from a previous response's next_token.
	// OPTIONAL.
	Token string `json:"token,omitempty"`
	// Limit is the maximum number of results to return (non-negative).
	// OPTIONAL.
	Limit int `json:"limit,omitempty"`
	// Properties holds implementation-specific paging hints such as sorting or
	// filtering. OPTIONAL.
	Properties map[string]any `json:"properties,omitempty"`
}

// PageResponse is the pagination object returned in a Search response. It is
// RECOMMENDED to be the first key of the response and MUST be present when the
// response is not the complete result set.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.2.2 (Response page object).
// https://openid.net/specs/authorization-api-1_0.html
type PageResponse struct {
	// NextToken is the opaque cursor for the next page. REQUIRED when the page
	// object is present; an empty string indicates the end of results.
	NextToken string `json:"next_token"`
	// Count is the number of results in this response (non-negative). OPTIONAL.
	Count int `json:"count,omitempty"`
	// Total is the total number of matching results at request time, which is
	// not guaranteed to be stable (non-negative). OPTIONAL.
	Total int `json:"total,omitempty"`
	// Properties holds implementation-specific paging metadata. OPTIONAL.
	Properties map[string]any `json:"properties,omitempty"`
}

// SubjectSearchRequest is the body of a Subject Search request, asking which
// subjects of the given type may perform the action on the resource. The
// subject's id SHOULD be omitted and MUST be ignored by the PDP if present.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.4 (Subject Search).
// https://openid.net/specs/authorization-api-1_0.html
type SubjectSearchRequest struct {
	// Subject identifies the type of subject being searched for. REQUIRED
	// (type only).
	Subject *Subject `json:"subject,omitempty"`
	// Action is the operation being tested. REQUIRED.
	Action *Action `json:"action,omitempty"`
	// Resource is the target of the operation. REQUIRED.
	Resource *Resource `json:"resource,omitempty"`
	// Context carries optional environment/request attributes. OPTIONAL.
	Context Context `json:"context,omitempty"`
	// Page carries pagination parameters. OPTIONAL.
	Page *Page `json:"page,omitempty"`
}

// Validate checks the fields REQUIRED for a Subject Search: a subject with a
// type, a valid action, and a valid resource. The subject's id is not required
// and is not validated here.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.4 (Subject Search).
// https://openid.net/specs/authorization-api-1_0.html
func (r *SubjectSearchRequest) Validate() error {
	if r.Subject == nil {
		return newValidationError("subject", ErrMissingSubject)
	}
	if r.Subject.Type == "" {
		return newValidationError("subject.type", ErrMissingType)
	}
	if err := r.Action.Validate(); err != nil {
		return err
	}
	return r.Resource.Validate()
}

// ResourceSearchRequest is the body of a Resource Search request, asking which
// resources of the given type the subject may perform the action on. The
// resource's id SHOULD be omitted and MUST be ignored by the PDP if present.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.5 (Resource Search).
// https://openid.net/specs/authorization-api-1_0.html
type ResourceSearchRequest struct {
	// Subject is the principal. REQUIRED.
	Subject *Subject `json:"subject,omitempty"`
	// Action is the operation being tested. REQUIRED.
	Action *Action `json:"action,omitempty"`
	// Resource identifies the type of resource being searched for. REQUIRED
	// (type only).
	Resource *Resource `json:"resource,omitempty"`
	// Context carries optional environment/request attributes. OPTIONAL.
	Context Context `json:"context,omitempty"`
	// Page carries pagination parameters. OPTIONAL.
	Page *Page `json:"page,omitempty"`
}

// Validate checks the fields REQUIRED for a Resource Search: a valid subject, a
// valid action, and a resource with a type. The resource's id is not required
// and is not validated here.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.5 (Resource Search).
// https://openid.net/specs/authorization-api-1_0.html
func (r *ResourceSearchRequest) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if err := r.Action.Validate(); err != nil {
		return err
	}
	if r.Resource == nil {
		return newValidationError("resource", ErrMissingResource)
	}
	if r.Resource.Type == "" {
		return newValidationError("resource.type", ErrMissingType)
	}
	return nil
}

// ActionSearchRequest is the body of an Action Search request, asking which
// actions the subject may perform on the resource. The action key is omitted
// from the request payload entirely.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.6 (Action Search).
// https://openid.net/specs/authorization-api-1_0.html
type ActionSearchRequest struct {
	// Subject is the principal. REQUIRED.
	Subject *Subject `json:"subject,omitempty"`
	// Resource is the target. REQUIRED.
	Resource *Resource `json:"resource,omitempty"`
	// Context carries optional environment/request attributes. OPTIONAL.
	Context Context `json:"context,omitempty"`
	// Page carries pagination parameters. OPTIONAL.
	Page *Page `json:"page,omitempty"`
}

// Validate checks the fields REQUIRED for an Action Search: a valid subject and
// a valid resource. No action is part of an Action Search request.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.6 (Action Search).
// https://openid.net/specs/authorization-api-1_0.html
func (r *ActionSearchRequest) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	return r.Resource.Validate()
}

// SubjectSearchResponse is the body of a Subject Search response. results holds
// zero or more subjects (only of the searched type); page and context are
// optional. The page field is declared first because the specification
// RECOMMENDS it as the first key.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.3 (Search response) and
// Section 8.4.
// https://openid.net/specs/authorization-api-1_0.html
type SubjectSearchResponse struct {
	// Page carries pagination metadata. OPTIONAL (but MUST be present when the
	// result set is incomplete).
	Page *PageResponse `json:"page,omitempty"`
	// Results holds the authorized subjects. REQUIRED.
	Results []Subject `json:"results"`
	// Context carries optional, implementation-specific information. OPTIONAL.
	Context map[string]any `json:"context,omitempty"`
}

// ResourceSearchResponse is the body of a Resource Search response. results
// holds zero or more resources (only of the searched type); page and context
// are optional.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.3 (Search response) and
// Section 8.5.
// https://openid.net/specs/authorization-api-1_0.html
type ResourceSearchResponse struct {
	// Page carries pagination metadata. OPTIONAL (but MUST be present when the
	// result set is incomplete).
	Page *PageResponse `json:"page,omitempty"`
	// Results holds the authorized resources. REQUIRED.
	Results []Resource `json:"results"`
	// Context carries optional, implementation-specific information. OPTIONAL.
	Context map[string]any `json:"context,omitempty"`
}

// ActionSearchResponse is the body of an Action Search response. results holds
// zero or more actions; page and context are optional.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.3 (Search response) and
// Section 8.6.
// https://openid.net/specs/authorization-api-1_0.html
type ActionSearchResponse struct {
	// Page carries pagination metadata. OPTIONAL (but MUST be present when the
	// result set is incomplete).
	Page *PageResponse `json:"page,omitempty"`
	// Results holds the authorized actions. REQUIRED.
	Results []Action `json:"results"`
	// Context carries optional, implementation-specific information. OPTIONAL.
	Context map[string]any `json:"context,omitempty"`
}
