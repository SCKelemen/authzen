package authzen

// Subject is the principal (user, service, device, ...) whose access is being
// evaluated. The type/id pair uniquely identifies the subject, and properties
// carries any additional attributes (for example department, group
// memberships, device_id, or ip_address).
//
// OpenID AuthZEN Authorization API 1.0, Section 5.1 (Subject).
// https://openid.net/specs/authorization-api-1_0.html
type Subject struct {
	// Type is the type of the subject. REQUIRED.
	Type string `json:"type"`
	// ID is the unique identifier of the subject, scoped to Type. REQUIRED for
	// an evaluation, but omitted for a Subject Search query (Section 8.4); the
	// id is therefore omitempty on the wire and enforced by Validate where it
	// is required.
	ID string `json:"id,omitempty"`
	// Properties holds additional subject attributes (simple or complex
	// values). OPTIONAL.
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the target of the requested access (the object being protected).
// The type/id pair uniquely identifies the resource, and properties carries any
// additional, possibly nested, attributes.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.2 (Resource).
// https://openid.net/specs/authorization-api-1_0.html
type Resource struct {
	// Type is the type of the resource. REQUIRED.
	Type string `json:"type"`
	// ID is the unique identifier of the resource, scoped to Type. REQUIRED for
	// an evaluation, but omitted for a Resource Search query (Section 8.5); the
	// id is therefore omitempty on the wire and enforced by Validate where it
	// is required.
	ID string `json:"id,omitempty"`
	// Properties holds additional resource attributes/metadata, which may be
	// nested objects. OPTIONAL.
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the verb or operation the subject wishes to perform on the
// resource. Properties carries any parameters of the action.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.3 (Action).
// https://openid.net/specs/authorization-api-1_0.html
type Action struct {
	// Name is the name of the action. REQUIRED.
	Name string `json:"name"`
	// Properties holds additional action parameters. OPTIONAL.
	Properties map[string]any `json:"properties,omitempty"`
}

// Context is a free-form set of environment or request attributes (for example
// time, location, or PEP capabilities). The specification defines no required
// keys.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.4 (Context).
// https://openid.net/specs/authorization-api-1_0.html
type Context map[string]any
