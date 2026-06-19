package authzen

// Default request paths for the AuthZEN APIs in the normative HTTPS + JSON
// binding. A PEP MUST use the URL advertised by the corresponding metadata
// parameter when present, and SHOULD otherwise form the URL by appending these
// default paths to the PDP base URL (policy_decision_point).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport), Table 1.
// https://openid.net/specs/authorization-api-1_0.html
const (
	// DefaultEvaluationPath is the default path of the Access Evaluation API.
	DefaultEvaluationPath = "/access/v1/evaluation"
	// DefaultEvaluationsPath is the default path of the Access Evaluations
	// (batch) API.
	DefaultEvaluationsPath = "/access/v1/evaluations"
	// DefaultSearchSubjectPath is the default path of the Subject Search API.
	DefaultSearchSubjectPath = "/access/v1/search/subject"
	// DefaultSearchResourcePath is the default path of the Resource Search API.
	DefaultSearchResourcePath = "/access/v1/search/resource"
	// DefaultSearchActionPath is the default path of the Action Search API.
	DefaultSearchActionPath = "/access/v1/search/action"
)

// Well-known metadata location constants.
//
// OpenID AuthZEN Authorization API 1.0, Section 9.2 (Obtaining metadata) and
// Section 12.2 (Well-Known URI registration).
// https://openid.net/specs/authorization-api-1_0.html
const (
	// WellKnownConfigurationSuffix is the registered well-known URI suffix for
	// the PDP configuration document.
	WellKnownConfigurationSuffix = "authzen-configuration"
	// WellKnownConfigurationPath is the default path of the PDP metadata
	// document, retrieved with HTTP GET.
	WellKnownConfigurationPath = "/.well-known/authzen-configuration"
)

// Metadata is the PDP configuration document published at
// /.well-known/authzen-configuration. It advertises the PDP base URL and the
// endpoints the PDP supports; an absent endpoint parameter signals that the
// corresponding API is unsupported. Parameters with no value are omitted rather
// than serialized as null, and unknown parameters MUST be ignored by the PEP.
//
// OpenID AuthZEN Authorization API 1.0, Section 9.1 (Metadata) and Section
// 12.1.3 (PDP Metadata registry).
// https://openid.net/specs/authorization-api-1_0.html
type Metadata struct {
	// PolicyDecisionPoint is the base URL of the PDP. REQUIRED. It MUST equal
	// the identifier the well-known URL was derived from, else the PEP discards
	// the document.
	PolicyDecisionPoint string `json:"policy_decision_point"`
	// AccessEvaluationEndpoint is the URL of the Access Evaluation API.
	// REQUIRED.
	AccessEvaluationEndpoint string `json:"access_evaluation_endpoint"`
	// AccessEvaluationsEndpoint is the URL of the Access Evaluations (batch)
	// API. OPTIONAL; absence signals batch is unsupported.
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint,omitempty"`
	// SearchSubjectEndpoint is the URL of the Subject Search API. OPTIONAL.
	SearchSubjectEndpoint string `json:"search_subject_endpoint,omitempty"`
	// SearchResourceEndpoint is the URL of the Resource Search API. OPTIONAL.
	SearchResourceEndpoint string `json:"search_resource_endpoint,omitempty"`
	// SearchActionEndpoint is the URL of the Action Search API. OPTIONAL.
	SearchActionEndpoint string `json:"search_action_endpoint,omitempty"`
	// Capabilities is a JSON array of registered IANA URNs describing
	// PDP-specific capabilities. OPTIONAL.
	Capabilities []string `json:"capabilities,omitempty"`
	// SignedMetadata is a JWT asserting the other parameters as claims; it MUST
	// contain an iss claim and, where supported, takes precedence over the
	// plain JSON values. OPTIONAL.
	SignedMetadata string `json:"signed_metadata,omitempty"`
}
