// Package client implements a Policy Enforcement Point (PEP) client for the
// OpenID AuthZEN Authorization API 1.0 over the normative HTTPS + JSON binding.
//
// The client speaks the Access Evaluation API (Section 6), the Access
// Evaluations / batch API (Section 7), the Subject, Resource, and Action Search
// APIs (Section 8), and discovers PDP configuration from the well-known
// metadata document (Section 9). Every request is an HTTPS POST with a JSON
// object body and Content-Type/Accept of application/json, except metadata
// which is retrieved with GET (Section 10.1, Table 1).
//
// Authentication of the API itself is out of scope of the specification, but
// OAuth 2.0 bearer tokens are RECOMMENDED (Section 0, Section 11.2); this client
// supports a static bearer token or an arbitrary per-request auth hook.
//
// OpenID AuthZEN Authorization API 1.0, Section 10 (Transport).
// https://openid.net/specs/authorization-api-1_0.html#name-transport
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	authzen "github.com/SCKelemen/authzen"
)

// Client is a PEP that calls an AuthZEN PDP over HTTPS + JSON. The zero value is
// not usable; construct one with New, or populate BaseURL (and optionally
// HTTPClient and the auth fields) directly.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport).
// https://openid.net/specs/authorization-api-1_0.html#name-transport
type Client struct {
	// BaseURL is the PDP base URL (policy_decision_point), for example
	// "https://pdp.example.com". Default endpoint paths are appended to it
	// unless an absolute per-endpoint URL is configured.
	BaseURL string

	// HTTPClient performs the HTTP requests. When nil, http.DefaultClient is
	// used. The PEP↔PDP connection MUST be secured with TLS (Section 11.1);
	// callers may install a custom Transport (for example for mTLS) here.
	HTTPClient *http.Client

	// BearerToken, when non-empty, is sent as an OAuth 2.0 bearer token in the
	// Authorization header. RECOMMENDED by the specification (Section 11.2).
	//
	// https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
	BearerToken string

	// AuthFunc, when non-nil, is invoked for every request after the bearer
	// token (if any) has been applied, allowing arbitrary authentication
	// schemes (signed requests, API keys, token refresh, ...). It runs after
	// BearerToken so it may override the Authorization header.
	AuthFunc func(*http.Request) error

	// The *Path fields override the default request paths from Table 1. Each
	// may be a path (joined onto BaseURL) or an absolute URL (used verbatim,
	// for example a value taken from PDP metadata). Empty means use the
	// authzen default path constant.
	EvaluationPath     string
	EvaluationsPath    string
	SearchSubjectPath  string
	SearchResourcePath string
	SearchActionPath   string

	// ExpectedIssuer is the identifier the well-known metadata document is
	// expected to assert as its policy_decision_point. When empty, BaseURL is
	// used. Metadata validates the discovered policy_decision_point against
	// this value to prevent PDP mix-up attacks (Section 9.2.3).
	ExpectedIssuer string

	// SkipMetadataValidation disables the Section 9.2.3 policy_decision_point
	// check performed by Metadata. It defaults to false (the MUST check is
	// enforced); set it only when a caller has an out-of-band reason to trust a
	// document whose identifier differs from the derivation origin.
	SkipMetadataValidation bool
}

// Option configures a Client built with New.
type Option func(*Client)

// WithHTTPClient sets the underlying *http.Client used for transport.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.HTTPClient = hc }
}

// WithBearerToken configures a static OAuth 2.0 bearer token sent in the
// Authorization header of every request (Section 11.2).
//
// https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
func WithBearerToken(token string) Option {
	return func(c *Client) { c.BearerToken = token }
}

// WithAuthFunc installs an arbitrary per-request authentication hook, invoked
// after any static bearer token has been applied.
func WithAuthFunc(fn func(*http.Request) error) Option {
	return func(c *Client) { c.AuthFunc = fn }
}

// WithEvaluationPath overrides the Access Evaluation endpoint path or URL.
func WithEvaluationPath(p string) Option {
	return func(c *Client) { c.EvaluationPath = p }
}

// WithEvaluationsPath overrides the Access Evaluations (batch) endpoint path or
// URL.
func WithEvaluationsPath(p string) Option {
	return func(c *Client) { c.EvaluationsPath = p }
}

// WithSearchSubjectPath overrides the Subject Search endpoint path or URL.
func WithSearchSubjectPath(p string) Option {
	return func(c *Client) { c.SearchSubjectPath = p }
}

// WithSearchResourcePath overrides the Resource Search endpoint path or URL.
func WithSearchResourcePath(p string) Option {
	return func(c *Client) { c.SearchResourcePath = p }
}

// WithSearchActionPath overrides the Action Search endpoint path or URL.
func WithSearchActionPath(p string) Option {
	return func(c *Client) { c.SearchActionPath = p }
}

// WithExpectedIssuer sets the identifier that the discovered metadata's
// policy_decision_point MUST match (Section 9.2.3). When unset, the client's
// BaseURL is used as the expected identifier.
func WithExpectedIssuer(issuer string) Option {
	return func(c *Client) { c.ExpectedIssuer = issuer }
}

// WithInsecureSkipMetadataValidation disables the Section 9.2.3
// policy_decision_point check in Metadata. This relaxes a normative MUST and
// should only be used when the caller trusts the document by other means.
func WithInsecureSkipMetadataValidation() Option {
	return func(c *Client) { c.SkipMetadataValidation = true }
}

// New returns a Client targeting the given PDP base URL with the supplied
// options applied.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{BaseURL: baseURL}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// APIError is returned when the PDP responds with a non-2xx HTTP status. Such
// statuses are transport-level errors and are unrelated to the authorization
// outcome: a deny is a successful HTTP 200 with {"decision": false}, not an
// HTTP error (Section 10.1.2). APIError can be inspected with errors.As.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2 (Error responses).
// https://openid.net/specs/authorization-api-1_0.html#name-error-responses
type APIError struct {
	// StatusCode is the HTTP status code returned by the PDP.
	StatusCode int
	// Body is the raw response body, which Table 2 describes as an error
	// message (the encoding is implementation-specific).
	Body []byte
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("authzen client: unexpected HTTP status %d", e.StatusCode)
	}
	return fmt.Sprintf("authzen client: unexpected HTTP status %d: %s", e.StatusCode, strings.TrimSpace(string(e.Body)))
}

// Evaluate calls the Access Evaluation API (a single decision). The request is
// validated client-side before being sent; a deny is reported as a successful
// response with Decision == false, not as an error.
//
// OpenID AuthZEN Authorization API 1.0, Section 6 (Access Evaluation API).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-api
func (c *Client) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("authzen client: nil EvaluationRequest")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out authzen.EvaluationResponse
	if err := c.post(ctx, c.endpoint(c.EvaluationPath, authzen.DefaultEvaluationPath), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EvaluateBatch calls the Access Evaluations (batch) API. The request is
// validated client-side, including the options.evaluations_semantic value.
//
// OpenID AuthZEN Authorization API 1.0, Section 7 (Access Evaluations API).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-api
func (c *Client) EvaluateBatch(ctx context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("authzen client: nil EvaluationsRequest")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out authzen.EvaluationsResponse
	if err := c.post(ctx, c.endpoint(c.EvaluationsPath, authzen.DefaultEvaluationsPath), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SearchSubjects calls the Subject Search API ("who can do action on
// resource?"). The request is validated client-side.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.4 (Subject Search).
// https://openid.net/specs/authorization-api-1_0.html#name-subject-search
func (c *Client) SearchSubjects(ctx context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("authzen client: nil SubjectSearchRequest")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out authzen.SubjectSearchResponse
	if err := c.post(ctx, c.endpoint(c.SearchSubjectPath, authzen.DefaultSearchSubjectPath), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SearchResources calls the Resource Search API ("which resources can subject
// do action on?"). The request is validated client-side.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.5 (Resource Search).
// https://openid.net/specs/authorization-api-1_0.html#name-resource-search
func (c *Client) SearchResources(ctx context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("authzen client: nil ResourceSearchRequest")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out authzen.ResourceSearchResponse
	if err := c.post(ctx, c.endpoint(c.SearchResourcePath, authzen.DefaultSearchResourcePath), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SearchActions calls the Action Search API ("what actions can subject perform
// on resource?"). The request is validated client-side.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.6 (Action Search).
// https://openid.net/specs/authorization-api-1_0.html#name-action-search
func (c *Client) SearchActions(ctx context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("authzen client: nil ActionSearchRequest")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out authzen.ActionSearchResponse
	if err := c.post(ctx, c.endpoint(c.SearchActionPath, authzen.DefaultSearchActionPath), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MetadataValidationError reports that a discovered PDP metadata document failed
// the Section 9.2.3 check: its policy_decision_point did not match the
// identifier the well-known URL was derived from. Per the specification the
// document MUST be discarded in this case, so Metadata returns this error and
// no metadata. It can be inspected with errors.As.
//
// OpenID AuthZEN Authorization API 1.0, Section 9.2.3 (Validating metadata).
// https://openid.net/specs/authorization-api-1_0.html#name-metadata
type MetadataValidationError struct {
	// Expected is the identifier the client derived discovery from.
	Expected string
	// Got is the policy_decision_point asserted by the fetched document.
	Got string
}

// Error implements the error interface.
func (e *MetadataValidationError) Error() string {
	return fmt.Sprintf("authzen client: metadata policy_decision_point %q does not match expected issuer %q (Section 9.2.3)", e.Got, e.Expected)
}

// Metadata retrieves the PDP configuration document from
// /.well-known/authzen-configuration with an HTTP GET. Unless validation is
// disabled, it then enforces Section 9.2.3 by requiring the document's
// policy_decision_point to match the identifier discovery was derived from
// (ExpectedIssuer, or BaseURL when unset); on mismatch it discards the document
// and returns a *MetadataValidationError. This prevents PDP mix-up attacks.
//
// OpenID AuthZEN Authorization API 1.0, Section 9.2 (Obtaining metadata) and
// Section 9.2.3 (Validating metadata).
// https://openid.net/specs/authorization-api-1_0.html#name-obtaining-metadata
func (c *Client) Metadata(ctx context.Context) (*authzen.Metadata, error) {
	endpoint := strings.TrimRight(c.BaseURL, "/") + authzen.WellKnownConfigurationPath
	var out authzen.Metadata
	if err := c.get(ctx, endpoint, &out); err != nil {
		return nil, err
	}
	if !c.SkipMetadataValidation {
		expected := c.ExpectedIssuer
		if expected == "" {
			expected = c.BaseURL
		}
		if !sameIssuer(expected, out.PolicyDecisionPoint) {
			return nil, &MetadataValidationError{Expected: expected, Got: out.PolicyDecisionPoint}
		}
	}
	return &out, nil
}

// sameIssuer reports whether two URLs identify the same PDP for the purposes of
// Section 9.2.3: the scheme and host must match (case-insensitively) and the
// paths must match once any trailing slash is removed. Query and fragment are
// ignored because policy_decision_point carries neither.
func sameIssuer(expected, got string) bool {
	e, err := url.Parse(expected)
	if err != nil {
		return false
	}
	g, err := url.Parse(got)
	if err != nil {
		return false
	}
	return strings.EqualFold(e.Scheme, g.Scheme) &&
		strings.EqualFold(e.Host, g.Host) &&
		strings.TrimRight(e.Path, "/") == strings.TrimRight(g.Path, "/")
}

// endpoint resolves the URL for an endpoint: an empty custom value falls back to
// the default path; a value containing "://" is treated as an absolute URL and
// used verbatim (for example a URL discovered via metadata); otherwise the path
// is appended to BaseURL.
func (c *Client) endpoint(custom, def string) string {
	p := custom
	if p == "" {
		p = def
	}
	if strings.Contains(p, "://") {
		return p
	}
	return strings.TrimRight(c.BaseURL, "/") + p
}

// post marshals body to JSON, performs an authenticated POST, and decodes a 2xx
// JSON response into out. Non-2xx responses are mapped to *APIError.
func (c *Client) post(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("authzen client: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("authzen client: build request: %w", err)
	}
	// The request Content-Type MUST be application/json (Section 10.1).
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

// get performs an authenticated GET and decodes a 2xx JSON response into out.
func (c *Client) get(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("authzen client: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

// do applies authentication, executes the request, and decodes the response.
func (c *Client) do(req *http.Request, out any) error {
	if err := c.applyAuth(req); err != nil {
		return err
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("authzen client: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("authzen client: read response: %w", err)
	}
	// Any non-2xx status is a transport-level error, distinct from a deny
	// decision which is returned as HTTP 200 (Section 10.1.2).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: data}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("authzen client: decode response: %w", err)
	}
	return nil
}

// applyAuth attaches authentication credentials to the request: a static bearer
// token first (if configured), then any custom auth hook.
func (c *Client) applyAuth(req *http.Request) error {
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	if c.AuthFunc != nil {
		if err := c.AuthFunc(req); err != nil {
			return fmt.Errorf("authzen client: auth hook: %w", err)
		}
	}
	return nil
}
