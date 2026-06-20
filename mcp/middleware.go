package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	authzen "github.com/SCKelemen/authzen"
)

// Authorizer is the decision seam the middleware delegates to: given an
// assembled AuthZEN evaluation request, it returns the PDP's decision.
//
// The signature matches the in-process PDP interface (the grpc package's PDP),
// so an in-process PDP implementation satisfies Authorizer directly. The
// network clients do NOT satisfy it as-is and each need a small adapter
// (typically via AuthorizerFunc):
//   - grpc.Client.Evaluate has a trailing variadic (opts ...grpc.CallOption),
//     so its method value does not match this interface.
//   - client.Client.Evaluate takes and returns pointers
//     (*EvaluationRequest / *EvaluationResponse).
//
// See the package README for both adapters.
//
// A policy deny is NOT an error: it is a successful EvaluationResponse with
// Decision == false. An error returned here is an infrastructure failure and is
// treated fail-closed (see Enforcer).
//
// OpenID AuthZEN Authorization API 1.0, Section 6 (Access Evaluation API).
// https://openid.net/specs/authorization-api-1_0.html
type Authorizer interface {
	Evaluate(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error)
}

// AuthorizerFunc adapts a plain function to the Authorizer interface.
type AuthorizerFunc func(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error)

// Evaluate implements Authorizer.
func (f AuthorizerFunc) Evaluate(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
	return f(ctx, req)
}

// RequestExtractor turns an inbound HTTP request into an MCP Request, including
// the authenticated token claims, the JSON-RPC method, and the targeted
// primitive. It is supplied by the caller because token validation and the MCP
// transport framing (HTTP vs the streamable JSON-RPC body) are
// deployment-specific; the middleware does not parse or verify tokens.
//
// SECURITY — THE EXTRACTOR MUST CRYPTOGRAPHICALLY VERIFY THE TOKEN BEFORE
// RETURNING A Request. It must validate the signature (or introspect the
// token), and check expiry (exp/nbf) and the audience / resource indicator
// (RFC 8707) so the token was actually minted for this server. The TokenClaims
// in the returned Request are trusted verbatim and become the AuthZEN subject;
// building a Request from an unverified or attacker-supplied token FAILS OPEN
// (the PDP would authorize a forged identity). On any verification failure the
// extractor must return an error — ErrNoToken for a missing/unusable token (so
// the middleware answers 401 and starts OAuth discovery), or any other error
// (mapped to a 403 deny).
//
// RFC 9068 - JWT Access Tokens (validation).
// https://www.rfc-editor.org/rfc/rfc9068
// RFC 8707 - Resource Indicators for OAuth 2.0 (audience binding).
// https://www.rfc-editor.org/rfc/rfc8707
// MCP Authorization (2025-06-18).
// https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
type RequestExtractor func(r *http.Request) (Request, error)

// ErrNoToken is the sentinel an extractor returns when the request is
// unauthenticated (no or unusable bearer token). The middleware maps it to a
// 401 challenge that points the client at the Protected Resource Metadata
// document to bootstrap discovery.
//
// RFC 6750 Section 3 - WWW-Authenticate (401 for missing/invalid token).
// https://www.rfc-editor.org/rfc/rfc6750#section-3
var ErrNoToken = errors.New("mcp: no bearer token")

// DenyInfo describes why a request was denied. It is passed to a Responder so a
// caller can customize the wire response while reusing the enforcement logic.
//
// CAUTION: Err is for server-side logging only. A Responder MUST NOT write Err
// (or any internal detail it carries) to the response body or headers; doing so
// risks leaking internal state to the client (information disclosure).
type DenyInfo struct {
	// Challenge is the WWW-Authenticate challenge to emit, with its Status set.
	Challenge Challenge
	// Response is the PDP decision that triggered the deny. It is the zero
	// value when the deny was produced before evaluation (a fail-closed error).
	Response authzen.EvaluationResponse
	// Err is the fail-closed cause (extractor, assembly, or Authorizer error),
	// or nil for an ordinary policy deny (Decision == false). Server-side only;
	// see the type-level caution about not writing it to the wire.
	Err error
}

// Responder writes the HTTP response for a denied request. The default
// responder (defaultResponder) sets the WWW-Authenticate header, the status
// code, and a small RFC 6750-style JSON error body.
//
// A Responder must treat DenyInfo.Err as server-side-only and never serialize
// it to the client (information disclosure).
type Responder func(w http.ResponseWriter, r *http.Request, info DenyInfo)

// Enforcer is an HTTP middleware that makes an MCP server act as an AuthZEN
// Policy Enforcement Point (PEP): it extracts the MCP request, asks the
// Authorizer for a decision, and either passes the request through or denies it
// with an OAuth-shaped challenge.
//
// It is fail-closed: any extractor error, request-assembly/validation error, or
// Authorizer error results in a deny, never a pass-through to the wrapped
// handler.
//
// OpenID AuthZEN Authorization API 1.0, Section 0 (PEP role).
// https://openid.net/specs/authorization-api-1_0.html
type Enforcer struct {
	authorizer       Authorizer
	extract          RequestExtractor
	scope            string
	resourceMetadata string
	realm            string
	respond          Responder
}

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithScope sets the default scope advertised in deny challenges (the scope the
// client must obtain), used when the decision response does not carry one.
func WithScope(scope string) Option {
	return func(e *Enforcer) { e.scope = scope }
}

// WithResourceMetadata sets the RFC 9728 Protected Resource Metadata URL
// advertised in challenges so a client can bootstrap OAuth discovery.
//
// RFC 9728 - OAuth 2.0 Protected Resource Metadata.
// https://www.rfc-editor.org/rfc/rfc9728
func WithResourceMetadata(url string) Option {
	return func(e *Enforcer) { e.resourceMetadata = url }
}

// WithRealm sets the protection realm advertised in challenges.
func WithRealm(realm string) Option {
	return func(e *Enforcer) { e.realm = realm }
}

// WithErrorResponder overrides how denials are written to the response. A nil
// responder is ignored.
func WithErrorResponder(r Responder) Option {
	return func(e *Enforcer) {
		if r != nil {
			e.respond = r
		}
	}
}

// New constructs an Enforcer. It panics if the authorizer or extractor is nil,
// since neither has a safe default and a missing dependency would otherwise
// silently fail open.
func New(a Authorizer, extract RequestExtractor, opts ...Option) *Enforcer {
	if a == nil {
		panic("mcp: nil Authorizer")
	}
	if extract == nil {
		panic("mcp: nil RequestExtractor")
	}
	e := &Enforcer{
		authorizer: a,
		extract:    extract,
		respond:    defaultResponder,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Handler wraps next with AuthZEN enforcement. On permit the request is passed
// through to next; on deny (or any fail-closed error) the wrapped handler is
// not invoked and a challenge response is written instead.
//
// A panic from the extractor or the wrapped handler is recovered and converted
// to a fail-closed 403 deny rather than being allowed to escape: a panicking
// authorization path must never become an open (or crashed) request. The panic
// value is carried in DenyInfo.Err for server-side logging only.
func (e *Enforcer) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				e.deny(w, r, DenyInfo{
					Challenge: e.insufficient(),
					Err:       fmt.Errorf("mcp: recovered panic in enforcement: %v", rec),
				})
			}
		}()

		mreq, err := e.extract(r)
		if err != nil {
			e.deny(w, r, DenyInfo{Challenge: e.challengeForError(err), Err: err})
			return
		}

		eval, err := mreq.EvaluationRequest()
		if err != nil {
			e.deny(w, r, DenyInfo{Challenge: e.challengeForError(err), Err: err})
			return
		}

		resp, err := e.authorizer.Evaluate(r.Context(), eval)
		if err != nil {
			// Fail closed on an infrastructure error: deny (403) rather than
			// pass through.
			e.deny(w, r, DenyInfo{Challenge: e.insufficient(), Err: err})
			return
		}

		if !resp.Decision {
			e.deny(w, r, DenyInfo{Challenge: e.challengeFromResponse(resp), Response: resp})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// challengeForError maps a pre-evaluation error to a challenge. A missing token
// (ErrNoToken) or a request whose token yields no subject (ErrMissingSubject)
// is an authentication failure -> 401; anything else (unknown method, missing
// primitive id, ...) is treated as a 403 deny.
//
// RFC 6750 Section 3.1 - Error Codes (401 vs 403).
// https://www.rfc-editor.org/rfc/rfc6750#section-3.1
func (e *Enforcer) challengeForError(err error) Challenge {
	if errors.Is(err, ErrNoToken) || errors.Is(err, ErrMissingSubject) {
		return e.unauthorized()
	}
	return e.insufficient()
}

// challengeFromResponse derives the challenge for a policy deny, preferring the
// challenge embedded by the PDP in the decision context (context.mcp) and
// falling back to a default insufficient_scope challenge. A status of 0 is
// normalized to 403, and a missing resource_metadata is filled from the
// Enforcer default.
func (e *Enforcer) challengeFromResponse(resp authzen.EvaluationResponse) Challenge {
	if c, ok := ChallengeFromDenyContext(resp.Context); ok {
		if c.Status == 0 {
			c.Status = http.StatusForbidden
		}
		if c.ResourceMetadata == "" {
			c.ResourceMetadata = e.resourceMetadata
		}
		if c.Scope == "" {
			c.Scope = e.scope
		}
		if c.Realm == "" {
			c.Realm = e.realm
		}
		return c
	}
	return e.insufficient()
}

// unauthorized builds the Enforcer's 401 challenge (missing/invalid token).
func (e *Enforcer) unauthorized() Challenge {
	c := Unauthorized(e.resourceMetadata)
	c.Scope = e.scope
	c.Realm = e.realm
	return c
}

// insufficient builds the Enforcer's 403 insufficient_scope challenge.
func (e *Enforcer) insufficient() Challenge {
	c := InsufficientScope(e.scope, e.resourceMetadata)
	c.Realm = e.realm
	return c
}

// deny clamps the challenge status to a valid error code and dispatches to the
// configured Responder. Clamping here (before the Responder runs) means every
// responder — default or custom — observes a safe DenyInfo.Challenge.Status.
func (e *Enforcer) deny(w http.ResponseWriter, r *http.Request, info DenyInfo) {
	info.Challenge.Status = clampDenyStatus(info.Challenge.Status)
	e.respond(w, r, info)
}

// clampDenyStatus forces a deny to carry a 4xx/5xx status. A PDP-supplied
// status (from context.mcp.status) is untrusted input: a deny must never emit a
// success (2xx) or redirect (3xx), and a value outside the valid HTTP range
// would panic http.ResponseWriter.WriteHeader. Anything outside [400, 599]
// falls back to 403 Forbidden.
//
// RFC 9110 Section 15 - Status Codes (4xx Client Error, 5xx Server Error).
// https://www.rfc-editor.org/rfc/rfc9110#section-15
func clampDenyStatus(status int) int {
	if status < 400 || status > 599 {
		return http.StatusForbidden
	}
	return status
}

// errorBody is the RFC 6750-style JSON error payload written by the default
// responder.
//
// RFC 6750 Section 3 - WWW-Authenticate / error response.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
type errorBody struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// defaultResponder writes the deny: the sanitized WWW-Authenticate header (via
// Challenge.String, which strips control characters and so cannot inject a
// header line), the status code, and a small JSON error body. When the
// challenge carries no explicit OAuth error code, one is inferred from the
// status (401 -> invalid_token, otherwise insufficient_scope).
//
// The status is clamped to a valid error code as defense-in-depth (Enforcer.deny
// already clamps), and the response is marked non-cacheable so an intermediary
// cannot replay a stale authorization decision.
//
// RFC 6750 Section 3 / 3.1 - WWW-Authenticate and Error Codes.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
// RFC 9111 Section 5.2.1.5 - no-store (responses must not be cached).
// https://www.rfc-editor.org/rfc/rfc9111#section-5.2.1.5
func defaultResponder(w http.ResponseWriter, _ *http.Request, info DenyInfo) {
	ch := info.Challenge
	status := clampDenyStatus(ch.Status)

	w.Header().Set("WWW-Authenticate", ch.String())
	w.Header().Set("Content-Type", "application/json")
	// Never cache an authorization error; Pragma is the HTTP/1.0 fallback.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)

	body := errorBody{Error: ch.Error, ErrorDescription: ch.ErrorDescription}
	if body.Error == "" {
		if status == http.StatusUnauthorized {
			body.Error = ErrorInvalidToken
		} else {
			body.Error = ErrorInsufficientScope
		}
	}
	// Encoding to an http.ResponseWriter cannot meaningfully fail; ignore the
	// error so the handler signature stays simple.
	_ = json.NewEncoder(w).Encode(body)
}
