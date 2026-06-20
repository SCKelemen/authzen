// Package approval implements the "aarp" approval-workflow extension for the
// OpenID AuthZEN Authorization API 1.0: asynchronous, human-in-the-loop access
// decisions that are not yet resolved at evaluation time (a PENDING decision).
//
// # Why an extension is needed
//
// AuthZEN's decision is a REQUIRED boolean: true permits, false denies, and a
// deny is fail-safe/closed (Section 5.5, Section 6.2). There is therefore no
// native "pending" value on the wire. The decision context, however, is an
// OPTIONAL free-form object that the specification explicitly designates as the
// extension point for reasons, advice/obligations, UI hints, and step-up
// instructions (Section 5.5.1, Figure 11). This package layers an approval
// workflow on top of that context without changing the wire format.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.5 (Decision) and Section
// 5.5.1 (decision context as the extension point).
// https://openid.net/specs/authorization-api-1_0.html
//
// # Design (Option B): pending == not-yet-success
//
// A pending approval is expressed as decision=false carrying an "approval"
// object in the decision context. When the request is approved it becomes
// decision=true (still carrying the approval object, now with status
// "approved"); when denied, expired, or canceled it remains decision=false
// with the corresponding terminal status. This mirrors how OAuth's Device
// Authorization Grant expresses "pending" as a not-yet-success error
// (authorization_pending) rather than a third decision value.
//
// The shape of the approval object is anchored on three prior-art
// specifications:
//
//   - RFC 8628 (OAuth 2.0 Device Authorization Grant): the authorization_pending
//     / slow_down / access_denied / expired_token lifecycle, and the interval
//     and expires_in polling parameters.
//     https://www.rfc-editor.org/rfc/rfc8628
//   - OpenID Client-Initiated Backchannel Authentication (CIBA): the
//     out-of-band auth_req_id handle, poll/ping/push delivery modes, and the
//     interval backoff for the poll mode.
//     https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
//   - RFC 9396 (OAuth 2.0 Rich Authorization Requests): the authorization_details
//     array of {type, locations, actions, datatypes, identifier, privileges}
//     objects, reused here (as RequestRef) to describe WHAT is pending approval.
//     https://www.rfc-editor.org/rfc/rfc9396
//
// # Contents
//
//   - Approval, RequestRef, Approvers, Grant, and the Status state values, with
//     helpers to project an Approval into/out of a decision context and to
//     build the corresponding authzen.EvaluationResponse.
//   - Store: an in-memory, concurrency-safe state machine for pending approvals
//     with opaque high-entropy identifiers and lazy expiry, plus an optional
//     OnResolve hook fired when an approval reaches a terminal state. The Store
//     does not evict on its own and grows without bound unless the caller
//     reclaims records via Delete, Sweep, or an opt-in background janitor
//     (WithJanitor); WithMaxSize caps it instead.
//   - Handler: a net/http poll endpoint that returns the current decision as an
//     authzen.EvaluationResponse.
//   - Notifier: an OPT-IN, safe-by-default delivery component that POSTs
//     ping/push callbacks to a client's CallbackURL, gated by a caller-supplied
//     URL validator (see AllowList).
//
// # Security: untrusted URLs (SSRF)
//
// The PollURL ("poll_url") and CallbackURL ("callback_url") fields are carried
// verbatim through the store, the response builders, and the poll handler. The
// core Store and Handler NEVER dereference, fetch, or otherwise make a network
// request to either URL; there is no auto-fetch or redirect-follow in the
// decision path. These fields are therefore untrusted input by default — treat
// values that arrive from a decision context (via FromContext) as
// attacker-controlled.
//
// The Notifier is the one component that DOES dereference CallbackURL, to
// deliver ping/push callbacks (see notify.go). It is opt-in and safe by default:
// it fails closed unless a caller-supplied Validate function approves the parsed
// target URL, and its default HTTP client does not follow redirects (so a
// validated URL cannot be bounced to an internal address). Callers MUST supply a
// strict validator — allow-list the scheme (https) and host and block
// link-local, loopback, and cloud-metadata addresses — to avoid a server-side
// request forgery (SSRF) vector; AllowList provides a ready-made https + host
// allow-list baseline. Any other component that decides to follow PollURL bears
// the same responsibility.
//
// Two residual SSRF gaps are NOT mitigated by this package and are the caller's
// responsibility:
//
//   - Custom HTTP client weakens redirect protection. The no-redirect policy is
//     set only on the default client built by NewNotifier. A caller who injects
//     their own *http.Client that follows redirects loses the redirect-bounce
//     protection. Preserve a no-redirect CheckRedirect (for example returning
//     http.ErrUseLastResponse) on any custom client.
//   - AllowList validates the host string, not the resolved IP. It enforces
//     https and a host allow-list but does NOT defend against DNS rebinding or
//     an allow-listed host that resolves to a loopback, link-local, or
//     cloud-metadata address. For hardened deployments add an IP-level guard at
//     dial time (a custom DialContext) that blocks private (RFC 1918),
//     loopback, link-local (169.254.0.0/16), and the 169.254.169.254 metadata
//     address.
//
// The package depends only on the Go standard library and the zero-dependency
// root module github.com/SCKelemen/authzen; it adds no external dependencies.
package approval
