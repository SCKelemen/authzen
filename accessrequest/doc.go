// Package accessrequest implements the OpenID AuthZEN Access Request and
// Approval Profile, an extension profile of the AuthZEN Authorization API that
// lets a Policy Enforcement Point (PEP) submit an access request when an
// authorization decision is denied but requestable.
//
// The profile preserves the Authorization API decision model: a denied decision
// remains a denial and MUST NOT be treated as access. It adds a requestable
// denial context (context.access_request), an Access Request Endpoint, an
// opaque task handle for the asynchronous workflow that resolves a denial, and
// a re-evaluation completion mode that keeps the Policy Decision Point (PDP)
// authoritative at enforcement time after approval.
//
// Like the root module, this package is transport-agnostic and depends only on
// the standard library and the core authzen information model: it defines the
// request and response payloads (and their JSON encoding) together with
// Validate helpers that enforce the REQUIRED fields mandated by the profile's
// MUST rules. Verification of integrity-protected artifacts (the PDP-issued
// binding_token and the Access Request Service approval.state) is left to a
// pluggable verifier so the core stays dependency-free.
//
// AuthZEN Access Request and Approval Profile, Draft 1 (2026-06-09).
// https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
package accessrequest
