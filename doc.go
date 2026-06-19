// Package authzen provides the core information model and message types for the
// OpenID AuthZEN Authorization API 1.0, the foundation on which a compliant
// Policy Decision Point (PDP) or Policy Enforcement Point (PEP) is built.
//
// The package is transport-agnostic: it defines the request and response
// payloads (and their JSON encoding) for the Access Evaluation API (Section 6),
// the Access Evaluations / batch API (Section 7), the Subject, Resource, and
// Action Search APIs (Section 8), and the PDP metadata document (Section 9). It
// does not implement any HTTP, gRPC, or CLI binding; those live in separate
// packages.
//
// All types follow the field names, JSON shapes, and required/optional rules of
// the specification exactly. Validation helpers enforce the REQUIRED fields
// mandated by the spec's MUST rules.
//
// OpenID AuthZEN Authorization API 1.0 (Final Specification, 2026-01-12).
// https://openid.net/specs/authorization-api-1_0.html
package authzen
