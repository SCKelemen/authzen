// Package interop hosts the AuthZEN 1.0 interoperability conformance harness.
//
// It is a test-only package: it contains no exported API and is built only when
// running the tests under interop/. The harness validates this module's
// request/response types, client (PEP), and server (PDP) against the OFFICIAL
// OpenID AuthZEN Working Group interop material, rather than against this
// module's own fixtures.
//
// Two layers are provided:
//
//   - Offline (default, CI-safe): drives the vendored interop vectors under
//     testdata/ (see testdata/SOURCES.md for provenance). It checks that our
//     wire format round-trips byte-compatibly with the official vectors and
//     that our client<->server path produces the official decisions and search
//     results.
//
//   - Live (opt-in, env-gated by AUTHZEN_INTEROP_LIVE=1; skipped by default):
//     points our client at a hosted interop PDP and checks that it can issue
//     real evaluation/evaluations/search calls and parse the decisions.
//
// OpenID AuthZEN Authorization API 1.0.
// https://openid.net/specs/authorization-api-1_0.html
package interop
