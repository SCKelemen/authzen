// Package mcp is a non-normative AuthZEN profile for Model Context Protocol
// (MCP) authorization. It maps the authorization facts of an MCP server — its
// OAuth 2.1 token, the JSON-RPC method being invoked, and the targeted MCP
// primitive (tool, resource, prompt, or the server/session itself) — onto the
// transport-agnostic core types of the OpenID AuthZEN Authorization API 1.0
// (github.com/SCKelemen/authzen), so that an MCP server can act as an AuthZEN
// Policy Enforcement Point (PEP) and delegate every access decision to a Policy
// Decision Point (PDP).
//
// The package builds an authzen.EvaluationRequest from an MCP request and
// provides RFC 6750 / RFC 9728 WWW-Authenticate challenge helpers for turning a
// deny into the OAuth-shaped response an MCP client expects. It carries no
// external dependencies and performs no network or token-validation work:
// authentication (verifying the bearer token) remains the responsibility of the
// OAuth resource server; this profile is concerned only with authorization.
//
// Trust boundary: OAuth authenticates the caller and audience-binds the token
// (RFC 8707); AuthZEN authorizes the requested action on the requested
// resource. The two are deliberately separate seams.
//
// Specifications referenced by this profile:
//   - MCP Authorization (2025-06-18).
//     https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
//   - RFC 9728 - OAuth 2.0 Protected Resource Metadata.
//     https://www.rfc-editor.org/rfc/rfc9728
//   - RFC 8414 - OAuth 2.0 Authorization Server Metadata.
//     https://www.rfc-editor.org/rfc/rfc8414
//   - RFC 8707 - Resource Indicators for OAuth 2.0.
//     https://www.rfc-editor.org/rfc/rfc8707
//   - RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage.
//     https://www.rfc-editor.org/rfc/rfc6750
//
// OpenID AuthZEN Authorization API 1.0.
// https://openid.net/specs/authorization-api-1_0.html
package mcp
