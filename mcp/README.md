# mcp — AuthZEN profile for MCP authorization (`coaz`)

A small, **zero-dependency** in-root package that lets a **Model Context
Protocol (MCP)** server act as an **AuthZEN Policy Enforcement Point (PEP)**: it
maps the authorization facts of an MCP request onto the core types of
[`github.com/SCKelemen/authzen`](../) so the access decision can be delegated to
a Policy Decision Point (PDP).

- MCP Authorization: <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- AuthZEN Authorization API 1.0: <https://openid.net/specs/authorization-api-1_0.html>

> **Status:** non-normative profile. This is the in-repo implementation of the
> MCP profile referenced from [`docs/SPEC_NOTES.md`](../docs/SPEC_NOTES.md).

## Trust boundary — OAuth authenticates, AuthZEN authorizes

An MCP server is an **OAuth 2.1 resource server**. Two concerns sit on either
side of a deliberate seam:

- **Authentication (OAuth).** The server validates the bearer token, and the
  token is audience-bound to the server via a resource indicator
  ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)). Discovery flows from a
  `401` + `WWW-Authenticate: Bearer resource_metadata="…"` to the Protected
  Resource Metadata document ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)),
  then to the Authorization Server metadata
  ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)) and OAuth 2.1 + PKCE.
- **Authorization (AuthZEN).** Given an *authenticated* caller, may they perform
  *this* MCP method on *this* primitive? That is the question this package
  turns into an `authzen.EvaluationRequest`.

This package performs **no token parsing or verification** and makes **no
network calls**. The caller supplies already-authenticated `TokenClaims`.

## Mapping

| MCP fact | AuthZEN element | Notes |
| --- | --- | --- |
| Authenticated principal (`sub` / `client_id` / `act`) | **Subject** | Type heuristic: `user` (has `sub`), `client` (only `client_id`), `agent` (has actor/delegation claim). `client_id`, `scopes`, `act`, `token_audience` carried in `properties`. |
| JSON-RPC method | **Action** | Via `ActionFor`, e.g. `tools/call` → `mcp.tools.call`. Call `Arguments` ride along under `action.properties.arguments`. |
| Targeted primitive | **Resource** | `tools/call` → `mcp_tool` (id = tool name); `resources/read` → `mcp_resource` (id = URI); `prompts/get` → `mcp_prompt` (id = name); the `*/list` methods → `mcp_server` (id = server URI). |
| Request metadata | **Context** | Under the reserved `mcp` key: `method`, `transport`, `resource_indicator` (RFC 8707), and a `token` object (`sub`, `client_id`, `scopes`, `act`, `audience`). |

### Resource-type & action constants

| Constant | Value |
| --- | --- |
| `ResourceTypeTool` | `mcp_tool` |
| `ResourceTypeResource` | `mcp_resource` |
| `ResourceTypePrompt` | `mcp_prompt` |
| `ResourceTypeServer` | `mcp_server` |
| `ActionToolsCall` … | `mcp.tools.call`, `mcp.tools.list`, `mcp.resources.read`, `mcp.resources.list`, `mcp.prompts.get`, `mcp.prompts.list` |

## Usage

### Build an evaluation request (PEP → PDP)

```go
req := mcp.Request{
    Method:            "tools/call",
    ToolName:          "search",
    Arguments:         map[string]any{"q": "authzen"},
    ServerURI:         "https://mcp.example.com",
    Transport:         "http",
    ResourceIndicator: "https://mcp.example.com", // RFC 8707 audience
    Token: mcp.TokenClaims{
        Subject:  "alice@example.com",
        ClientID: "ide-client",
        Scopes:   []string{"mcp:tools"},
        Audience: "https://mcp.example.com",
    },
}

eval, err := req.EvaluationRequest()
if err != nil {
    // unknown method, missing tool/resource/prompt id, or no subject
}
// hand eval to a PDP via the authzen client, server.PDP, or grpc binding
```

### Deny with an OAuth-shaped challenge (PDP → PEP → client)

```go
// The PDP denies and attaches a ready challenge for the PEP to surface.
ch := mcp.InsufficientScope("mcp:tools", "https://mcp.example.com/.well-known/oauth-protected-resource")

resp := authzen.EvaluationResponse{
    Decision: false,
    Context:  mcp.DenyContext(ch), // {"mcp":{"status":403,"error":"insufficient_scope","www_authenticate":{…}}}
}

// At the HTTP edge the PEP emits the header:
w.Header().Set("WWW-Authenticate", ch.String())
w.WriteHeader(ch.Status) // 403
```

For an unauthenticated request, use `mcp.Unauthorized(resourceMetadataURL)`
(HTTP `401`) to bootstrap discovery. Clients can read a server's challenge with
`mcp.ParseChallenge(header)`.

### Enforce at the HTTP edge (`Enforcer` middleware)

`mcp.Enforcer` wires the pieces together as standard `net/http` middleware. You
supply two seams: an `Authorizer` (the PDP call) and a `RequestExtractor` (turns
an `*http.Request` into an `mcp.Request`, since token parsing/transport is
deployment-specific). The middleware extracts, assembles the evaluation request,
asks the PDP, and either calls `next` or writes an OAuth challenge.

```go
// Authorizer matches the in-process PDP interface (grpc.PDP), so an in-process
// PDP implementation satisfies it directly. The network clients do NOT — each
// needs a small adapter (their method signatures differ):
//
//   // grpc.Client: trailing variadic opts ...grpc.CallOption
//   authorizer := mcp.AuthorizerFunc(func(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
//       return grpcClient.Evaluate(ctx, req) // drop the opts
//   })
//
//   // client.Client (HTTP): pointer in/out
//   authorizer := mcp.AuthorizerFunc(func(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
//       resp, err := httpClient.Evaluate(ctx, &req)
//       if err != nil {
//           return authzen.EvaluationResponse{}, err
//       }
//       return *resp, nil
//   })

// Caller-owned: validate the bearer token and frame the MCP request. The
// extractor MUST cryptographically verify the token (signature, expiry,
// audience/resource indicator) before returning a Request — an unverified token
// fails open. Return an error satisfying errors.Is(err, mcp.ErrNoToken) when
// unauthenticated (-> 401).
extract := func(r *http.Request) (mcp.Request, error) { /* ... */ }

enforcer := mcp.New(authorizer, extract,
    mcp.WithScope("mcp:tools"),
    mcp.WithResourceMetadata("https://mcp.example.com/.well-known/oauth-protected-resource"),
)

mux := http.NewServeMux()
mux.Handle("/mcp", enforcer.Handler(mcpHandler)) // mcpHandler runs only on permit
```

On deny the `Enforcer` prefers the challenge embedded by the PDP in the decision
context (`ChallengeFromDenyContext`) and falls back to a default
`insufficient_scope` challenge built from the configured options. The default
responder sets `WWW-Authenticate` (via the sanitized `Challenge.String`), the
status, and an RFC 6750-style JSON body; override it with
`mcp.WithErrorResponder`.

#### Fail-closed semantics

The middleware **never falls through to `next` on error** — every failure path
denies. Mapping:

| Condition | `next` called? | HTTP status | Challenge |
| --- | --- | --- | --- |
| Permit (`Decision == true`) | **yes** | — (handler decides) | none |
| Policy deny (`Decision == false`) | no | clamped `context.mcp.status` (default `403`) | from `context.mcp`, else default `insufficient_scope` |
| Extractor returns `ErrNoToken` (or wraps it) | no | `401` | `Unauthorized` (resource_metadata for discovery) |
| Extractor returns any other error | no | `403` | `insufficient_scope` |
| Assembly error `ErrMissingSubject` (token has no principal) | no | `401` | `Unauthorized` |
| Assembly error (unknown method, missing primitive id, …) | no | `403` | `insufficient_scope` |
| `Authorizer` returns an error (PDP unavailable, etc.) | no | `403` | `insufficient_scope` |
| Extractor or `next` **panics** | no\* | `403` | `insufficient_scope` |

\* The panic is recovered and converted to a fail-closed 403; for an extractor
panic `next` is never reached.

A deny status is always **clamped to `[400, 599]`** before it reaches the wire:
an untrusted `context.mcp.status` of `200`/`302` (or an out-of-range value that
would otherwise panic `WriteHeader`) falls back to `403`. Deny responses also
carry `Cache-Control: no-store` and `Pragma: no-cache`.

`New` panics if the `Authorizer` or `RequestExtractor` is nil, so a missing
dependency fails fast at startup rather than silently failing open.

## Design notes

- A policy **deny is not an error** — it is `EvaluationResponse{Decision:false}`
  with an optional context. The HTTP status (`401`/`403`) lives in the
  challenge, surfaced by the PEP at the transport edge.
- `String()` renders RFC 6750 / RFC 9728 `WWW-Authenticate` parameters as
  quoted-strings in a stable order; `ParseChallenge` is its inverse for the
  wire-visible fields.
- Pure standard library; no external dependencies.
