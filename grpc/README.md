# authzen/grpc

A gRPC binding for the [OpenID AuthZEN Authorization API 1.0][spec], layered on
top of the transport-agnostic core types in
[`github.com/SCKelemen/authzen`](../).

This is a **nested Go module** (`github.com/SCKelemen/authzen/grpc`) so that the
gRPC and protobuf dependencies never leak into the zero-dependency root module.

## Why gRPC?

The AuthZEN spec defines a normative HTTPS + JSON binding (Section 10) and
explicitly permits additional bindings (gRPC, CoAP) to be defined as profiles
(Section 0). This package is such a gRPC profile. The proto schema mirrors the
HTTP/JSON semantics while following Google's [API Improvement Proposals][aip]:

| Concern              | AIP            | In this API                                            |
| -------------------- | -------------- | ------------------------------------------------------ |
| Resource orientation | AIP-121/122    | `Subject`, `Resource`, `Action`                        |
| Standard `Get`       | AIP-131        | `GetConfiguration` returns the `Configuration` resource |
| Standard `List`      | AIP-132        | `SearchSubjects` / `SearchResources` / `SearchActions` |
| Custom methods       | AIP-136        | `Evaluate` / `EvaluateBatch`                           |
| Pagination           | AIP-158        | request `page_size` / `page_token`; response `page` object |
| Field behavior       | AIP-203        | `REQUIRED` / `OPTIONAL` annotations                    |

### Pagination fidelity

The proto<->core pagination conversion is **lossless** for responses.

The **request** page uses the flat, AIP-158-idiomatic `page_size` / `page_token`
/ `page_properties` fields. The only normalization is benign and intentional: a
present-but-empty request page (no token, default limit, no properties) is
indistinguishable on the wire from an absent page and is reconstructed as
absent. Because every request-page field is optional with a default, an empty
page requests nothing that an absent page does not.

The **response** page is carried as a nullable `PageResponse` message that
mirrors the AuthZEN page object (Section 8.2.2) one-for-one, rather than the
flat AIP-158 `next_page_token` / `total_size` fields. This is a deliberate
deviation from the flat response convention for two reasons:

- **`count`** — AuthZEN's page object has a `count` field that the flat AIP-158
  response convention omits. The message carries it explicitly, so `Count` is
  preserved rather than derived from `len(results)`.
- **presence** — a page that is *present but empty* (the end-of-results marker:
  `next_token=""` with everything else zero) is semantically distinct from an
  *absent* page. A nullable message captures that distinction exactly; flat
  scalar fields could not (every field would be zero in both cases).

As a result `NextToken`, `Count`, `Total`, `Properties`, and page presence all
survive a core -> proto -> core round-trip unchanged.

### Status-code mapping (Section 10.1.2)

A policy **deny** is a *successful* call (`OK` / HTTP 200 with `decision=false`);
only request/processing failures map to error codes.

| `google.rpc.Code`   | HTTP | Meaning                                          |
| ------------------- | ---- | ------------------------------------------------ |
| `OK`                | 200  | Request processed (decision may be allow or deny) |
| `INVALID_ARGUMENT`  | 400  | Missing/invalid required attribute               |
| `UNAUTHENTICATED`   | 401  | PEP failed to authenticate to the PDP            |
| `PERMISSION_DENIED` | 403  | Forbidden (transport-level, not a policy deny)   |
| `INTERNAL`          | 500  | Internal PDP error                               |

## Layout

```
proto/authzen/v1/   # proto source (types.proto, access.proto)
gen/authzen/v1/     # generated Go (committed); package authzenv1
conv.go             # proto <-> core conversions
server.go           # PDP interface + Server adapter
client.go           # ergonomic PEP Client wrapper
*_test.go           # conversion + in-memory bufconn tests
```

## Usage

### Server (PDP)

Implement the `PDP` interface using the core types, then register it:

```go
import (
    authzengrpc "github.com/SCKelemen/authzen/grpc"
    "google.golang.org/grpc"
)

srv := grpc.NewServer()
authzengrpc.NewServer(myPDP).Register(srv)
// srv.Serve(lis)
```

The `Server` converts each request to the core type, validates required fields
(returning `codes.InvalidArgument` for a missing one), delegates to the `PDP`,
and converts the result back. A `PDP` may return a `status` error to choose the
code; any other error becomes `codes.Internal`.

### Client (PEP)

```go
client := authzengrpc.NewClient(conn) // conn is a *grpc.ClientConn
resp, err := client.Evaluate(ctx, authzen.EvaluationRequest{
    Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
    Action:   &authzen.Action{Name: "can_read"},
    Resource: &authzen.Resource{Type: "todo", ID: "1"},
})
// resp.Decision
```

`Client.Raw()` exposes the generated `AccessServiceClient` for advanced needs.

## Regenerating the stubs

The generated code under `gen/` is committed. Regenerate after editing the
protos:

```bash
make deps      # one-time / when deps change: fetch googleapis into buf.lock
make generate  # buf generate -> gen/
make check     # buf lint + go vet + build + test
```

Requires `buf`, `protoc-gen-go`, and `protoc-gen-go-grpc` on `PATH` (see the
`Makefile` header for install commands).

[spec]: https://openid.net/specs/authorization-api-1_0.html
[aip]: https://google.aip.dev/
