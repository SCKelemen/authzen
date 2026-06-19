# authzen

[![CI](https://github.com/SCKelemen/authzen/actions/workflows/ci.yml/badge.svg)](https://github.com/SCKelemen/authzen/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/SCKelemen/authzen.svg)](https://pkg.go.dev/github.com/SCKelemen/authzen)
[![Go Report Card](https://goreportcard.com/badge/github.com/SCKelemen/authzen)](https://goreportcard.com/report/github.com/SCKelemen/authzen)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

A clean, dependency-light Go implementation of the **OpenID AuthZEN
Authorization API 1.0** — the standard for how a Policy Enforcement Point (PEP)
asks a Policy Decision Point (PDP) *"is this subject allowed to perform this
action on this resource?"*

- Specification: <https://openid.net/specs/authorization-api-1_0.html>
- Working-group render: <https://openid.github.io/authzen/>

> **Status:** the root module targets the Authorization API 1.0 **Final
> Specification** (approved 2026-01-12).

## What is AuthZEN?

AuthZEN standardizes the contract between a **PEP** (the application enforcing
access) and a **PDP** (the service that decides). It defines a transport-
agnostic information model — `Subject`, `Resource`, `Action`, `Context`,
`Decision` — and a normative HTTPS + JSON binding for four families of APIs:

| API | Spec section | What it answers |
| --- | --- | --- |
| Access Evaluation | §6 | One decision: may *subject* do *action* on *resource*? |
| Access Evaluations (batch) | §7 | Many decisions in one round trip (boxcarred). |
| Subject / Resource / Action Search | §8 | Discovery: *who/what/which* satisfies a relation. |
| Metadata | §9 | The PDP's `.well-known` configuration document. |

A policy **deny** is a *successful* response (`decision: false`), never an error
— a distinction this library preserves end to end.

## Features

- **Conformant core types** — the request/response payloads and their exact
  JSON encoding for §5–§9, with `Validate` helpers that enforce every REQUIRED
  field mandated by the spec's MUST rules.
- **HTTP client (PEP)** — `client` package: `Evaluate`, `EvaluateBatch`, the
  three Search APIs, and metadata discovery over the normative HTTPS + JSON
  binding, with pluggable auth (static bearer token or per-request hook).
- **HTTP server (PDP)** — `server` package: implement a small `PDP` interface
  and get a ready `http.Handler` that wires the standard routes, validates
  input, and applies the §10.1 transport and error-mapping rules (including
  optional batch-semantic handling).
- **gRPC binding** — the nested `grpc` module: an AIP-designed gRPC profile of
  the API with committed, generated stubs (see [grpc/README.md](./grpc/README.md)).
- **CLI** — a `cmd/authzen` command-line PEP for scripting and CI gating, built
  only on the standard library and the in-repo client; see [CLI](#cli) below.
- **Minimal dependencies** — see the philosophy callout below.

### Minimal-dependency philosophy

The **root module has zero external dependencies** — it builds on the Go
standard library alone (`net/http`, `encoding/json`, ...). Anything that would
pull in a heavier dependency tree is isolated in its own module: the gRPC
binding (which needs `grpc`/`protobuf`/`buf`) lives in the nested `grpc` module
so those dependencies never leak into consumers of the core. Depend on
`github.com/SCKelemen/authzen` for the types, client, and server; opt in to
`github.com/SCKelemen/authzen/grpc` only if you want gRPC.

## Module layout

This repository contains **two Go modules**:

```
github.com/SCKelemen/authzen          # root module — ZERO external deps
├── *.go                              # core information model (§5–§9) + validation
├── client/                           # PEP: HTTPS + JSON client
├── server/                           # PDP: http.Handler + PDP interface
├── cmd/authzen/                      # CLI (PEP for scripting/CI)
└── docs/SPEC_NOTES.md                # engineering reference for the spec

github.com/SCKelemen/authzen/grpc     # nested module — grpc + protobuf + buf
├── proto/authzen/v1/                 # proto source
├── gen/authzen/v1/                   # generated Go (committed)
├── conv.go / server.go / client.go   # proto <-> core, PDP adapter, PEP wrapper
└── README.md                         # gRPC binding docs
```

The nested module uses a `replace github.com/SCKelemen/authzen => ../` directive
so the binding always builds against the local core.

## Install

```bash
# Core types, HTTP client, and HTTP server (zero-dependency root module):
go get github.com/SCKelemen/authzen

# gRPC binding (nested module, only if you want gRPC):
go get github.com/SCKelemen/authzen/grpc
```

Requires Go 1.26 or newer (`go 1.26` in `go.mod`).

## Quickstart

### Client (PEP)

```go
package main

import (
	"context"
	"fmt"
	"log"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/client"
)

func main() {
	c := client.New("https://pdp.example.com",
		client.WithBearerToken("ey...")) // OAuth 2.0 bearer (RECOMMENDED, §11.2)

	resp, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "todo", ID: "1"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// A deny is a successful response with Decision == false, not an error.
	fmt.Println("allowed:", resp.Decision)
}
```

### Server (PDP)

```go
package main

import (
	"context"
	"log"
	"net/http"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/server"
)

// myPDP is your decision logic. It only sees requests that already passed the
// package's structural validation (REQUIRED fields present).
type myPDP struct{}

func (myPDP) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	allow := req.Action.Name == "can_read" // your policy here
	return &authzen.EvaluationResponse{Decision: allow}, nil
}

func (myPDP) SearchSubjects(ctx context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	return &authzen.SubjectSearchResponse{}, nil
}
func (myPDP) SearchResources(ctx context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	return &authzen.ResourceSearchResponse{}, nil
}
func (myPDP) SearchActions(ctx context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	return &authzen.ActionSearchResponse{}, nil
}

func main() {
	h := server.NewHandler(myPDP{}, server.WithMetadata(&authzen.Metadata{
		PolicyDecisionPoint:      "https://pdp.example.com",
		AccessEvaluationEndpoint: "https://pdp.example.com/access/v1/evaluation",
	}))
	log.Fatal(http.ListenAndServe(":8080", h))
}
```

The handler serves the standard routes (`/access/v1/evaluation`,
`/access/v1/evaluations`, `/access/v1/search/{subject,resource,action}`, and
`/.well-known/authzen-configuration`). Batch evaluation works out of the box: if
your `PDP` does not implement the optional `BatchEvaluator` interface, the
handler loops `Evaluate` while honoring the requested `evaluations_semantic`
(`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`).

### CLI

`cmd/authzen` is a command-line PEP over the HTTPS + JSON binding. It is a thin
wrapper over the `client` package, depends only on the standard library, and
exposes the four API families as subcommands: `evaluate` (§6), `evaluations`
(§7), `search` (§8), and `discover` (§9). Every command takes the shared flags
`--url` (required), `--token`, `--timeout`, and `--json`.

```bash
# Install:
go install github.com/SCKelemen/authzen/cmd/authzen@latest

# Single evaluation — prints "allow" or "deny":
authzen evaluate \
  --url https://pdp.example.com \
  --subject-type user --subject-id alice@example.com \
  --action can_read \
  --resource-type todo --resource-id 1

# Gate a script/CI step on a deny (exit non-zero only on deny):
authzen evaluate --url https://pdp.example.com \
  --subject-type user --subject-id alice@example.com \
  --action can_delete --resource-type todo --resource-id 1 \
  --deny-exit-code 3

# Send a full request document (or "-" for stdin), with bearer auth and raw JSON:
authzen evaluate --url https://pdp.example.com \
  --token "ey..." --json --request ./request.json

# Fetch and summarize the PDP metadata document:
authzen discover --url https://pdp.example.com
```

A deny is a successful call and exits `0` unless `--deny-exit-code N` is given;
transport/API errors exit `1`, and usage errors exit `2`. Run
`authzen <command> --help` for the full flag list.

### gRPC

The gRPC binding lives in the nested `grpc` module. See
**[grpc/README.md](./grpc/README.md)** for the proto schema, the AIP design
notes, the gRPC ↔ HTTP status-code mapping, and server/client examples.

```go
import (
	authzen "github.com/SCKelemen/authzen"
	authzengrpc "github.com/SCKelemen/authzen/grpc"
)

client := authzengrpc.NewClient(conn) // conn is a *grpc.ClientConn
resp, err := client.Evaluate(ctx, authzen.EvaluationRequest{
	Subject:  &authzen.Subject{Type: "user", ID: "alice@example.com"},
	Action:   &authzen.Action{Name: "can_read"},
	Resource: &authzen.Resource{Type: "todo", ID: "1"},
})
```

## Conformance & spec coverage

The library tracks the Authorization API 1.0 Final Specification. The core
types follow the field names, JSON shapes, and required/optional rules of the
spec exactly; `docs/SPEC_NOTES.md` is the engineering reference that maps each
implementation decision back to a spec section.

| Spec area | Section | Core types / validation | HTTP client | HTTP server | gRPC |
| --- | --- | :---: | :---: | :---: | :---: |
| Information model (Subject/Resource/Action/Context) | §5 | ✅ | — | — | ✅ |
| Access Evaluation | §6 | ✅ | ✅ | ✅ | ✅ |
| Access Evaluations (batch) | §7 | ✅ | ✅ | ✅ | ✅ |
| Subject / Resource / Action Search | §8 | ✅ | ✅ | ✅ | ✅ |
| Metadata (`.well-known`) | §9 | ✅ | ✅ | ✅ | ✅ |
| Transport (HTTPS + JSON, error mapping) | §10 | — | ✅ | ✅ | n/a |

The gRPC binding is a non-normative **profile** (the spec permits additional
bindings as profiles); it mirrors the HTTP/JSON semantics. Interop fixtures are
drawn from the spec's own JSON examples and the
[AuthZEN interop](https://authzen-interop.net) "Todo" scenario.

## Testing

Both modules are tested independently. From the repository root:

```bash
# Root module (zero-dependency core, client, server):
go test ./...

# gRPC module (nested):
cd grpc && go test ./...
```

CI runs the full gate on every push and pull request — `gofmt`, `go vet`,
`go build`, and `go test -race -coverprofile=... -covermode=atomic` for **both**
modules, plus `buf lint` and a `buf generate` + `git diff` check that fails if
the committed generated stubs drift. See
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

To regenerate the gRPC stubs after editing the protos:

```bash
cd grpc
make generate   # buf generate -> gen/   (requires buf + protoc-gen-go[-grpc])
make check      # buf lint + go vet + build + test
```

## License

Licensed under the **Apache License 2.0** — see [LICENSE](./LICENSE). Apache 2.0
is the customary choice for OpenID-ecosystem libraries (it pairs a permissive
grant with an explicit patent license), which keeps this implementation easy to
adopt alongside the specification.

Copyright 2026 Samuel Kelemen.
