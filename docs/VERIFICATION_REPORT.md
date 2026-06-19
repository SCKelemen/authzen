# AuthZEN 1.0 Go Implementation — Independent Consolidated Verification

> Verifier: independent reviewer (did not author the implementation).
> Scope: the **whole repo** at `/Users/sam/zen/authzen` after four parallel fix
> workstreams landed (server hardening, client/CLI transport, core semantics,
> gRPC parity). Both modules were verified **together**, not package-by-package.
> Method: ran the full gate (gofmt/vet/build/test/cover) on both modules,
> dependency and license audits, then read the changed source to confirm the
> conformance claims. Spec digest: `docs/SPEC_NOTES.md` (authoritative).
> Implementation files were **not** modified. Nothing was committed or pushed.

## TL;DR — all gates pass

- **Root module**: `gofmt -l .` clean, `go vet ./...` clean, `go build ./...`
  clean, `go test ./... -count=1` all `ok`.
- **gRPC module**: `gofmt -l .` clean, `go vet ./...` clean, `go build ./...`
  clean, `go test ./... -count=1` all `ok`; `go mod tidy` is a **no-op**;
  `buf lint` exits **0** (buf 1.65.0).
- **Zero external deps in the root module**: `go list -m all` prints only
  `github.com/SCKelemen/authzen`; `go.mod` has no `require` block. The gRPC and
  protobuf dependency tree is **quarantined** to the nested `grpc/` module.
- **No `Apache` references** remain anywhere in the tree (license swap clean).
- All five previously-PARTIAL conformance areas are now **PASS** (details in §1).

---

## 1. Conformance matrix (current)

Legend: **PASS** = implemented + positive **and** negative tests; **PARTIAL** =
implemented but missing tests, or a residual deviation; **MISSING** = not
implemented.

| Spec area | Status | Implementation | Tests |
|---|---|---|---|
| **Access Evaluation §6** (REQUIRED subject/action/resource) | **PASS** | `evaluation.go`; `server/server.go:handleEvaluation`; `grpc/server.go:Evaluate` | `roundtrip_test.go`, `server_test.go:TestMissingRequiredFieldReturns400`, `grpc:TestEvaluateMissingRequiredFieldInvalidArgument` |
| **Access Evaluations / batch §7** (defaulting, override, 3 semantics) | **PASS** | `evaluations.go` (`Resolved`/`Validate`), `server/server.go:EvaluateBatch` | `evaluations_test.go`, `server/roundtrip_test.go:TestBatch*`, `grpc:TestEvaluateBatch*` |
| **Batch single-decision response §7.1 / §6.2** *(was PARTIAL)* | **PASS** | `EvaluationsResponse{Decision *bool, Context, Evaluations}` with shape-selecting `MarshalJSON`/`UnmarshalJSON`; `SingleDecision()` helper (`evaluations.go:310`). A request with no/empty `evaluations` is answered with the single `{"decision":…,"context":…}` shape, **not** `{"evaluations":[…]}`. | `review_findings_test.go:TestEvaluationsResponseSingleDecisionRoundTrip`, `TestSingleDecisionHelper`; gRPC `review_findings_test.go:TestEvaluationsResponseSingleDecisionToProto` |
| **Batch per-member error semantics §7.2.1 / §5.5** *(report previously wrong — now confirmed IMPLEMENTED)* | **PASS** | `server/server.go:EvaluateBatch` (≈L117): a member whose `Evaluate` errors is **not** aborted as a whole-batch 500; it yields a per-member **closed** decision `{Decision:false, Context:{"error":EvaluationError{Status:500,…}}}` and the loop continues per the active semantic (an errored member is a deny → short-circuits `deny_on_first_deny`; not a permit → continues `permit_on_first_permit`). Decisions default closed (§5.5). Context **cancellation** is the distinct case that still surfaces as an error. | `server/coverage_test.go:TestBatchPerMemberErrorPermitOnFirstPermit`, `TestEvaluateBatchCancelledContextReturnsError`, `server_test.go:TestEvaluateBatchDefaultLoopDirect` |
| **Subject / Resource / Action Search §8** | **PASS** | `search.go` (3 request/response types + `Validate`); `server/server.go:handleSearch*`; `grpc/server.go:Search*` | `search_test.go`, `server/roundtrip_test.go:TestSearch*`, `grpc:TestSearch*` |
| **Searched `id` ignored §8.4 / §8.5** *(was PARTIAL)* | **PASS** | `search.go` documents that the searched `subject.id` / `resource.id` is not required and MUST be ignored by the PDP; the gRPC server actively **strips** it before invoking the PDP (`grpc/server.go:130` `req.Subject.ID = ""`, `:149` `req.Resource.ID = ""`). | `grpc:review_findings_test.go:TestSearchSubjectsStripsID`, `TestSearchResourcesStripsID` |
| **Pagination §8.2** (opaque token, end sentinel, lossless transport) *(was PARTIAL)* | **PASS** | Core: `PageResponse.NextToken` has no `omitempty` ⇒ end sentinel (`next_token:""`) always serialized. gRPC: a dedicated **nullable `PageResponse`** proto message preserves `next_token`, `count`, and `total` exactly (`grpc/conv.go:pageResponseToProto/FromProto` ≈L495–525) — the earlier lossy `count` drop and empty-token→nil-page collapse are gone; an absent page is distinguishable on the wire. | `search_test.go:TestPaginationRoundTrip`, `TestEndOfResultsSentinel`; `grpc:conv_test.go` page round-trips |
| **Decision response incl. reason/context §5.5 / §6.2** | **PASS** | `evaluation.go` (`Context`, `Reasons`, `ReasonContext`, `EvaluationError`) | `roundtrip_test.go:TestEvaluationResponseRoundTrip`, `grpc:TestEvaluationResponseRoundTrip` |
| **Metadata discovery + §9.2.3 validation** *(report previously wrong — now confirmed IMPLEMENTED)* | **PASS** | `client/client.go:Metadata` fetches `/.well-known/authzen-configuration` then enforces §9.2.3: the document's `policy_decision_point` MUST match the expected issuer (`ExpectedIssuer`, defaulting to `BaseURL`) via canonicalizing `sameIssuer`; on mismatch it returns `*MetadataValidationError` and **discards** the document. Escape hatches: `WithExpectedIssuer`, `WithInsecureSkipMetadataValidation` (documented as relaxing a MUST). Server side: `metadata.go` + `handleMetadata` (GET-only, required fields not `omitempty`). | `client/coverage_test.go:TestMetadataHappyPath`, `TestMetadataValidationMismatch`, `TestMetadataValidationSkip`, `TestMetadataExpectedIssuerOverride`, `TestMetadataValidationErrorString`; `server_test.go:TestMetadataNotConfiguredReturns404`, `TestPostOnMetadataReturns405` |
| **gRPC ⇄ core parity** *(was PARTIAL)* | **PASS** | `grpc/conv.go` + `grpc/server.go`: single-decision batch responses round-trip into the `evaluations` array rather than being dropped (`evaluationsResponseToProto` ≈L403); search `id` stripping; lossless pagination (above); `mapToStruct` JSON-normalizes ordinary Go values before `structpb` so realistic property maps convert instead of erroring. | `grpc/conv_test.go` (entities/eval/batch/search/metadata/semantics); `grpc:review_findings_test.go:TestMapToStructJSONNormalizesOrdinaryGoValues`, `TestEvaluationsResponseSingleDecisionToProto`, `TestSearch*StripsID` |
| **HTTP binding: methods / content types / status §10** | **PASS** | `server/server.go` (`requirePost`→405/415, `decodeJSON`→400, 404 catch-all) | `server_test.go` (400/405/415/404, charset accepted, X-Request-ID echoed) |
| **HTTP hardening (defense-in-depth)** | **PASS** | `WithMaxBodyBytes` (HTTP 413 cap), `WithMaxBatchSize` (HTTP 400 cap before fan-out), `WithVerboseErrors` (generic client errors + server-side correlation id, §10.1.2), `WithErrorLogger`, `sanitizeRequestID` (strips CR/LF to prevent header-splitting on the echoed `X-Request-ID`). | `server/hardening_test.go`, `server/coverage_test.go` |
| **Client transport security** | **PASS** | `client/client.go:stripSensitiveOnRedirect` — a `CheckRedirect` hook that drops the `Authorization` header on an `https→http` scheme downgrade or cross-host redirect, preserves it same-origin, and re-imposes the 10-redirect bound; installed even when the caller supplies their own `*http.Client` (via a non-mutating shallow copy). | `client/transport_security_test.go:TestStripSensitiveOnRedirect`, `TestRedirectStripsAuthorizationEndToEnd`, `TestRedirectKeepsAuthorizationSameOrigin` |
| **Required-field validation (MUST)** | **PASS** | `errors.go` sentinels + `*.Validate()`; → HTTP 400 / gRPC `InvalidArgument` | `validation_test.go`, `grpc:TestEvaluate*InvalidArgument` |
| **Unknown-field tolerance §10.1.1** | **PASS** | `encoding/json` default; `server.decodeJSON` | `validation_test.go:TestUnknownFieldsIgnored` |

### Spec-fidelity spot checks (read from source)
1. **JSON field names** match the spec exactly across `evaluation.go`,
   `types.go`, `evaluations.go` (incl. `options.evaluations_semantic` via custom
   `Options.MarshalJSON`), `search.go`, and `metadata.go`.
2. **Batch defaulting/override** (`EvaluationsRequest.Resolved`) does a correct
   per-field merge with `clone*` helpers so resolved members never alias the
   caller's maps; empty `evaluations` ⇒ single request from top-level fields.
3. **Three batch semantics** short-circuit exactly per the spec examples
   (`[t,f,t]` / `[t,f]` / `[t]`).
4. **§9.2.3 issuer match** uses a canonicalizing comparison (`sameIssuer`):
   scheme/host ASCII-lowercased, trailing slash trimmed, query/fragment ignored.

### Residual notes (non-blocking, not regressions)
- The HTTP/core search path leaves a supplied `id` in place and relies on the
  PDP to ignore it (spec says the PDP MUST ignore); only the **gRPC** server
  actively strips it. Both are spec-compliant; behavior simply differs by
  binding.
- gRPC intentionally uses AIP-158 names for *request* paging inputs
  (`page_size`, `page_token`) while the *response* `PageResponse` message mirrors
  the spec's `next_token`/`count`/`total`. This is a documented binding choice.

---

## 2. Coverage (current, exact)

### Root module `github.com/SCKelemen/authzen`
`go test ./... -cover` → all `ok`:

| Package | Coverage |
|---|---|
| `github.com/SCKelemen/authzen` (core) | **92.5%** |
| `.../client` | **97.4%** |
| `.../server` | **91.2%** |
| `.../cmd/authzen` (CLI, part of root module — covered by `./...`) | **86.2%** |

### gRPC module `github.com/SCKelemen/authzen/grpc`
`go test ./... -cover` → `ok`:

| Package | Coverage |
|---|---|
| `.../grpc` (hand-written binding) | **94.4%** |
| `.../grpc/gen/authzen/v1` (generated protobuf) | **0.0%** |

> The generated package has no tests by design; the hand-written `grpc` package
> is at 94.4%.

### Movement vs. the previous report
| Package | Was | Now |
|---|---|---|
| core | 91.3% | **92.5%** |
| client | 45.9% | **97.4%** |
| server | 73.9% | **91.2%** |
| cmd/authzen | 53.9% | **86.2%** |
| grpc (binding) | 79.1% | **94.4%** |

---

## 3. Command evidence

**Root — gates** (`/Users/sam/zen/authzen`):
```
=== gofmt -l . ===
=== go vet ./... ===
=== go build ./... ===
=== go test ./... -count=1 ===
ok  github.com/SCKelemen/authzen        0.310s
ok  github.com/SCKelemen/authzen/client 1.043s
ok  github.com/SCKelemen/authzen/cmd/authzen 0.798s
ok  github.com/SCKelemen/authzen/server 1.047s
```
**Root — coverage:**
```
ok  github.com/SCKelemen/authzen        coverage: 92.5% of statements
ok  github.com/SCKelemen/authzen/client coverage: 97.4% of statements
ok  github.com/SCKelemen/authzen/cmd/authzen coverage: 86.2% of statements
ok  github.com/SCKelemen/authzen/server coverage: 91.2% of statements
```
**Root — dependencies:** `go list -m all` → `github.com/SCKelemen/authzen`
(only); `go.mod` has no `require` block. Zero external dependencies.

**gRPC — gates** (`/Users/sam/zen/authzen/grpc`):
```
=== gofmt -l . ===
=== go vet ./... ===
=== go build ./... ===
=== go test ./... -count=1 -cover ===
ok  github.com/SCKelemen/authzen/grpc                coverage: 94.4% of statements
    github.com/SCKelemen/authzen/grpc/gen/authzen/v1 coverage: 0.0% of statements
```
**gRPC — `go mod tidy`:** no-op (identical `go.mod`/`go.sum` sha before and
after; empty `git diff`). **`buf lint`:** exit code `0` (buf 1.65.0).
**gRPC — dependency quarantine:** `go.mod` requires `google.golang.org/grpc`,
`google.golang.org/protobuf`, `google.golang.org/genproto/...`, and `golang.org/x/*`
(indirect), with `replace github.com/SCKelemen/authzen => ../`. These live only
in the nested module and do not appear in the root module's graph.

**License grep:** `rg "Apache"` over the repo → 0 matches.
