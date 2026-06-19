# AuthZEN 1.0 Go Implementation — Independent Conformance & Coverage Verification

> Verifier: independent reviewer (did not author the implementation).
> Method: read every source + test file; ran both module test suites with
> `-race` and atomic coverage. Spec digest: `docs/SPEC_NOTES.md` (authoritative).
> Implementation files were **not** modified.

## TL;DR

- Core data model, validation, single/batch evaluation, search, pagination,
  metadata, and the HTTP + gRPC bindings are all present and largely faithful.
- Tests pass on both modules (`-race`, atomic).
- Coverage: **root total 61.6%** (core 91.3%, server 73.9%, client 45.9%,
  cmd 53.9%); **grpc module total 31.0%** (hand-written `grpc` pkg 79.1%,
  generated `gen/authzen/v1` 0.0% which drags the module total down).
- A handful of real conformance gaps exist (none are crashes): client metadata
  `policy_decision_point` is **not validated** against the derivation URL
  (§9.2.3 MUST), the default batch loop turns a per-evaluation backend error
  into a **whole-batch HTTP 500** instead of a per-item closed decision
  (§7.2.1), search does not strip/ignore a supplied `id`/`name` (§8.4/8.5
  "MUST be ignored if present"), and the gRPC pagination mapping is lossy.

---

## 1. Conformance matrix

Legend: **PASS** = implemented + positive **and** negative tests; **PARTIAL** =
implemented but missing tests, or a spec-relevant deviation/by-design limit;
**MISSING** = not implemented.

| Spec area | Status | Implementation (file) | Positive tests | Negative tests | Notes |
|---|---|---|---|---|---|
| **Access Evaluation §6** (request/response, REQUIRED S/A/R) | **PASS** | `evaluation.go` (`EvaluationRequest`, `EvaluationResponse`, `Validate`); HTTP: `server/server.go:handleEvaluation`; gRPC: `grpc/server.go:Evaluate` | `roundtrip_test.go:TestEvaluationRequestRoundTrip/Response`; `server/roundtrip_test.go:TestEvaluateRoundTrip`; `grpc/server_test.go:TestEvaluatePermit` | `validation_test.go:TestEvaluationRequestValidate` (8 missing-field cases); `server_test.go:TestMissingRequiredFieldReturns400`; `grpc:TestEvaluateMissingRequiredFieldInvalidArgument` | Field names match spec exactly (`subject/action/resource/context`, `decision`). |
| **Access Evaluations / batch §7** (defaulting, override, semantics) | **PARTIAL** | `evaluations.go` (`EvaluationsRequest.Resolved/Validate`, `Options`); `server/server.go:EvaluateBatch`; gRPC `grpc/server.go:EvaluateBatch` | `evaluations_test.go`; `server/roundtrip_test.go:TestBatch*` (ExecuteAll/Deny/Permit/Defaults); `grpc:TestEvaluateBatch*` | `validation_test.go:TestEvaluationsRequestValidate` (missing field, invalid semantic); `grpc:TestEvaluateBatchMissingFieldInvalidArgument` | Defaulting & 3 short-circuits correct. **Deviations:** (a) per-evaluation backend error aborts the whole batch with HTTP 500 rather than a per-item `{"decision":false}` + error context (§7.2.1); (b) empty/absent `evaluations` returns an `{"evaluations":[…]}` array rather than a bare single Decision (§7.1.1 "behaves identically to a single request" — ambiguous). |
| **Subject / Resource / Action Search §8** | **PASS** | `search.go` (3 request/response types + `Validate`); `server/server.go:handleSearch*`; gRPC `grpc/server.go:SearchSubjects/Resources/Actions` | `search_test.go`; `server/roundtrip_test.go:TestSearch*RoundTrip`; `grpc:TestSearchSubjects/Resources/Actions` | `validation_test.go:TestSearchRequestValidate`; `grpc:TestSearch{Subjects,Resources}MissingActionInvalidArgument` | See §8 caveat below: a supplied `subject.id`/`resource.id` is **not** stripped/ignored (left to PDP); no test that a present id is ignored. |
| **Pagination §8.2** (opaque token, end sentinel) | **PARTIAL** | `search.go` (`Page`, `PageResponse`; `NextToken` has no `omitempty` ⇒ always serialized) | `search_test.go:TestPaginationRoundTrip`, `TestEndOfResultsSentinel`; `grpc:TestPageResponseFromProtoNilWhenEmpty` | end sentinel (`next_token:""`) tested | "Token present ⇒ all other params MUST be identical / PDP SHOULD error" is **not** implemented (stateful, SHOULD). gRPC mapping is lossy (drops `count`, collapses empty-`next_token` page to nil) — see §4. |
| **Decision response incl. reason/context §5.5/§6.2** | **PASS** | `evaluation.go` (`EvaluationResponse.Context`, `Reasons`, `ReasonContext`, `EvaluationError`) | `roundtrip_test.go:TestEvaluationResponseRoundTrip` (reason_admin/user, error obj); `grpc:TestEvaluationResponseRoundTrip` | n/a (context is free-form/out of scope) | `decision` always serialized (REQUIRED); top-level batch `decision` structurally impossible (type has no field) ⇒ correctly omitted. |
| **Metadata / .well-known §9/§10** | **PARTIAL** | `metadata.go` (`Metadata`, path constants); `server/server.go:handleMetadata` (GET-only); client `client.go:Metadata`; gRPC `GetConfiguration` | `metadata_test.go`; `server/roundtrip_test.go:TestMetadataRoundTrip`; `grpc:TestGetConfiguration` | `server_test.go:TestMetadataNotConfiguredReturns404`, `TestPostOnMetadataReturns405`; `metadata_test.go:TestMetadataOmitsUnsupportedEndpoints` | Field names match spec exactly; required fields lack `omitempty`. **Gap:** client `Metadata()` does **not** validate `policy_decision_point` equals the derivation URL and discard otherwise (§9.2.3 MUST). `signed_metadata` carried but never validated (optional). |
| **HTTP binding: status codes & content types §10** | **PASS** | `server/server.go` (`requirePost`→405/415, `decodeJSON`→400, `writeJSON`/`writeError`, X-Request-ID echo, 404 catch-all) | `server/roundtrip_test.go` (200 happy paths, deny=200) | `server_test.go`: 400 (malformed + missing field), 405 (GET on POST, POST on metadata), 415 (wrong + missing CT), 404 (unknown path + metadata absent), charset accepted, X-Request-ID echoed | Error body is `{"error":"…"}` JSON (spec says "an error message string"; wrapping in JSON is a reasonable, documented choice). No 401/`WWW-Authenticate` helper (auth out of scope; SHOULD). |
| **Required-field validation (MUST rules)** | **PASS (core)** | `errors.go` (sentinels + `ValidationError`), `*.Validate()` across core | `validation_test.go` (errors.Is/As on every sentinel + field path) | extensive missing-field matrix | Mapped to HTTP 400 (server) and gRPC `InvalidArgument` (grpc). |
| **Unknown-field tolerance §10.1.1** | **PASS** | `encoding/json` default (no `DisallowUnknownFields`); `server.decodeJSON` | `validation_test.go:TestUnknownFieldsIgnored` | — | Correct: receivers MUST ignore unknown members. |
| **gRPC profile (proto ⇄ core conversions)** | **PASS (pkg) / PARTIAL (fidelity)** | `grpc/conv.go`, `grpc/server.go`, `grpc/client.go` | `grpc/conv_test.go` round-trips (entities, eval, batch, search, metadata, semantics) | `grpc/server_test.go` InvalidArgument/Internal/status-passthrough | gRPC intentionally uses AIP-158 names (`page_size`, `next_page_token`, `total_size`) not the JSON names — fine for a non-normative binding, but the `count` field is dropped and rebuilt from `len(results)` (lossy). |

### Spec-fidelity spot checks (read from source, not comments)

1. **JSON field names** — verified exact match: `evaluation.go`/`types.go` →
   `subject`,`action`,`resource`,`context`,`type`,`id`,`name`,`properties`,
   `decision`,`context`; `evaluations.go` → `evaluations`,`options` and
   `options.evaluations_semantic` (via custom `Options.MarshalJSON`);
   `search.go` → `token`,`limit`,`properties`,`next_token`,`count`,`total`,
   `results`,`page`; `metadata.go` → all eight `*_endpoint`/`policy_decision_point`/
   `capabilities`/`signed_metadata` names match §9.1.1 / §12.1.3.
2. **Batch defaulting/override (`Resolved`)** — correct per-field merge: a
   member value wins; nil inherits top-level; empty `evaluations` ⇒ single
   request from top-level fields (`evaluations.go:130`). Confirmed by
   `TestBatchDefaultsApplied`.
3. **Well-known config field names** — match (see #1). Required fields
   (`policy_decision_point`, `access_evaluation_endpoint`) are **not**
   `omitempty` (always emitted); optional ones are.
4. **Three batch semantics short-circuit** — `server/server.go:EvaluateBatch`:
   `execute_all` returns all; `deny_on_first_deny` returns up to & including the
   first `!Decision`; `permit_on_first_permit` up to & including the first
   `Decision`. Verified by `TestBatch*` (root) and `TestEvaluateBatch*` (grpc),
   matching the verbatim spec examples (`[t,f,t]`, `[t,f]`, `[t]`).

---

## 2. Coverage (exact numbers)

### Root module `github.com/SCKelemen/authzen`
Command: `go test ./... -race -coverprofile=/tmp/root.cov -covermode=atomic`
→ all packages **ok**. `go tool cover -func | tail -1`: **total 61.6%**.

| Package | Coverage |
|---|---|
| `github.com/SCKelemen/authzen` (core) | **91.3%** |
| `.../server` | **73.9%** |
| `.../cmd/authzen` | **53.9%** |
| `.../client` | **45.9%** |

### gRPC module `github.com/SCKelemen/authzen/grpc`
Command: `go test ./... -race -coverprofile=/tmp/grpc.cov -covermode=atomic`
→ **ok** (`grpc`), generated pkg has no tests. `func | tail -1`: **total 31.0%**.

| Package | Coverage |
|---|---|
| `.../grpc` (hand-written) | **79.1%** |
| `.../grpc/gen/authzen/v1` (generated) | **0.0%** |

> The 31.0% module figure is dominated by generated protobuf code with zero
> tests. The meaningful, hand-written `grpc` package is at 79.1%.

---

## 3. Lowest-covered files/functions & concrete test gaps

### Client package (45.9%) — biggest real gap
`go tool cover -func=/tmp/root.cov` shows these client methods at **0.0%** in
the client package's own profile (they are exercised end-to-end by
`server/roundtrip_test.go`, but that coverage is credited to the `server`
package, not `client`):
- `client.go:177 EvaluateBatch`, `196 SearchSubjects`, `215 SearchResources`,
  `234 SearchActions`, `253 Metadata`, `295 get` — all 0.0%.
- Option setters `WithHTTPClient`, `WithEvaluationsPath`,
  `WithSearch{Subject,Resource,Action}Path` — 0.0%.

**Add (client_test.go):** for each of `EvaluateBatch`/`SearchSubjects`/
`SearchResources`/`SearchActions`/`Metadata` against an `httptest` server:
(a) a positive decode test, (b) a nil-request error, (c) a client-side
`Validate` failure that sends **no** HTTP request, (d) a non-2xx →
`*APIError`. Add a `Metadata()` test that asserts the **`policy_decision_point`
discard rule** once implemented (see gap A below).

### Server package (73.9%)
- `handleEvaluations` 56.2%, `handleSearchSubject/Resource/Action` 53.8% — the
  error/return branches are not driven over HTTP.
  **Add:** HTTP-level negative tests for the batch and search endpoints:
  malformed JSON (400), missing required field (400), and a PDP that returns an
  error (→ 500). Currently only the single-evaluation endpoint has the 400/500
  HTTP paths fully covered.
- `isJSONContentType` 83.3% — add a malformed Content-Type (`mime.ParseMediaType`
  error) case.
- Path-override options `WithEvaluationPath`/`WithEvaluationsPath`/`WithSearch*`
  are 0.0% — add one test that builds a handler with custom paths and hits them.

### Core (91.3%) — small but spec-relevant
- `search.go` `SubjectSearchRequest.Validate` 71.4%, `ResourceSearchRequest`
  66.7%, `ActionSearchRequest` 66.7% — missing-`subject` and missing-`resource`
  branches for resource/action search are untested.
  **Add:** resource-search missing subject; action-search missing subject;
  subject-search missing action/resource (a couple are present, complete the
  matrix).
- `evaluations.go` `Validate` 90.9% / `UnmarshalJSON` 91.7% — add a case where
  `evaluations_semantic` is a non-string JSON value, and a top-level-missing +
  empty-evaluations case.

### gRPC `conv.go` (most funcs 66–87%)
- The `mapToStruct` error branch (invalid value → error) is never hit in any
  `*ToProto`; the nil-input branches of several `*FromProto` are partial.
  **Add:** a conversion test passing `Properties`/`Context` containing an
  unsupported value (e.g. a `chan`) to assert the error propagates from
  `evaluationRequestToProto`, `subjectSearchRequestToProto`, etc.
- `grpc/client.go` `NewClientFromGRPC` and `Raw` are 0.0%; `metadataFromProto`
  66.7%. Add a fake-client test using `NewClientFromGRPC` and assert `Raw()`.

### cmd/authzen (53.9%)
- `search.go:runSearchResource` 0.0%, `runSearch` 27.3%, many `*Usage`/`main`
  helpers 0.0%. Not conformance-critical (CLI PEP), but `runSearchResource`
  being 0% while subject/action are partially covered is an obvious asymmetry —
  add a CLI resource-search test mirroring the existing subject/action ones.

### Prioritized concrete gaps (by correctness value)

1. **Implement + test §9.2.3 metadata validation (MUST).** `client.Metadata`
   must check `policy_decision_point` equals the base URL the well-known doc was
   derived from and discard/error otherwise. Add positive + mismatch tests.
2. **Batch per-evaluation error semantics (§7.2.1).** Decide and document:
   today `server.EvaluateBatch` returns HTTP 500 for *any* member error; the
   spec models per-item failures as `{"decision":false}` + error context with
   the batch still HTTP 200. Add a test fixing the intended behavior (and, if
   per-item is intended, convert backend errors to closed decisions).
3. **Search "id MUST be ignored if present" (§8.4/§8.5).** Add a test that a
   subject/resource search with a populated `id` still validates and that the id
   is not forwarded in a way that changes results (or strip it in `Validate`/
   conversion). Currently no enforcement and no test.
4. **HTTP-level negative tests for batch & search endpoints** (400 missing
   field, 500 PDP error) — closes the 53–56% server handler branches.
5. **Client method coverage** (batch/search/metadata positive + APIError +
   local-validation-no-send) — raises client from 45.9% and tests the real PEP
   surface directly rather than only transitively.
6. **gRPC conversion error paths & pagination fidelity** — test
   `mapToStruct`-error propagation; document/justify the lossy `count` drop and
   the empty-`next_token`→nil-page collapse (a PDP signalling end-of-results
   with `next_token:""` and no count/total loses its `page` object over gRPC).
