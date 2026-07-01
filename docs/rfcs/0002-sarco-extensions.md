# RFC 0002: SARCO Extensions — Application Audit, Actor Chains, and Scoping

- **Status:** Draft
- **Author:** Samuel Kelemen
- **Date:** [verify — set on publish]
- **Reviewers:** TBD
- **Extends:** [RFC 0001: SARCO — an AuthZEN-aligned audit-log information model](./0001-sarco-audit-log.md)

## Summary

RFC 0001 defines SARCO — **S**ubject, **A**ction, **R**esource, **C**ontext,
**O**utcome — with two event types (`authz.decision`, `resource.access`)
correlated by a PDP-minted `decision_id`. This RFC extends SARCO with the pieces
a real multi-tenant application needs before it can retire its homegrown audit
log:

1. **A third event type, `application.audit`** — for application events that are
   not authorization decisions and not resource-server enforcement: CRUD on
   domain objects, settings and configuration changes, membership changes, and
   grant lifecycle. Same SARC vocabulary; its Outcome adds a normative
   `changes[]` array for before/after mutation capture, with redaction rules.
2. **A normative `actor` envelope member on all event types** — capturing who
   *actually* acted when it differs from the `subject`: delegation chains
   (services, workflows, AI agents acting on behalf of a user) and
   impersonation sessions (an operator acting *as* a user). Aligned with the
   `accessrequest.Actor` type this repo already ships and with the OAuth `act`
   claim semantics.
3. **A first-class `scope` envelope member** — an ordered tenancy path
   (e.g. organization → workspace → project) that gives multi-tenant systems a
   queryable partition key and defines who may read the record, without mining
   the free-form `context`.
4. **Presentation and correlation conventions** — a `display_name` property
   convention (presentation-only, never identity), and an optional `source`
   envelope member reusing `accessrequest.Source` to tie records to sessions,
   tickets, and integrations.

Like RFC 0001, this is **schema only**: no new wire protocol, no transport
mandate, and no change to the two event types RFC 0001 defines. Everything here
is additive.

## Problem & context

RFC 0001 closes the H4 gap for *decisions* and *enforcement*: the PDP records
what it decided, the resource server records what it did. But most of what an
application audit log holds is neither. "Alice renamed project X," "Bob changed
the SSO enforcement setting," "Carol added Dave to workspace W," "a support
engineer granted time-boxed project access" — these are domain mutations. There
is no PDP round trip at the moment of record (the authorization, if any,
happened earlier and elsewhere), no `decision_id` to reference, and the fact
that matters is not *permit/deny* but *what changed, from what, to what*.

Teams that try to force these into `resource.access` end up lying in the same
way RFC 0001's merged-record alternative lies: `decision_ref` is perpetually
null, `obligations_fulfilled` is perpetually empty, and the one field auditors
actually ask for — the before/after diff — has no home. Meanwhile SIEMs
classify these events differently (application activity, not IAM), so the
mapping story diverges too.

Three further gaps show up as soon as the emitter is a real production system:

1. **The actor is not the subject.** A support engineer impersonates a customer
   to reproduce a bug; an AI agent calls an MCP tool on behalf of a user; a
   workflow service executes a scheduled job under a customer's grant. RFC 0001
   records only `subject`. If the impersonator or the agent chain is not on the
   record, the audit log attests that *the customer* changed the setting — which
   is exactly the kind of false attestation an audit log exists to prevent. This
   repo already models the chain (`accessrequest.Actor`, following the OAuth
   actor-profile draft), and the impersonation workstream needs the audit side
   of it.
2. **Tenancy is buried.** In a multi-tenant system, *every* audit query is
   scoped: "show workspace admins the events in their workspace." With tenancy
   hidden in `context` or in `resource.properties`, the partition key must be
   mined per-deployment, and the read-authorization boundary ("who may see this
   record") has no normative anchor.
3. **Records are unreadable without joins.** Consumers render audit trails to
   humans. Requiring a live directory join to display "Alice Smith" instead of
   `usr_01HF...` makes every viewer stateful; but letting display names leak
   into identity comparison creates spoofable identity. The convention needs to
   be stated once, normatively.

**What breaks if we do nothing:** application teams keep their homegrown audit
schema next to SARCO, the one-vocabulary win evaporates, impersonated and
agent-driven actions are attributed to the wrong principal, and tenant-scoped
audit visibility (workspace owners/admins reading their own logs) has no schema
to build on.

## Goals / Non-goals

**Goals**

- Define `application.audit` as a third SARCO event type over the same SARC
  vocabulary, with an Outcome shape that captures mutations (`changes[]`) and
  normative redaction rules.
- Define a normative `actor` envelope member — delegation and impersonation
  chains of arbitrary depth — reusing `accessrequest.Actor` and the OAuth `act`
  claim semantics, on **all** SARCO event types (including RFC 0001's two).
- Define a first-class `scope` envelope member as the tenancy partition key and
  the read-visibility boundary for the record.
- Define the `display_name` presentation convention and the optional `source`
  correlation member (reusing `accessrequest.Source`).
- Extend RFC 0001's mapping tables (OCSF, CADF, SET) to cover the new event
  type and the actor chain.

**Non-goals**

- **Authentication events.** Unchanged from RFC 0001: login, MFA, and session
  start/stop are SET/SSF/CAEP territory. (An impersonation *session start* is an
  authn event; the *actions taken during it* are SARCO records carrying the
  actor chain.)
- **Tamper evidence.** Unchanged: integrity is an orthogonal layer (RFC 0001,
  Adjacent layers).
- **Transport.** Unchanged: SARCO remains transport-agnostic; SET is one
  binding. This RFC adds **no new wire protocol** — only schema.
- **Retention, review workflow, and access-control policy for reading audit
  logs.** `scope` defines the *boundary*; the policy that evaluates it is the
  PDP's job (and is itself an AuthZEN evaluation).

## Proposal

### Event type 3 — `application.audit`

Emitted by the application after performing (or failing to perform) a domain
mutation or other auditable application event: CRUD on domain objects, settings
and configuration changes, membership changes, grant lifecycle
(issue/extend/revoke), export/import, and similar. The `action` is the
**performed** application action, named in the emitter's action vocabulary
(e.g. `project.rename`, `workspace.member.add`, `project.access.grant`).

Why a distinct event type rather than overloading `resource.access`:

- **No authorizing action at a resource-server boundary.** `resource.access` is
  the enforcement-time record of a PEP performing an action a PDP authorized;
  its spine is `decision_ref`. An application mutation typically has **no
  decision to reference** — `decision_ref` would be perpetually null, which
  RFC 0001 reserves for the *static-rule* case, not the *not-an-enforcement-event*
  case. Overloading would make the two indistinguishable.
- **Different facts.** The high-signal payload is the before/after diff
  (`changes[]`), which has no home in the access Outcome; conversely
  `obligations_fulfilled` is meaningless here.
- **Different SIEM class.** SIEMs route authorization/IAM events and
  application-activity events to different classes and detections; collapsing them
  degrades both mappings (see Mappings).

When an application mutation *was* directly authorized by a PDP round trip, the
emitter MAY set `decision_ref` on the `application.audit` record with the same
semantics as RFC 0001 (valid, null, or stale). Correlation via `trace` and
`source` (below) is the more common join path.

```json
{
  "event_type": "application.audit",
  "event_id": "evt_01HJ...",
  "decision_ref": null,
  "occurred_at": "2026-01-12T20:05:11Z",
  "scope": [
    { "type": "organization", "id": "org_9f2c" },
    { "type": "workspace", "id": "ws_7a41" }
  ],
  "subject": { "type": "user", "id": "usr_01HF...",
               "properties": { "display_name": "Alice Smith" } },
  "action":   { "name": "workspace.settings.update" },
  "resource": { "type": "workspace_settings", "id": "ws_7a41",
                "properties": { "display_name": "Acme / Payments" } },
  "context":  { "time": "2026-01-12T20:05:11Z", "ip_address": "172.217.22.14" },
  "outcome": {
    "result": "success",
    "status": 200,
    "effect": "updated",
    "changes": [
      { "field": "sso.enforced", "old": false, "new": true },
      { "field": "scim.token", "old": "[REDACTED]", "new": "[REDACTED]",
        "redacted": true }
    ]
  }
}
```

Outcome (application):

| Field | Type | Notes |
| --- | --- | --- |
| `result` | `success` \| `failure` \| `error` | Same vocabulary as `resource.access` (RFC 0001). |
| `status` | integer | Transport/application status (e.g. HTTP). OPTIONAL. |
| `effect` | string | Side effect actually applied (`created`, `updated`, `deleted`, `granted`, `revoked`, `no-op`, ...). |
| `changes` | array of Change | Before/after mutation capture. REQUIRED when the event records a mutation and `result` is `success`; MUST be empty or omitted when nothing changed. |
| `error` | object | Machine-readable failure detail (`code`, `message`) when `result` is `failure` or `error`. OPTIONAL. |

Change object:

| Field | Type | Notes |
| --- | --- | --- |
| `field` | string | Path of the mutated field, in the emitter's naming (dotted paths RECOMMENDED). REQUIRED. |
| `old` | any | Value before the mutation. MAY be the redaction sentinel. |
| `new` | any | Value after the mutation. MAY be the redaction sentinel. |
| `redacted` | boolean | True when `old`/`new` carry the sentinel instead of the real value. OPTIONAL, default false. |

**Redaction rules (normative):**

- Sensitive values **MUST be redactable**: an emitter replaces `old`/`new` with
  the sentinel string `"[REDACTED]"` and sets `redacted: true`, preserving the
  *fact* of the change while withholding the value.
- `changes` **MUST NOT capture secrets** — credentials, tokens, API keys, key
  material, and values the emitter classifies as secret MUST be redacted at
  emission time, never post-hoc. A redaction applied downstream is too late; the
  sink already holds the secret.
- Redaction is per-side: a rotation event MAY redact both `old` and `new`; a
  reclassification MAY redact only one side.

### Actor chains — delegation and impersonation

This RFC adds a normative `actor` envelope member to **all** SARCO event types
(`authz.decision`, `resource.access`, `application.audit`). It answers the
question RFC 0001's `subject` cannot: *who actually performed this, and on whose
authority?*

The member reuses the shape of `accessrequest.Actor` (this repo,
`accessrequest/request.go`), which itself follows the OAuth Actor Profile for
Delegation, and it aligns with the RFC 8693 `act` claim: the top-level actor is
the immediate actor; nested `act` objects walk outward toward the `subject`.

> OAuth Actor Profile for Delegation (draft-mcguinness-oauth-actor-profile) —
> https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/
> RFC 8693 §4.1 — OAuth 2.0 Token Exchange, `act` (Actor) Claim —
> https://datatracker.ietf.org/doc/html/rfc8693#section-4.1

| Field | Type | Notes |
| --- | --- | --- |
| `mode` | `delegation` \| `impersonation` | Discriminator (normative; see below). REQUIRED when `actor` is present. |
| `id` | string | Stable identifier of the immediate actor. REQUIRED. |
| `issuer` | string | Authority/tenant/IdP for the actor identifier. OPTIONAL. |
| `type` | string | Actor category: `user`, `service`, `workload`, `ai_agent`, ... OPTIONAL. |
| `act` | object | Next link in the chain (`sub`/`iss`, optional `sub_profile`, and a further nested `act`), per RFC 8693 / the actor-profile draft. Arbitrary depth. OPTIONAL. |
| `session_id` | string | Identifier of the delegation/impersonation session under which the actor operated. OPTIONAL (RECOMMENDED for impersonation). |

**Delegation vs. impersonation (normative):**

- **Delegation** (`mode: delegation`): the `subject` remains the principal on
  whose behalf the action occurred; the actor chain records *who acted for
  them* — a service, a workflow, an AI agent. Authorization is evaluated against
  the subject (possibly narrowed by the delegation); attribution is the chain.
- **Impersonation** (`mode: impersonation`): the `subject` is the
  **impersonated** user — the record reads, for downstream authorization and
  data semantics, as if that user acted. The impersonator **MUST** be recorded
  as the actor, and the record **MUST** be marked with `mode: impersonation`.
  A record of an action taken during an impersonation session that carries no
  actor, or carries the actor without the impersonation marking, is
  **non-conformant** — it falsely attests that the user acted.

More generally: **any SARCO record produced under delegation or impersonation
that omits the actor chain is non-conformant.** When the subject acted directly,
`actor` is omitted entirely (absence means "subject acted in person").

**AI-agent chains.** Agentic paths are first-class, not a special case. An MCP
client calling a tool for a user, an autonomous agent operating under a standing
grant, and agent-calls-agent chains are all expressed by the same structure:
the immediate actor is the last hop (the thing that touched the system), and
each `act` nesting is the next authority outward, terminating at the chain root
acting for the `subject`. Example — an autonomous agent invoked by an
orchestrator on behalf of Alice:

```json
"actor": {
  "mode": "delegation",
  "id": "agent://research-assistant",
  "type": "ai_agent",
  "act": {
    "sub": "svc://orchestrator",
    "iss": "https://idp.example.com",
    "sub_profile": "workload"
  }
}
```

Chains have no depth limit; emitters MUST preserve every hop they know about
and MUST NOT collapse the chain to its root or its leaf.

On `authz.decision` events the actor chain records who *requested* the decision
on the subject's behalf (e.g. the agent that called the PDP); on
`resource.access` and `application.audit` it records who performed the action.

### Scope — tenancy as a first-class envelope member

This RFC adds an optional-but-RECOMMENDED `scope` envelope member to all event
types: an **ordered** array of `{type, id}` pairs, outermost container first
(e.g. organization → workspace → project). Emitters in multi-tenant systems
SHOULD populate it on every record.

| Field | Type | Notes |
| --- | --- | --- |
| `scope` | array of `{ "type": string, "id": string }` | Ordered, outermost first. Each element names one containment level. |

Semantics (normative):

- **Partition key.** `scope` is the queryable tenancy path. Consumers MUST be
  able to filter records by scope prefix (all events under `organization
  org_9f2c`, all events under `workspace ws_7a41`) without inspecting `context`
  or `resource.properties`.
- **Visibility boundary.** `scope` is the authorization boundary for *reading*
  the record: a reader authorized at a scope element is eligible to read
  records whose scope path contains that element (e.g. workspace owners/admins
  see workspace-scoped records; organization admins see everything beneath the
  organization). The read-access *policy* is out of scope (it is itself an
  AuthZEN evaluation with the record as the `resource`); the *boundary* it
  evaluates is this member.
- `scope` describes where the **resource** lives, not where the subject or
  actor lives. Cross-tenant actions (a subject from tenant A touching a
  resource in tenant B) carry the resource's scope; the subject's home tenant,
  if relevant, belongs in `subject.properties`.

### Presentation convention — `display_name`

Emitters MAY set `properties.display_name` (string) on `subject`, `resource`,
and any other SARC entity carrying `properties`, to make records renderable
without a directory join.

Normative rules:

- `display_name` is **presentation-only**. It **MUST NOT** be used for
  identity, comparison, correlation, or authorization — only `type` + `id`
  identify an entity.
- `display_name` **MAY be stale**: it captures the name *at emission time* and
  is never updated. Renames do not rewrite history.
- Consumers rendering `display_name` SHOULD treat it as untrusted display text
  (it is emitter-supplied and, transitively, often user-supplied).

### Correlation convention — `source`

This RFC adds an optional `source` envelope member reusing the shape of
`accessrequest.Source` (this repo, `accessrequest/request.go`; profile §10.1
`client.source`):

| Field | Type | Notes |
| --- | --- | --- |
| `session_id` | string | Bounded interaction context (application session, chat/agent conversation, CLI invocation, workflow thread). OPTIONAL. |
| `external_url` | string | HTTPS URL of the external system that motivated the action (ticket, document, chat thread). OPTIONAL. |
| `integration_id` | string | Upstream integration or workflow that produced the action. OPTIONAL. |

`source` complements `trace` (W3C Trace Context, per RFC 0001): `trace` joins
records within one distributed request; `source` joins records across requests
belonging to one session, ticket, or integration run. For impersonation,
`source.session_id` and `actor.session_id` SHOULD carry the same impersonation
session identifier, tying every action in the session together.

> W3C Trace Context — https://www.w3.org/TR/trace-context/

### Extended envelope (summary)

RFC 0001's envelope, with this RFC's additions marked **(new)**:

| Field | Type | Notes |
| --- | --- | --- |
| `event_type` | string | `authz.decision`, `resource.access`, or **(new)** `application.audit`. |
| `event_id` | string | Unique id of *this* record. |
| `decision_id` | string | Decision-record only (RFC 0001). |
| `decision_ref` | string \| null | Access records (RFC 0001); MAY appear on `application.audit` when a PDP round trip directly authorized the mutation. |
| `occurred_at` | RFC 3339 | When the event happened. |
| `trace` | object | W3C trace context. |
| `actor` | object | **(new)** Delegation/impersonation chain. REQUIRED whenever the acting party differs from `subject`; omitted when the subject acted directly. |
| `scope` | array | **(new)** Ordered tenancy path; partition key and read-visibility boundary. |
| `source` | object | **(new)** Session/ticket/integration correlation (`accessrequest.Source` shape). |

## Worked example — time-boxed project access grant under impersonation

A support engineer, operating through an approved impersonation session,
grants a customer time-boxed access to a project inside a workspace. One
`application.audit` record captures the whole story:

```json
{
  "event_type": "application.audit",
  "event_id": "evt_01HK7Q...",
  "decision_ref": null,
  "occurred_at": "2026-01-12T21:14:03Z",
  "scope": [
    { "type": "organization", "id": "org_9f2c" },
    { "type": "workspace", "id": "ws_7a41" }
  ],
  "subject": {
    "type": "user",
    "id": "usr_cust_318a",
    "properties": { "display_name": "Dana Customer" }
  },
  "actor": {
    "mode": "impersonation",
    "id": "usr_support_042",
    "issuer": "https://idp.example.com",
    "type": "user",
    "session_id": "imp_sess_01HK6..."
  },
  "action": { "name": "project.access.grant" },
  "resource": {
    "type": "project",
    "id": "proj_c55e",
    "properties": { "display_name": "Payments Backend" }
  },
  "context": { "time": "2026-01-12T21:14:03Z", "ip_address": "203.0.113.9" },
  "source": {
    "session_id": "imp_sess_01HK6...",
    "external_url": "https://support.example.com/tickets/48213"
  },
  "outcome": {
    "result": "success",
    "status": 200,
    "effect": "granted",
    "changes": [
      { "field": "access_type", "old": null, "new": "editor" },
      { "field": "expires_at", "old": null, "new": "2026-01-13T21:14:03Z" }
    ]
  }
}
```

Reading the record: the grant is attributed to Dana's account (`subject`), the
support engineer is on the hook for having performed it (`actor`,
`mode: impersonation`), the ticket that motivated it is one click away
(`source.external_url`), the grant is visibly time-boxed (`changes` →
`expires_at`), and workspace admins of `ws_7a41` can see it (`scope`).

How a typical homegrown application audit-log call maps onto this,
field-by-field:

| Typical audit call parameter | SARCO extension field |
| --- | --- |
| actor id | `actor.id` (impersonation/delegation) or `subject.id` (direct) |
| actor display name | `subject.properties.display_name` / actor entry in a directory — presentation only |
| target type | `resource.type` |
| target id | `resource.id` |
| target display name | `resource.properties.display_name` |
| workspace id | `scope[]` element `{ "type": "workspace", "id": ... }` |
| event/action name | `action.name` |
| status | `outcome.result` (+ `outcome.status` for the numeric code) |
| error | `outcome.error` (`code`, `message`) when `result` ≠ `success` |
| details map (before/after) | `outcome.changes[]` (`field`, `old`, `new`, `redacted`) |
| details map (other) | `context` (environment) or `action.properties` (parameters) |
| session / ticket reference | `source.session_id` / `source.external_url` |
| timestamp | `occurred_at` |

Nothing in the homegrown shape is lost, and four things are gained: the
impersonation marking, the ordered scope path, the redaction contract, and the
standards mappings below.

## Mappings

Extending RFC 0001's tables. As there, each mapping is lossless in the
direction that matters, and version-sensitive pins carry `[verify]`.

### OCSF

- `application.audit` → **Application Activity** category (UID 6). Nearest
  class: **Application Lifecycle** (UID 6002) for lifecycle events, or **API
  Activity** (UID 6003) for generic CRUD, with `outcome.effect` mapping to the
  class activity and `outcome.changes[]` carrying into the class's
  enrichment/unmapped data. [verify — confirm on the pinned OCSF version
  whether a dedicated data/change-activity class (e.g. Data Security or a 6.x
  application class with before/after support) is a better home for mutation
  records than 6003]
- Actor chain → OCSF `actor.user` (the immediate actor) plus `actor.session`
  (the impersonation/delegation session, from `actor.session_id`); the
  impersonated principal (SARCO `subject`) → OCSF `user` on the target side of
  the class. [verify — class-dependent; confirm whether the target OCSF class
  distinguishes acting user from affected user, and where multi-hop chains land
  (likely `unmapped`)]
- `scope` → OCSF `metadata`/`cloud`/organization attributes per class.
  [verify]
- Schema: https://schema.ocsf.io/ (Application Activity:
  https://schema.ocsf.io/categories/application)

### CADF (DMTF DSP0262)

| CADF | SARCO extension |
| --- | --- |
| `initiator` | `actor` when present (the party that acted), else `subject` |
| `initiator.credential` | the delegation/impersonation assertion backing the chain (`actor.act`, session token) |
| `target` | `resource` |
| `action` | `action` |
| `outcome` | `outcome.result` |
| `observer` | the emitting application |
| `attachments` / `measurements` | `outcome.changes[]` (before/after capture) [verify — confirm the idiomatic CADF home for state diffs] |

When `mode: impersonation`, CADF's `initiator` is the impersonator and the
impersonated user (SARCO `subject`) is carried as target-adjacent context —
CADF has no native impersonation marking, so the `mode` discriminator MUST be
preserved in the mapped event's extension data.

> DMTF DSP0262 (CADF), v1.0.0 —
> https://www.dmtf.org/sites/default/files/standards/documents/DSP0262_1.0.0.pdf
> (index: https://www.dmtf.org/dsp/DSP0262)

### SET / SSF / CAEP

- `application.audit` records MAY be emitted as Security Event Tokens like the
  other two event types; the SARCO `subject` maps to the SET subject
  (RFC 9493 subject identifier), and the actor chain maps onto the SET/JWT
  `act` claim structure directly — this is the same claim family the chain is
  modeled on, so the round trip is exact.
  > RFC 8417 — Security Event Token (SET) —
  > https://datatracker.ietf.org/doc/html/rfc8417
  > RFC 9493 — Subject Identifiers for Security Event Tokens —
  > https://datatracker.ietf.org/doc/html/rfc9493
  > RFC 8693 §4.1 — `act` claim —
  > https://datatracker.ietf.org/doc/html/rfc8693#section-4.1
- Grant lifecycle events (`project.access.grant` / extend / revoke as
  `application.audit` records) are the application-side complement of the CAEP
  signals RFC 0001 sketches for `aarp`; the two views correlate via `source`
  and `trace`.

## Alternatives considered

Each option gets its best case before the concrete reason it loses here.

1. **Overload `resource.access` for application events.** *Best case:* no new
   event type to socialize; one Outcome shape fewer. *Why it loses:* it
   conflates "enforcement of an authorized action at a PEP boundary" with
   "domain mutation with no decision in sight." `decision_ref: null` becomes
   ambiguous (static rule vs. not-an-enforcement-event), the mutation diff has
   no home, and SIEM classification degrades for both event families. The
   category error RFC 0001 avoids between decision and access would be
   reintroduced one layer up.
2. **Put the actor chain in `context`.** *Best case:* zero schema change —
   `context` is free-form and the data fits today. *Why it loses:* the chain is
   the difference between a true and a false attestation; a field with MUST
   semantics ("impersonation MUST be recorded and marked") cannot live in a
   member the spec defines as having no required keys. Free-form placement also
   makes the non-conformance rule unenforceable and the OCSF/CADF actor mapping
   per-deployment.
3. **Model impersonation by swapping `subject` to the impersonator.** *Best
   case:* the record trivially shows who acted. *Why it loses:* it breaks the
   data semantics — downstream systems (and RFC 0001's correlation with the
   decision the PDP made *about the impersonated user*) key on the subject the
   system believed was acting. Impersonation means the system acted *as* the
   user; the record must reflect that, with the impersonator alongside, marked.
   This is also how RFC 8693 frames impersonation vs. delegation.
4. **Scope as a `resource.properties` convention.** *Best case:* no envelope
   change; tenancy is arguably a resource attribute. *Why it loses:* `properties`
   is free-form and per-type; a partition key and visibility boundary must be
   uniform across all event types and all resource types to be queryable and to
   anchor read authorization. Mining per-type properties is exactly the status
   quo this member exists to end.
5. **Status quo / do nothing.** *Best case:* RFC 0001 ships as-is; smaller
   surface. *Why it loses:* application teams cannot adopt SARCO for the bulk
   of their audit volume, impersonated/agent actions remain misattributed, and
   tenant-scoped audit visibility has no schema anchor — the three concrete
   consumers this extension exists for.

## Assumptions & risks

Load-bearing assumptions first; failure modes are written so a reviewer can
check them, ordered by impact × likelihood.

- **Assumption: emitters can detect delegation/impersonation at emission time.**
  The non-conformance rule only works if the emitting code path *knows* it is in
  an impersonation or delegation context. *Fails if* impersonation is
  implemented as a plain credential swap invisible to the application layer.
  *Mitigation/test:* require the impersonation session token to carry the `act`
  claim (RFC 8693) so the chain is extractable wherever the token is; verify on
  the impersonation workstream's token design before finalizing.
- **Assumption: `changes[]` can be produced without a read-modify-write race.**
  *Fails if* the emitter cannot observe the pre-image (blind writes, upserts),
  yielding `old: null` that is indistinguishable from "was actually null."
  *Mitigation:* permit an explicit `"old": { "unknown": true }` marker or omit
  `old`; decide in review (Open Questions).
- **Assumption: one ordered scope path is enough.** *Fails if* a deployment has
  DAG-shaped tenancy (a project in two workspaces) or resources spanning scopes.
  *Mitigation:* the member is an array of paths in the worst case; keep single-path
  as the normative default and revisit on evidence.
- **Risk: redaction under-triggers.** *Fails if* emitters don't classify a value
  as secret and `changes[]` captures it; the sink then holds the secret and
  post-hoc redaction is (per this RFC) too late. *Mitigation:* pair the profile
  with a deny-list of field-path patterns that MUST be redacted (token, secret,
  key, password); conformance vector asserting sentinel substitution.
- **Risk: `display_name` gets used for identity anyway.** *Fails if* a consumer
  correlates or authorizes on the display string. *Mitigation:* the MUST NOT is
  normative; reference implementations never index it.

## Rollout / migration

Additive to RFC 0001's phases; nothing here blocks Phase 1 of RFC 0001.

1. **Phase 1 — schema + application emitter.** Land `application.audit`,
   `actor`, `scope`, `source`, and `display_name` in the profile doc and the
   in-repo `sarco/` package (types + `Validate` helpers, matching the repo's
   zero-dependency conventions). Provide an emitter helper that takes the
   typical homegrown call shape (actor, target, workspace, status, error,
   details) and produces a conformant record — the worked-example mapping as
   code.
2. **Phase 2 — chain plumbing.** Wire the actor chain from the impersonation
   and delegation token paths (`act` claim extraction) so records get the chain
   for free; add the conformance vectors (impersonation-without-chain is
   rejected; redaction sentinel round-trips).
3. **Phase 3 — mappings + visibility.** Pin OCSF version and classes alongside
   RFC 0001's `[verify]` items; ship the OCSF exporter extension; build the
   scope-filtered read path (workspace owners/admins reading workspace-scoped
   records) as an AuthZEN evaluation over the record's `scope`.

## Open questions

Cheap, decisive questions first.

1. **Which OCSF class carries `application.audit` mutations best** — API
   Activity (6003), Application Lifecycle (6002), or a data-change class on the
   pinned version? (Same cheap test as RFC 0001: map the worked example and
   diff for dropped fields.) *Decide together with RFC 0001's OCSF pin.*
2. **Unknown pre-image in `changes[]`:** omit `old`, allow an explicit
   unknown marker, or require emitters to read-before-write? (Cheap; affects
   the Change table only.)
3. **Is `mode` binary,** or do we need a third value for machine-to-machine
   contexts where "delegation vs. impersonation" is ill-posed (e.g. a workload
   acting under its own identity on a schedule *derived from* a user's
   configuration)?
4. **Does `scope` stay a single ordered path,** or become a set of paths for
   DAG-shaped tenancy? (Default: single path; revisit on evidence.)
5. **Should `actor` be REQUIRED (not just recorded) on `authz.decision`** when
   the PDP can see an `act` claim in the caller's token — i.e., does the PDP
   have a duty to record the chain even when the PEP didn't pass it explicitly?
6. **Grant lifecycle placement,** refining RFC 0001's question: are
   `aarp`/JIT grant events `application.audit` records, CAEP signals, or both —
   and if both, which is authoritative?
