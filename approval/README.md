# authzen/approval

An **approval-workflow extension** ("aarp") for the
[OpenID AuthZEN Authorization API 1.0][spec]: asynchronous, human-in-the-loop
access decisions that are **not yet resolved** at evaluation time — a `PENDING`
decision.

This is an **in-root package** of the zero-dependency root module
[`github.com/SCKelemen/authzen`](../). It adds **no external dependencies**
(standard library + the root package only).

## Why an extension?

AuthZEN's `decision` is a **REQUIRED boolean** (`true` = permit, `false` =
deny; deny is fail-safe/closed — §5.5, §6.2). There is no native "pending"
value. The decision **`context`** is, however, an OPTIONAL free-form object the
spec designates as the **extension point** (§5.5.1, Figure 11).

### Design (Option B): pending == not-yet-success

We do **not** change the AuthZEN wire format. A pending approval is expressed as:

```jsonc
{
  "decision": false,            // fail-safe deny while undecided
  "context": {
    "approval": { "status": "pending", "...": "..." }
  }
}
```

On approval it becomes `decision: true` (status `approved`); on a terminal
negative outcome it stays `decision: false` with the matching status. This
mirrors how OAuth's **Device Authorization Grant** (RFC 8628) expresses
"pending" as a not-yet-success (`authorization_pending`) rather than inventing a
third decision value.

### Prior art the object shape is anchored on

| Spec | Borrowed | Section |
| --- | --- | --- |
| [RFC 8628][rfc8628] (OAuth Device Grant) | `expires_in`, `interval`, pending/denied/expired lifecycle, high-entropy handle | §3.2, §3.5, §5.2 |
| [CIBA][ciba] | `delivery` modes (poll/ping/push), out-of-band request handle | §7.1, §7.3 |
| [RFC 9396][rfc9396] (Rich Authorization Requests) | `request_ref` shape (`type`, `locations`, `actions`, `datatypes`, `identifier`, `privileges`) | §2 |

## The `approval` object

| Field | JSON | Type | Notes |
| --- | --- | --- | --- |
| Status | `status` | string | `pending` \| `approved` \| `denied` \| `expired` \| `canceled` (REQUIRED) |
| ID | `approval_id` | string | opaque high-entropy poll handle |
| ExpiresIn | `expires_in` | int (seconds) | RFC 8628 `expires_in` |
| Interval | `interval` | int (seconds) | min seconds between polls |
| PollURL | `poll_url` | string | absolute URL to poll |
| Delivery | `delivery` | []string | `poll` \| `ping` \| `push` (CIBA) |
| CallbackURL | `callback_url` | string | ping/push notification target |
| RequestRef | `request_ref` | object | what is pending approval (RFC 9396 shape) |
| Approvers | `approvers` | object | `{operator: any\|all, stage, stage_count}` |
| Grant | `grant` | object | `{expires_at}` — time-boxed grant once approved |
| DecidedBy | `decided_by` | string | principal that approved/denied |
| DecidedAt | `decided_at` | RFC 3339 | when approved/denied |
| ReasonUser | `reason_user` | object | user-facing reason(s), AuthZEN `reason_user` convention |

## State machine

```
                    Approve(by, grant)
                 ┌────────────────────────▶ approved   (decision = true)
                 │
   Create        │   Deny(by, reason)
  ─────────▶  pending ──────────────────▶ denied      (decision = false)
                 │
                 │   Cancel()
                 ├────────────────────────▶ canceled   (decision = false)
                 │
                 │   lazy: now ≥ created + expires_in
                 └────────────────────────▶ expired    (decision = false)

  pending is the ONLY non-terminal state.
  approved / denied / canceled / expired are TERMINAL and IMMUTABLE.
  An illegal transition returns ErrAlreadyResolved (or ErrExpired).
```

Expiry is **lazy**: a pending request past its deadline transitions to
`expired` the next time it is read or a transition is attempted — no background
goroutine, no timers.

## Poll flow

```
PEP                              PDP (Handler + Store)
 │   POST /access/v1/evaluation    │
 │ ───────────────────────────────▶│  policy says "needs approval"
 │                                  │  store.Create(...) -> approval_id
 │ ◀───────────────────────────────│  200 {decision:false, context:{approval:{status:pending,...}}}
 │                                  │
 │   (wait `interval` seconds)      │   <-- Retry-After header echoes interval
 │   GET /access/v1/approval/{id}   │
 │ ───────────────────────────────▶│  store.Get(id)
 │ ◀───────────────────────────────│  200 {decision:false, ...status:pending}
 │            ... repeat ...        │
 │                                  │  (human) store.Approve(id, by, grant)
 │   GET /access/v1/approval/{id}   │
 │ ───────────────────────────────▶│
 │ ◀───────────────────────────────│  200 {decision:true, ...status:approved}
```

Unknown `{id}` → `404` with an AuthZEN error object (`{status, message}`). The
poll endpoint is stdlib `net/http` only, using the Go 1.22+ pattern
`GET /access/v1/approval/{id}`.

## MCP elicitation tie-in

This extension pairs naturally with the [AuthZEN MCP profile][mcp]. When a PDP
returns a **pending** decision for an MCP tool authorization, the MCP host can
surface it as an [**elicitation**][mcp-elicit]: the user is prompted to
**accept**, **decline**, or **cancel** the pending action. Those three outcomes
map one-for-one onto the store transitions:

| MCP elicitation outcome | Store transition | Resulting decision |
| --- | --- | --- |
| accept | `Approve(id, by, grant)` | `decision: true` |
| decline | `Deny(id, by, reason)` | `decision: false` (denied) |
| cancel | `Cancel(id)` | `decision: false` (canceled) |

The PEP polls (or receives a ping/push) and re-checks the decision once the
human has acted, closing the human-in-the-loop loop.

## Callback delivery (ping / push)

The core `Store` and `Handler` are **poll-only** and never touch the network.
Push/ping callbacks are an **opt-in, separately-constructed** `Notifier` that
POSTs to a client's `callback_url` when an approval resolves, following the CIBA
delivery modes:

| `delivery` | Behavior | Body |
| --- | --- | --- |
| `poll` (or unset) | no-op — the client polls the status endpoint | — |
| `ping` | POST a minimal notification; the client then polls for the result | `{"approval_id", "status"}` |
| `push` | POST the full result | the `EvaluationResponse` (`decision` + `approval` context) |

`Notifier` is **safe by default** because it dereferences a client-supplied URL
(an SSRF surface):

- It **fails closed**: with no `Validate` function it refuses to POST anywhere.
- `Validate` is called with the parsed URL **before** any I/O; a non-nil error
  aborts the callback with no request made. `AllowList(hosts...)` is a ready-made
  validator (https-only + host allow-list).
- The default HTTP client has a bounded timeout and **does not follow
  redirects** (a redirect to an internal address would bypass the allow-list).
- `Notify` honors `context` cancellation/deadlines and treats any non-2xx
  response (including an unfollowed redirect) as an error.

**Caveats (residual SSRF, not mitigated here — caller's responsibility):**

- **Custom `HTTPClient` weakens redirect protection.** The no-redirect policy is
  set only on the default client built by `NewNotifier`. A caller who injects
  their own `*http.Client` that follows redirects loses the redirect-bounce
  protection — preserve a no-redirect `CheckRedirect` (e.g. return
  `http.ErrUseLastResponse`) on any custom client.
- **`AllowList` validates the host string, not the resolved IP.** It enforces
  https + a host allow-list but does **not** defend against DNS rebinding or an
  allow-listed host that resolves to a loopback/link-local/cloud-metadata
  address. For hardened deployments add an IP-level guard at dial time (a custom
  `DialContext`) blocking private (RFC 1918), loopback, link-local
  (`169.254.0.0/16`), and the `169.254.169.254` metadata address.

Wire it to the store's `OnResolve` hook so a resolution triggers delivery:

```go
n := approval.NewNotifier(approval.AllowList("hooks.example.com"))
store := approval.NewStore()
store.OnResolve = func(a *approval.Approval) {
    // OnResolve runs synchronously outside the store lock; dispatch async.
    go func() {
        if err := n.Notify(context.Background(), a); err != nil {
            log.Printf("approval callback failed: %v", err)
        }
    }()
}
```

`OnResolve` fires **exactly once** per approval, when it reaches a terminal
state (approve/deny/cancel, or lazy expiry observed on read).

## Example

```go
store := approval.NewStore()
mux := http.NewServeMux()
// The Handler routes the full "GET /access/v1/approval/{id}" pattern itself;
// mount it under the path prefix on an outer mux.
mux.Handle("/access/v1/approval/", approval.NewHandler(store))

// In the PDP, when policy requires human approval:
pending, _ := store.Create(approval.NewPending(&approval.RequestRef{
    Type:    "payment_initiation",
    Actions: []string{"transfer"},
}))
resp := approval.PendingResponse(pending) // decision=false + approval context

// Later, a human approves:
expiresAt := time.Now().Add(time.Hour)
store.Approve(pending.ID, "manager@example.com", &approval.Grant{
    ExpiresAt: &expiresAt, // *time.Time so an unset expiry is omitted on the wire
})
// Next poll of GET /access/v1/approval/{id} returns decision=true.
```

## Security

- **Opaque, high-entropy IDs.** `Store.Create` mints each `approval_id` from
  256 bits (`crypto/rand`) and refuses to create a request if the entropy
  source fails (RFC 8628 §5.2). The RNG is injectable only for testing; the
  default is `crypto/rand.Reader`.
- **Fail-safe deny.** Every non-approved state (pending/denied/expired/canceled)
  yields `decision: false`, so a PEP that ignores the `approval` context still
  denies.
- **Terminal states are immutable.** Illegal transitions return
  `ErrAlreadyResolved` / `ErrExpired`; expiry is enforced lazily on read.
- **Untrusted URLs (SSRF).** `poll_url` and `callback_url` are carried
  **verbatim**. The core `Store` and `Handler` **never** dereference or fetch
  them. The opt-in `Notifier` is the only component that POSTs to `callback_url`,
  and it is **safe by default**: it fails closed without a caller-supplied
  `Validate` function and its default client does not follow redirects. Supply a
  strict validator (`AllowList` enforces https + a host allow-list; also block
  loopback, link-local, and cloud-metadata addresses). Any component that later
  follows `poll_url` bears the same responsibility. Treat values obtained via
  `FromContext` as attacker-controlled.

[spec]: https://openid.net/specs/authorization-api-1_0.html
[rfc8628]: https://www.rfc-editor.org/rfc/rfc8628
[ciba]: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
[rfc9396]: https://www.rfc-editor.org/rfc/rfc9396
[mcp]: https://openid.github.io/authzen/authzen-mcp-profile-1_0.html
[mcp-elicit]: https://modelcontextprotocol.io/specification/draft/client/elicitation
