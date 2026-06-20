# Vendored AuthZEN interop test vectors

These files are an **unmodified copy** of the OFFICIAL OpenID AuthZEN Working
Group interop material, vendored so the conformance harness in `interop/` can
run fully offline (CI-safe). They are test fixtures only; they are not part of
the library.

## Source repository

- Repo: <https://github.com/openid/authzen>
- Pinned commit: `93ff568d5ce2ad2a86858e4b90847e26ceb5347a`
- Vendored on: 2026-06-20

## Files

### Todo application — Access Evaluation / Access Evaluations vectors

The Todo scenario is the canonical AuthZEN interop scenario (a shared todo list
with role-based access). See
<https://authzen-interop.net/docs/scenarios/todo-1.0-id/> and the test harness
at `interop/authzen-todo-backend/test`.

| Vendored path | Upstream path |
| --- | --- |
| `todo/decisions-authorization-api-1_0-00.json` | `interop/authzen-todo-backend/test/decisions-authorization-api-1_0-00.json` |
| `todo/decisions-authorization-api-1_0-01.json` | `interop/authzen-todo-backend/test/decisions-authorization-api-1_0-01.json` |
| `todo/decisions-authorization-api-1_0-02.json` | `interop/authzen-todo-backend/test/decisions-authorization-api-1_0-02.json` |

Raw URL pattern (pinned):
`https://raw.githubusercontent.com/openid/authzen/93ff568d5ce2ad2a86858e4b90847e26ceb5347a/interop/authzen-todo-backend/test/<file>`

Shape:

```jsonc
{
  "evaluation": [
    { "request": { "subject": {...}, "action": {...}, "resource": {...} },
      "expected": true }
  ],
  "evaluations": [   // only present in the -02 (draft 02 / batch) file
    { "request": { "subject": {...}, "action": {...},
                   "evaluations": [ { "resource": {...} } ] },
      "expected": [ { "decision": true }, { "decision": false } ] }
  ]
}
```

Notes on the three spec variations:

- `-02` is the AuthZEN 1.0-aligned format (clean `subject`/`action`/`resource`,
  with extra attributes nested under `properties`). It also adds the batch
  `evaluations` array. This is the file used for STRICT wire round-trip
  conformance.
- `-01` is mostly 1.0-aligned but some `subject` objects carry a `_note`
  annotation key used as an inline comment in the fixture.
- `-00` is the pre-1.0 draft format: some `subject`/`resource` objects carry
  attributes (`identity`, `userID`) as *top-level siblings* of `type`/`id`
  rather than under `properties`.

### Search demo — Subject / Resource / Action Search vectors

The Search scenario (<https://authzen-interop.net/docs/category/results-4>) lists
authorized subjects, resources, and actions. Harness at
`interop/authzen-search-demo/test-harness/src`.

| Vendored path | Upstream path |
| --- | --- |
| `search/subject-results.json` | `interop/authzen-search-demo/test-harness/src/subject/results.json` |
| `search/resource-results.json` | `interop/authzen-search-demo/test-harness/src/resource/results.json` |
| `search/action-results.json` | `interop/authzen-search-demo/test-harness/src/action/results.json` |

Shape:

```jsonc
{
  "evaluation": [
    { "request":  { "subject": {...}, "action": {...}, "resource": {...} },
      "expected": { "results": [ { "type": "user", "id": "alice" } ] } }
  ]
}
```

Per AuthZEN 1.0 Section 8:

- Subject Search request omits `subject.id` (only `subject.type`).
- Action Search request omits the `action` key entirely.
- Resource Search request omits `resource.id` (only `resource.type`).

## Related interop resources (not vendored)

- Hosted PEP backend: <https://todo-backend.authzen-interop.net>
- Hosted PDP list: `interop/authzen-todo-backend/src/pdps.json`
- Certification scenario draft: <https://github.com/openid/authzen/issues/433>
- Spec: <https://openid.net/specs/authorization-api-1_0.html>
