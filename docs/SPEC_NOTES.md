# OpenID AuthZEN — Authorization API 1.0 — Implementation Notes

> Engineering reference for implementing an AuthZEN-compliant Policy Decision
> Point (PDP) and/or Policy Enforcement Point (PEP). All JSON examples are
> copied **verbatim** from the specification and are suitable for use as test
> fixtures.

## Source documents

| Document | URL | Notes |
| --- | --- | --- |
| **Authorization API 1.0 — Final Specification** | https://openid.net/specs/authorization-api-1_0.html | Approved as OpenID **Final Specification** on **2026-01-12**. Authoritative. |
| Spec (GitHub Pages render) | https://openid.github.io/authzen/ | Same content, rendered from the working group repo. |
| Working group repo | https://github.com/openid/authzen | Spec source at `api/authorization-api-1_0.md`; interop harness in `interop/`. |
| Interop site | https://authzen-interop.net | "Todo" interop scenario + results. |
| MCP profile | https://openid.github.io/authzen/authzen-mcp-profile-1_0.html | Profile for MCP tool authorization (out of scope here). |

Spec lineage (for historical context — **do not implement against drafts**):
- draft 00 — Identiverse 2024 interop target.
- draft 01 — First Implementer's Draft; **evaluation endpoint only**.
- draft 02 — Adds the **evaluations** (boxcarred/batch) endpoint.
- draft 03 — Adds the **subject/resource/action search** APIs.
- **1.0 Final** — current authoritative version (this document targets it).

**Authors/editors:** Omri Gazitt (Aserto), David Brossard (Axiomatics), Atul
Tulshibagwale (SGNL). Copyright © 2026 The OpenID Foundation.

---

## 0. Roles, model, and conformance language

- **PDP** (Policy Decision Point): the service that **implements** the
  Authorization API. Serves decisions.
- **PEP** (Policy Enforcement Point): the **client** that calls the API. May
  also use Search APIs for discovery (not just enforcement).
- The API is defined **transport-agnostically**; §10 defines a **normative
  HTTPS + JSON binding** that a compliant PDP **MUST** implement. Other
  bindings (gRPC, CoAP) **MAY** be defined as profiles.
- Authentication of the API itself is **out of scope**; OAuth 2.0 (RFC 6749)
  support is **RECOMMENDED**.
- MUST / SHOULD / MAY are used per RFC 2119/8174 throughout (§-level callouts
  below).

### Information model (§5)
Entities: **Subject**, **Action**, **Resource**, **Context**, **Decision**.

---

## 1. Access Evaluation API (singular) — §6

Single decision: "Can `subject` perform `action` on `resource` (in `context`)?"

### Endpoint / transport (§10.1, Table 1)
- **Method:** `POST`
- **Default path:** `/access/v1/evaluation`
- **Metadata parameter:** `access_evaluation_endpoint` (**REQUIRED** in metadata)
- **Request `Content-Type`:** `application/json` (**MUST**)
- **Success:** HTTP `200` + `Content-Type: application/json`
- All API requests in the HTTPS binding are **POST** with a JSON object body.

### Request schema (§6.1)
Top-level object with four entities:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `subject` | Subject (§5.1) | **REQUIRED** | The principal. |
| `action` | Action (§5.3) | **REQUIRED** | The verb/operation. |
| `resource` | Resource (§5.2) | **REQUIRED** | The target. |
| `context` | Context (§5.4) | OPTIONAL | Environment / request attributes. |

#### Subject (§5.1)
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `type` | string | **REQUIRED** | Type of the subject. |
| `id` | string | **REQUIRED** | Unique id, scoped to `type`. |
| `properties` | object | OPTIONAL | Additional attributes (simple or complex values). e.g. `department`, group memberships, `device_id`, `ip_address`. |

#### Resource (§5.2)
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `type` | string | **REQUIRED** | Type of the resource. |
| `id` | string | **REQUIRED** | Unique id, scoped to `type`. |
| `properties` | object | OPTIONAL | Resource attributes/metadata; may be nested objects. |

#### Action (§5.3)
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `name` | string | **REQUIRED** | Name of the action. |
| `properties` | object | OPTIONAL | Action parameters. |

#### Context (§5.4)
- Free-form object of environment attributes (e.g. `time`, location, PEP
  capabilities, JSON Schema / JSON-LD refs). No required keys.

### Response schema (§6.2) — Decision (§5.5)
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `decision` | boolean | **REQUIRED** | `true` = allow, `false` = deny (deny is closed/fail-safe). |
| `context` | object | OPTIONAL | Reasons, advice/obligations, UI hints, step-up instructions, etc. Semantics are implementation-specific (out of scope). |

- `true` → request **permitted**. If the PEP does not understand the response
  `context`, it **MAY** reject the decision.
- `false` → request **denied** and **MUST NOT** proceed.

### Verbatim examples

**Subject — minimal (Figure 1):**
```json
{
  "type": "user",
  "id": "alice@example.com"
}
```

**Subject — with property (Figure 2):**
```json
{
  "type": "user",
  "id": "alice@example.com",
  "properties": {
    "department": "Sales"
  }
}
```

**Subject — IP + device id (Figure 3):**
```json
{
  "type": "user",
  "id": "alice@example.com",
  "properties": {
    "ip_address": "172.217.22.14",
    "device_id": "8:65:ee:17:7e:0b"
  }
}
```

**Resource — minimal (Figure 4):**
```json
{
  "type": "book",
  "id": "123"
}
```

**Resource — nested property object (Figure 5):**
```json
{
  "type": "book",
  "id": "123",
  "properties": {
    "library_record":{
      "title": "AuthZEN in Action",
      "isbn": "978-0593383322"
    }
  }
}
```

**Action — minimal (Figure 6):**
```json
{
  "name": "can_read"
}
```

**Action — with properties (Figure 7):**
```json
{
  "name": "extend-loan",
  "properties": {
    "period": "2W"
  }
}
```

**Context — minimal (Figure 8):**
```json
{
  "time": "1985-10-26T01:22-07:00"
}
```

**Context — with JSON Schema ref (Figure 9):**
```json
{
  "time": "1985-10-26T01:22-07:00",
  "schema": "https://schema.example.com/access-request.schema.json"
}
```

**Full Access Evaluation request (Figure 14):**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "resource": {
    "type": "account",
    "id": "123"
  },
  "action": {
    "name": "can_read",
    "properties": {
      "method": "GET"
    }
  },
  "context": {
    "time": "1985-10-26T01:22-07:00"
  }
}
```

**Decision — minimal allow (Figure 10):**
```json
{
  "decision": true
}
```

**Full HTTP request (Figure 28):**
```http
POST /access/v1/evaluation HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: Bearer <myoauthtoken>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "resource": {
    "type": "todo",
    "id": "1"
  },
  "action": {
    "name": "can_read"
  },
  "context": {
    "time": "1985-10-26T01:22-07:00"
  }
}
```

**Full HTTP response (Figure 29):**
```http
HTTP/1.1 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "decision": true
}
```

---

## 2. Access Evaluations API (plural / batch / "boxcarring") — §7

Evaluate **multiple** requests in a single message exchange.

### Endpoint / transport (§10.1, Table 1)
- **Method:** `POST`
- **Default path:** `/access/v1/evaluations`
- **Metadata parameter:** `access_evaluations_endpoint` (OPTIONAL in metadata —
  absence signals the PDP does not support batch)

### Request schema (§7.1)
Builds on the single Access Evaluation request object (§6.1) and adds:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `subject` | Subject | conditional | Top-level **default** for each evaluation. |
| `action` | Action | conditional | Top-level **default** for each evaluation. |
| `resource` | Resource | conditional | Top-level **default** for each evaluation. |
| `context` | Context | OPTIONAL | Top-level **default** for each evaluation. |
| `evaluations` | array of Access Evaluation request objects (§6.1) | OPTIONAL | The discrete sub-requests. |
| `options` | object | OPTIONAL | PEP-supplied execution metadata (see below). |

**Defaulting rules (§7.1.1):**
- Top-level `subject`, `action`, `resource`, `context` provide **default
  values** for every object in `evaluations`.
- A key specified **inside** an individual evaluation object **overrides** the
  top-level default.
- Because `subject`, `action`, `resource` are required for a valid evaluation,
  any of them omitted from an evaluation object **MUST** be supplied as a
  top-level key.
- Top-level `subject`/`action`/`resource` **MAY** be omitted **only if** the
  `evaluations` array is present, non-empty, and every member supplies them.
- If `evaluations` is **absent or empty**, the request behaves **identically to
  a single Access Evaluation request** (backwards compatible).

### `options` object (§7.1.2)
General-purpose execution metadata. Arbitrary additional keys allowed.

**`options.evaluations_semantic` (§7.1.2.1)** — exactly one of:

| Value | Semantic | Analogy |
| --- | --- | --- |
| `execute_all` | **Default.** Execute every request (possibly in parallel); return all results in request order. Failures denoted by `"decision": false` (+ optional reason in context). | run all |
| `deny_on_first_deny` | Short-circuit on first denial/failure; return up to and including the first deny. | `&&` |
| `permit_on_first_permit` | Short-circuit on first permit; return up to and including the first permit. | `\|\|` |

Omitting `evaluations_semantic` ⇒ `execute_all`.

### Response schema (§7.2)
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `evaluations` | array of Decision (§5.5) | present for batch | Decisions in the **same order** as the request `evaluations` array. |
| `decision` | boolean | RECOMMENDED to **omit** | When `evaluations` is present, top-level `decision` SHOULD be omitted; if present the PEP can ignore it. |

For short-circuit semantics the response array length may be shorter than the
request array (it stops at the deciding element).

### Errors in batch (§7.2.1)
Two distinct error classes:
1. **Transport-level / whole-payload errors** → HTTP 4xx/5xx (see §10.1.2).
2. **Per-evaluation errors** → handled in the payload. Decisions **default to
   closed** (`false`); the per-item `context` may carry an `error` object or a
   `reason`.

### Verbatim examples

**Three requests, no defaults (each fully specified):**
```json
{
  "evaluations": [
    {
      "subject": {
        "type": "user",
        "id": "alice@example.com"
      },
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "boxcarring.md"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    },
    {
      "subject": {
        "type": "user",
        "id": "alice@example.com"
      },
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "subject-search.md"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    },
    {
      "subject": {
        "type": "user",
        "id": "alice@example.com"
      },
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    }
  ]
}
```

**Single subject + context defaults, per-item action+resource:**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "context": {
    "time": "2024-05-31T15:22-07:00"
  },
  "evaluations": [
    {
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "boxcarring.md"
      }
    },
    {
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "subject-search.md"
      }
    },
    {
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      }
    }
  ]
}
```

**Default `action` overridden by third item:**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "context": {
    "time": "2024-05-31T15:22-07:00"
  },
  "action": {
    "name": "can_read"
  },
  "evaluations": [
    {
      "resource": {
        "type": "document",
        "id": "boxcarring.md"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "subject-search.md"
      }
    },
    {
      "action": {
        "name": "can_edit"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      }
    }
  ]
}
```

**`options` object example:**
```json
{
  "evaluations": [{
    "resource": {
      "type": "doc",
      "id": "1"
    },
    "subject": {
      "type": "doc",
      "id": "2"
    }
  }],
  "options": {
    "evaluations_semantic": "execute_all",
    "another_option": "value"
  }
}
```

**`execute_all` request:**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "read"
  },
  "options": {
    "evaluations_semantic": "execute_all"
  },
  "evaluations": [
    {
      "resource": {
        "type": "document",
        "id": "1"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "2"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "3"
      }
    }
  ]
}
```
**`execute_all` response (all three returned):**
```json
{
  "evaluations": [
    {
      "decision": true
    },
    {
      "decision": false
    },
    {
      "decision": true
    }
  ]
}
```

**`deny_on_first_deny` request:**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "read"
  },
  "options": {
    "evaluations_semantic": "deny_on_first_deny"
  },
  "evaluations": [
    {
      "resource": {
        "type": "document",
        "id": "1"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "2"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "3"
      }
    }
  ]
}
```
**`deny_on_first_deny` response (short-circuits at #2):**
```json
{
  "evaluations": [
    {
      "decision": true
    },
    {
      "decision": false,
      "context": {
        "code": "200",
        "reason": "deny_on_first_deny"
      }
    }
  ]
}
```

**`permit_on_first_permit` request:**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "read"
  },
  "options": {
    "evaluations_semantic": "permit_on_first_permit"
  },
  "evaluations": [
    {
      "resource": {
        "type": "document",
        "id": "1"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "2"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "3"
      }
    }
  ]
}
```
**`permit_on_first_permit` response (short-circuits at #1):**
```json
{
  "evaluations": [
    {
      "decision": true
    }
  ]
}
```

**Batch response with reasons (§7.2):**
```json
{
  "evaluations": [
    {
      "decision": true
    },
    {
      "decision": false,
      "context": {
        "reason": "resource not found"
      }
    },
    {
      "decision": false,
      "context": {
        "reason": "Subject is a viewer of the resource"
      }
    }
  ]
}
```

**Batch response with per-item `error` object (§7.2.1):**
```json
{
  "evaluations": [
    {
      "decision": true
    },
    {
      "decision": false,
      "context": {
        "error": {
          "status": 404,
          "message": "Resource not found"
        }
      }
    },
    {
      "decision": false,
      "context": {
        "reason": "Subject is a viewer of the resource"
      }
    }
  ]
}
```

**Full HTTP batch request (Figure 30):**
```http
POST /access/v1/evaluations HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: Bearer <myoauthtoken>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "context": {
    "time": "2024-05-31T15:22-07:00"
  },
  "action": {
    "name": "can_read"
  },
  "evaluations": [
    {
      "resource": {
        "type": "document",
        "id": "boxcarring.md"
      }
    },
    {
      "resource": {
        "type": "document",
        "id": "subject-search.md"
      }
    },
    {
      "action": {
        "name": "can_edit"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      }
    }
  ]
}
```

**Full HTTP batch response (Figure 31):**
```http
HTTP/1.1 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "evaluations": [
    {
      "decision": true
    },
    {
      "decision": false,
      "context": {
        "error": {
          "status": 404,
          "message": "Resource not found"
        }
      }
    },
    {
      "decision": false,
      "context": {
        "reason": "Subject is a viewer of the resource"
      }
    }
  ]
}
```

---

## 3. Decision response & reason/context conventions — §5.5

`decision` (boolean, REQUIRED) + `context` (object, OPTIONAL). The `context`
**format and semantics are implementation-specific and out of scope**; the spec
shows non-normative conventions. Implementations MAY use keys that map to other
standards (e.g. HTTP status codes) for interoperable reasons.

**Reasons keyed by code, split admin/user (Figure 11):**
```json
{
  "decision": false,
  "context": {
    "reason_admin": {
      "403": "Request failed policy C076E82F"
    },
    "reason_user": {
      "403": "Insufficient privileges. Contact your administrator"
    }
  }
}
```

**Metadata + environment context (Figure 12):**
```json
{
  "decision": false,
  "context": {
    "metadata": {
      "response_time": 60,
      "response_time_unit": "ms"
    },
    "environment": {
      "ip": "10.10.0.1",
      "datetime": "2025-06-27T18:03-07:00",
      "os": "ubuntu24.04.2LTS-AMDx64"
    }
  }
}
```

**Step-up authentication request (Figure 13):**
```json
{
  "decision": false,
  "context": {
    "acr_values": "urn:com:example:loa:3",
    "amr_values": "mfa hwk"
  }
}
```

> Note: `reason_admin`/`reason_user` (as maps keyed by code), `error`
> (`{status, message}`), and `reason` (string) are all **non-normative**
> conventions illustrated by the spec — not enforced fields. Design your PDP's
> context shape deliberately and document it.

---

## 4. Search APIs — §8

Discover the set of subjects, resources, or actions permitted in a context.
Construct a payload like an evaluation request but **omit the `id`/`name` of the
entity being searched for**. The PDP returns the authorized entities of that
type.

### Semantics (§8.1)
- A result, if subsequently passed to Access Evaluation, **SHOULD** yield
  `"decision": true` (not guaranteed — may depend on time, etc.).
- Searches **SHOULD** be transitive (traverse intermediate
  relationships/groups). E.g. user∈group, group=viewer(doc) ⇒ user is returned.

### Common Search response (§8.3)
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `results` | array of entities | **REQUIRED** | Zero+ entities, **only** of the searched type. |
| `page` | object (§8.2.2) | OPTIONAL | RECOMMENDED to be the **first** key; MUST be present if the response is not the complete result set. |
| `context` | object | OPTIONAL | Extra info, like the evaluation response context. |

### Pagination (§8.2) — opaque cursor tokens
**Request `page` object (§8.2.1):**
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `token` | string | OPTIONAL | Opaque value from a previous response's `next_token`. |
| `limit` | non-negative integer | OPTIONAL | Max results to return. |
| `properties` | object | OPTIONAL | Impl-specific (sorting/filtering). |

**Response `page` object (§8.2.2):**
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `next_token` | string | **REQUIRED** (when `page` present) | Opaque cursor; **empty string** ⇒ no more results (end). |
| `count` | non-negative integer | OPTIONAL | Number of results in this response. |
| `total` | non-negative integer | OPTIONAL | Total matching at request time (not guaranteed stable). |
| `properties` | object | OPTIONAL | Impl-specific (e.g. estimated totals). |

Rules:
- Initial request omits `token`. Repeat with `page.token = next_token` until
  `next_token == ""`.
- When a request carries a `token`, **all** other entities/params (`subject`,
  `resource`, `action`, `context`, `limit`, …) **MUST** be identical to the
  prior request; PDP **SHOULD** error otherwise.
- Pagination is **not** an atomic snapshot — items may repeat or be omitted if
  the data set changes mid-pagination.
- Extra `page` keys **MUST** be defined in the PDP Capabilities Registry (§12.3)
  and declared in `supported_capabilities` metadata.

### 4.1 Subject Search — §8.4
"Who can do `action` on `resource`?"
- **Default path:** `/access/v1/search/subject` · metadata `search_subject_endpoint` · POST
- Request fields: `subject` (**REQUIRED**, MUST have `type`; `id` SHOULD be
  omitted and MUST be ignored if present), `action` (**REQUIRED**), `resource`
  (**REQUIRED**), `context` (OPTIONAL), `page` (OPTIONAL).

**Request (Figure 20):**
```json
{
  "subject": {
    "type": "user"
  },
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "account",
    "id": "123"
  },
  "context": {
    "time": "2024-10-26T01:22-07:00"
  }
}
```
**Response (Figure 21):**
```json
{
  "results": [
    {
      "type": "user",
      "id": "alice@example.com"
    },
    {
      "type": "user",
      "id": "bob@example.com"
    }
  ]
}
```

### 4.2 Resource Search — §8.5
"Which resources can `subject` do `action` on?"
- **Default path:** `/access/v1/search/resource` · metadata `search_resource_endpoint` · POST
- Request fields: `subject` (**REQUIRED**), `action` (**REQUIRED**), `resource`
  (**REQUIRED**, MUST have `type`; `id` SHOULD be omitted, MUST be ignored if
  present), `context` (OPTIONAL), `page` (OPTIONAL).

**Request (Figure 22):**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "account"
  }
}
```
**Response (Figure 23):**
```json
{
  "results": [
    {
      "type": "account",
      "id": "123"
    },
    {
      "type": "account",
      "id": "456"
    }
  ]
}
```

### 4.3 Action Search — §8.6
"What actions can `subject` perform on `resource`?"
- **Default path:** `/access/v1/search/action` · metadata `search_action_endpoint` · POST
- Request fields: `subject` (**REQUIRED**), `resource` (**REQUIRED**), `context`
  (OPTIONAL), `page` (OPTIONAL). **The `action` key is omitted** from the
  request payload.

**Request (Figure 24):**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "resource": {
    "type": "account",
    "id": "123"
  },
  "context": {
    "time": "2024-10-26T01:22-07:00"
  }
}
```
**Response (Figure 25):**
```json
{
  "results": [
    {
      "name": "can_read"
    },
    {
      "name": "can_write"
    }
  ]
}
```

### Pagination examples (§8.2.3)
**Initial request, limit 2 (Figure 15):**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "account"
  },
  "page": {
    "limit": 2
  }
}
```
**Initial response — page 1 of 3 (Figure 16):**
```json
{
  "page": {
    "next_token": "a3M9NDU2O3N6PTI=",
    "count": 2,
    "total": 3
  },
  "results": [
    {
      "type": "account",
      "id": "123"
    },
    {
      "type": "account",
      "id": "456"
    }
  ]
}
```
**Second request — pass `token` (Figure 17):**
```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "account"
  },
  "page": {
    "token": "a3M9NDU2O3N6PTI="
  }
}
```
**Second response — end (`next_token: ""`) (Figure 18):**
```json
{
  "page": {
    "next_token": "",
    "count": 1,
    "total": 3
  },
  "results": [
    {
      "type": "account",
      "id": "789"
    }
  ]
}
```
**Response with `context` + partial `page` (Figure 19):**
```json
{
  "page": {
    "count": 2,
    "total": 102
  },
  "context": {
    "query_execution_time_ms": 42
  },
  "results": [
    {
      "type": "account",
      "id": "123"
    },
    {
      "type": "account",
      "id": "456"
    }
  ]
}
```

### Full HTTP search examples (§10.1.4)
**Subject Search request (Figure 32):**
```http
POST /access/v1/search/subject HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: Bearer <myoauthtoken>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "subject": {
    "type": "user"
  },
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "account",
    "id": "123"
  }
}
```
**Subject Search response (Figure 33):**
```http
HTTP/1.1 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "page": {
    "next_token": "a3M9NDU2O3N6PTI="
  },
  "results": [
    {
      "type": "user",
      "id": "alice@example.com"
    },
    {
      "type": "user",
      "id": "bob@example.com"
    }
  ]
}
```
**Resource Search request (Figure 34):**
```http
POST /access/v1/search/resource HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: Bearer <myoauthtoken>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "account"
  }
}
```
**Resource Search response (Figure 35):**
```http
HTTP/1.1 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "page": {
    "next_token": "a3M9NDU2O3N6PTI="
  },
  "results": [
    {
      "type": "account",
      "id": "123"
    },
    {
      "type": "account",
      "id": "456"
    }
  ]
}
```
**Action Search request (Figure 36):**
```http
POST /access/v1/search/action HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: Bearer <myoauthtoken>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "subject": {
    "type": "user",
    "id": "alice@example.com"
  },
  "resource": {
    "type": "account",
    "id": "123"
  },
  "context": {
    "time": "2024-10-26T01:22-07:00"
  }
}
```
**Action Search response (Figure 37):**
```http
HTTP/1.1 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "page": {
    "next_token": "a3M9NDU2O3N6PTI="
  },
  "results": [
    {
      "name": "can_read"
    },
    {
      "name": "can_write"
    }
  ]
}
```

---

## 5. Well-known metadata endpoint (PDP Metadata) — §9

PDPs **RECOMMENDED** to publish configuration metadata.

### Location (§9.2)
- Well-known URI suffix: **`authzen-configuration`** (registered, permanent).
- Full path: **`/.well-known/authzen-configuration`** (inserted between host and
  any path/query per RFC 8615).
- Multi-tenant example: `https://pdp.example.com/.well-known/authzen-configuration/tenant1`
- Retrieved via **HTTP `GET`**. Success: `200` + `Content-Type: application/json`.
- Normal HTTP caching applies; use `Cache-Control`/`max-age` (§11.9).

### Metadata fields (§9.1.1 / IANA registry §12.1.3)
| Field | Required | Description |
| --- | --- | --- |
| `policy_decision_point` | **REQUIRED** | Base URL of the PDP (https, no query/fragment). Used to prevent PDP mix-up; **MUST** equal the identifier the well-known URL was derived from (§9.2.3) — else discard. |
| `access_evaluation_endpoint` | **REQUIRED** | URL of the Access Evaluation API endpoint. |
| `access_evaluations_endpoint` | OPTIONAL | URL of the Access Evaluations (batch) endpoint. |
| `search_subject_endpoint` | OPTIONAL | URL of the Subject Search endpoint. |
| `search_resource_endpoint` | OPTIONAL | URL of the Resource Search endpoint. |
| `search_action_endpoint` | OPTIONAL | URL of the Action Search endpoint. |
| `capabilities` | OPTIONAL | JSON array of registered IANA URNs for PDP-specific capabilities (§9.1.2). |
| `signed_metadata` | OPTIONAL | A JWT (JWS-signed/MACed) asserting the above as claims; **MUST** contain `iss`; takes precedence over plain JSON if supported (§9.1.3). |

- **Absence** of an endpoint parameter ⇒ PEP treats that API as **unsupported**.
- Parameters with multiple values → JSON arrays. Parameters with no value →
  **omitted** (not `null`). Unknown params → **MUST** be ignored.

> Note: the spec text/registry lists `capabilities`. The pagination text (§8.2)
> also references a `supported_capabilities` metadata name for declaring
> capability URNs — treat the IANA-registered `capabilities` array as the
> authoritative carrier for capability URNs and cross-check against the live
> spec when implementing capability negotiation.

### Verbatim examples
**Metadata GET request (§9.2.1):**
```http
GET /.well-known/authzen-configuration HTTP/1.1
Host: pdp.example.com
```
**Metadata response (§9.2.2):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "policy_decision_point": "https://pdp.example.com",
  "access_evaluation_endpoint": "https://pdp.example.com/access/v1/evaluation",
  "search_subject_endpoint": "https://pdp.example.com/access/v1/search/subject",
  "search_resource_endpoint": "https://pdp.example.com/access/v1/search/resource"
}
```
**Multi-tenant discovery URL:**
```
https://pdp.example.com/.well-known/authzen-configuration/tenant1
```

---

## 6. Endpoint paths / URL structure — §4, §10.1 (Table 1)

- API version is **1.0**. Endpoints for v1.0 **SHOULD** include `v1` in the
  identifier, e.g. base `https://pdp.example.com/access/v1/`.
- The request URL **MUST** be the metadata endpoint value when provided;
  otherwise **SHOULD** be formed by appending the default path to the PDP base
  URL (`policy_decision_point`).

| API | Default Path | Method | Metadata Parameter | Req §| Resp § |
| --- | --- | --- | --- | --- | --- |
| Access Evaluation | `/access/v1/evaluation` | POST | `access_evaluation_endpoint` (REQUIRED) | 6.1 | 6.2 |
| Access Evaluations (batch) | `/access/v1/evaluations` | POST | `access_evaluations_endpoint` (OPTIONAL) | 7.1 | 7.2 |
| Subject Search | `/access/v1/search/subject` | POST | `search_subject_endpoint` (OPTIONAL) | 8.4.1 | 8.3 |
| Resource Search | `/access/v1/search/resource` | POST | `search_resource_endpoint` (OPTIONAL) | 8.5.1 | 8.3 |
| Action Search | `/access/v1/search/action` | POST | `search_action_endpoint` (OPTIONAL) | 8.6.1 | 8.3 |
| PDP Metadata | `/.well-known/authzen-configuration` | **GET** | n/a | 9.2.1 | 9.2.2 |

---

## 7. HTTP status codes, errors, content types — §10.1

### Transport rules (§10.1)
- All API requests (except metadata GET) are **HTTPS `POST`**.
- Request **MUST** include `Content-Type: application/json`; body **MUST** be a
  JSON object conforming to the request schema.
- Success: **`200`** + `Content-Type: application/json`, JSON-object body.

### Error status codes (§10.1.2, Table 2)
| Code | Meaning | Body |
| --- | --- | --- |
| `400` | Bad Request (e.g., missing required attribute → MUST 400) | An error message string |
| `401` | Unauthorized (auth missing/invalid) | An error message string |
| `403` | Forbidden | An error message string |
| `500` | Internal Error | An error message string |

> The error response **body content** is described as "An error message string"
> (not a structured object) for transport-level errors. **Per-evaluation**
> errors in batch are carried inside `context` (e.g. `error: {status, message}`)
> — see §7.2.1.

**Critical distinction (§10.1.2):** HTTP errors indicate request/processing
problems and are **unrelated to the authorization outcome**. A **deny** is a
**successful** request: HTTP `200` with body `{ "decision": false }`. A `401`
means the PEP failed to authenticate to the PDP (e.g., missing `Authorization`
header / invalid token).

**Auth failure (§11.3):** On missing/invalid credentials, respond `401` and
SHOULD include `WWW-Authenticate`:
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="https://as.example.com"
```

### JSON serialization (§10.1.1)
- Top-level of every request/response body **MUST** be a JSON object (RFC 8259).
- Type mapping: Object→JSON object, Array→JSON array, String→JSON string,
  Integer→JSON number, Boolean→`true`/`false`.
- Missing required attribute → **MUST** return `400`.
- Receivers **MUST** ignore unknown fields (forward compatibility).
- Implementations **MUST NOT** assume JSON member ordering.
- **SHOULD** follow I-JSON (RFC 7493): UTF-8, no unpaired surrogates, numbers
  within IEEE-754 double precision, unique member names; omit `null`-valued
  members (§11.5).

### Request identification (§10.1.3)
- Requests **MAY** carry a request id; if present, **RECOMMENDED** header
  `X-Request-ID` (arbitrary string, PEP-generated).
- If the request includes `X-Request-ID`, the PDP **MUST** echo the **same**
  identifier in the response.
```http
POST /access/v1/evaluation HTTP/1.1
Authorization: Bearer mF_9.B5f-4.1JqM
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716
```

---

## 8. Versioning, required/optional fields, conformance summary

### Versioning (§4)
- Version **1.0**. Future revisions **MAY augment** (new methods, new optional
  params, new auth mechanisms, new optional headers) but **MUST NOT modify** the
  API defined here.
- Endpoints **SHOULD** carry `v1` in their identifier.

### Required vs optional fields (quick reference)
| Context | REQUIRED | OPTIONAL |
| --- | --- | --- |
| Subject | `type`, `id` | `properties` |
| Resource | `type`, `id` | `properties` |
| Action | `name` | `properties` |
| Context | — | (any) |
| Decision | `decision` | `context` |
| Eval request | `subject`, `action`, `resource` | `context` |
| Evaluations request | `evaluations` items (each needs S/A/R via item or top-level default) | top-level `subject`/`action`/`resource`/`context`, `options` |
| Subject Search req | `subject`(type only), `action`, `resource` | `context`, `page` |
| Resource Search req | `subject`, `action`, `resource`(type only) | `context`, `page` |
| Action Search req | `subject`, `resource` (**no** `action`) | `context`, `page` |
| Search response | `results` | `page`, `context` |
| Response `page` | `next_token` | `count`, `total`, `properties` |
| Metadata | `policy_decision_point`, `access_evaluation_endpoint` | all other endpoints, `capabilities`, `signed_metadata` |

### Key MUST/SHOULD conformance points
- PDP **MUST** implement the HTTPS+JSON binding (§10).
- All API calls (except metadata) **MUST** be `POST` with
  `Content-Type: application/json` and a JSON-object body.
- Missing required attribute → **MUST** return `400` (§10.1.1).
- Receivers **MUST** ignore unknown fields; **MUST NOT** assume member ordering.
- Deny = `200` + `{ "decision": false }` — **MUST NOT** be conflated with HTTP
  4xx/5xx.
- Decisions default **closed** (`false`).
- `decision` is **REQUIRED** in a Decision; for batch, top-level `decision`
  **SHOULD** be omitted when `evaluations` is present.
- Search: searched entity's `id`/`name` **SHOULD** be omitted, and **MUST** be
  ignored if present (subject/resource search).
- Pagination: `next_token` **REQUIRED** in `page`; empty string ⇒ end; non-token
  params **MUST** stay identical across pages (PDP **SHOULD** error otherwise).
- Metadata: `policy_decision_point` **MUST** match the derivation URL else
  discard; PEP **MUST** ignore unknown metadata params; signed metadata, if
  supported, **MUST** validate and takes precedence.
- Connection PEP↔PDP **MUST** be secured (e.g. TLS) (§11.1). PDP **SHOULD**
  authenticate the PEP (mTLS / OAuth / API key — choice out of scope) (§11.2).
- Auth (RFC 6749 OAuth 2.0) support is **RECOMMENDED** (not required).
- PDP **MAY** sign authorization responses for integrity/non-repudiation (§11.6).
- PDP **SHOULD** apply DoS protections (rate limiting, payload-size/nesting
  limits) (§11.7).

---

## 9. Security considerations — §11 (digest)
- **§11.1** Integrity + confidentiality of PEP↔PDP link **MUST** be secured (TLS).
- **§11.2** PDP **SHOULD** authenticate PEP (mTLS / OAuth / API key) to mitigate
  DoS and policy-probing.
- **§11.3** `401` + `WWW-Authenticate` on auth failure.
- **§11.4** Trust model: PDP must trust PEP-supplied attribute values.
- **§11.5** I-JSON payload hygiene (see §10.1.1 above).
- **§11.6** Optional response signing (advantages beyond TLS when intermediaries
  exist).
- **§11.7** Availability / DoS protections (rate limiting).
- **§11.8** Signed vs unsigned metadata trust differences.
- **§11.9** Metadata HTTP caching.

---

## 10. IANA registries — §12 (for reference)
- New protocol registry group **"AuthZEN"** / **"AuthZEN Parameters"**.
- **AuthZEN Policy Decision Point Metadata** registry (§12.1) — seeds:
  `policy_decision_point`, `access_evaluation_endpoint`,
  `access_evaluations_endpoint`, `search_subject_endpoint`,
  `search_resource_endpoint`, `search_action_endpoint`, `capabilities`,
  `signed_metadata`.
- **Well-Known URI** `authzen-configuration` (permanent) (§12.2).
- **AuthZEN Policy Decision Point Capabilities** registry (§12.3) — capability
  names MUST begin with `:`; expressed as URNs in metadata.
- `authzen` URN sub-namespace (§12.4).

---

## 11. Implementation checklist (PDP)
1. Serve `POST /access/v1/evaluation` — single decision (`decision` bool). **Required.**
2. (Optional) `POST /access/v1/evaluations` — batch with `evaluations` array,
   top-level defaults, `options.evaluations_semantic`
   (`execute_all`/`deny_on_first_deny`/`permit_on_first_permit`).
3. (Optional) `POST /access/v1/search/{subject,resource,action}` — discovery
   with `results` + opaque-token `page` pagination.
4. Serve `GET /.well-known/authzen-configuration` advertising the endpoints you
   support (omit unsupported ones).
5. Enforce: `Content-Type: application/json`, JSON-object bodies, `400` on
   missing required fields, `401` (+`WWW-Authenticate`) on auth failure,
   `200`+`{ "decision": false }` for denies (never 403 for a policy deny),
   ignore unknown fields, echo `X-Request-ID`, TLS, rate limiting.

## 11.b Implementation checklist (PEP)
1. (Optional) Fetch `/.well-known/authzen-configuration`; validate
   `policy_decision_point`; cache per HTTP directives; choose endpoints from
   metadata (fall back to default paths).
2. Build Subject/Action/Resource/Context; POST to the evaluation endpoint;
   enforce on `decision`. Reject/handle unknown response `context` as desired.
3. Use batch endpoint to reduce round-trips; pick the appropriate
   `evaluations_semantic`.
4. For discovery use Search APIs; iterate pagination via `page.token` until
   `next_token == ""`, keeping all other params identical.
5. Send `X-Request-ID` for correlation; secure the channel; authenticate to PDP.
