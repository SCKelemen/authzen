package authzen

import (
	"encoding/json"
	"testing"
)

// TestEvaluationsRequestRoundTrip exercises Access Evaluations (batch) requests,
// including top-level defaults, per-item overrides, and the options object.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1 (Access Evaluations
// Request), Section 7.1.2 (options), Figures 30 and related examples.
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-request
func TestEvaluationsRequestRoundTrip(t *testing.T) {
	cases := map[string]string{
		"three fully specified, no defaults": `{
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
    }
  ]
}`,
		"subject + context defaults": `{
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
    }
  ]
}`,
		"default action overridden (Figure 30 body)": `{
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
}`,
		"options with extra key": `{
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
}`,
		"execute_all request": `{
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
    }
  ]
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[EvaluationsRequest](t, fixture) })
	}
}

// TestEvaluationsResponseRoundTrip exercises batch responses, including the
// execute_all and short-circuit forms and per-item reason/error contexts.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2 (Access Evaluations
// Response) and Section 7.2.1, Figure 31 and related examples.
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-response
func TestEvaluationsResponseRoundTrip(t *testing.T) {
	cases := map[string]string{
		"execute_all response": `{
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
}`,
		"deny_on_first_deny response": `{
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
}`,
		"permit_on_first_permit response": `{
  "evaluations": [
    {
      "decision": true
    }
  ]
}`,
		"per-item error object (Figure 31)": `{
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
}`,
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) { roundTrip[EvaluationsResponse](t, fixture) })
	}
}

// TestResolvedDefaulting verifies the defaulting rules: a member inherits the
// top-level subject/action/resource/context unless it specifies its own, and a
// member value overrides the default.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.1 (Defaulting rules).
// https://openid.net/specs/authorization-api-1_0.html
func TestResolvedDefaulting(t *testing.T) {
	const fixture = `{
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
      "action": {
        "name": "can_edit"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      }
    }
  ]
}`
	var req EvaluationsRequest
	if err := json.Unmarshal([]byte(fixture), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resolved := req.Resolved()
	if len(resolved) != 2 {
		t.Fatalf("Resolved() length = %d, want 2", len(resolved))
	}

	// Item 0 inherits the top-level subject, action, and context.
	r0 := resolved[0]
	if r0.Subject == nil || r0.Subject.ID != "alice@example.com" {
		t.Errorf("item 0 subject = %+v, want inherited alice", r0.Subject)
	}
	if r0.Action == nil || r0.Action.Name != "can_read" {
		t.Errorf("item 0 action = %+v, want inherited can_read", r0.Action)
	}
	if r0.Context["time"] != "2024-05-31T15:22-07:00" {
		t.Errorf("item 0 context = %+v, want inherited time", r0.Context)
	}
	if r0.Resource == nil || r0.Resource.ID != "boxcarring.md" {
		t.Errorf("item 0 resource = %+v, want own boxcarring.md", r0.Resource)
	}

	// Item 1 overrides the action while still inheriting subject/context.
	r1 := resolved[1]
	if r1.Action == nil || r1.Action.Name != "can_edit" {
		t.Errorf("item 1 action = %+v, want overridden can_edit", r1.Action)
	}
	if r1.Subject == nil || r1.Subject.ID != "alice@example.com" {
		t.Errorf("item 1 subject = %+v, want inherited alice", r1.Subject)
	}

	if err := req.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// TestResolvedEmptyBehavesAsSingle verifies that an empty evaluations array
// makes the request behave like a single Access Evaluation request built from
// the top-level fields.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.1 (Defaulting rules).
// https://openid.net/specs/authorization-api-1_0.html
func TestResolvedEmptyBehavesAsSingle(t *testing.T) {
	req := EvaluationsRequest{
		Subject:  &Subject{Type: "user", ID: "alice@example.com"},
		Action:   &Action{Name: "can_read"},
		Resource: &Resource{Type: "document", ID: "1"},
	}
	resolved := req.Resolved()
	if len(resolved) != 1 {
		t.Fatalf("Resolved() length = %d, want 1", len(resolved))
	}
	if err := resolved[0].Validate(); err != nil {
		t.Errorf("single resolved request invalid: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// TestOptionsSemanticConstants verifies the three defined semantic values
// serialize to their exact spec strings.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.1.2.1 (evaluations_semantic).
// https://openid.net/specs/authorization-api-1_0.html
func TestOptionsSemanticConstants(t *testing.T) {
	want := map[EvaluationsSemantic]string{
		SemanticExecuteAll:          "execute_all",
		SemanticDenyOnFirstDeny:     "deny_on_first_deny",
		SemanticPermitOnFirstPermit: "permit_on_first_permit",
	}
	for sem, str := range want {
		if string(sem) != str {
			t.Errorf("semantic %q = %q, want %q", sem, string(sem), str)
		}
	}
}
