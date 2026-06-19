package authzen

import (
	"encoding/json"
	"testing"
)

// TestSubjectSearchRoundTrip exercises Subject Search request/response shapes.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.4 (Subject Search), Figures
// 20-21 and 32-33.
// https://openid.net/specs/authorization-api-1_0.html
func TestSubjectSearchRoundTrip(t *testing.T) {
	t.Run("request (Figure 20)", func(t *testing.T) {
		roundTrip[SubjectSearchRequest](t, `{
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
}`)
	})
	t.Run("response (Figure 21)", func(t *testing.T) {
		roundTrip[SubjectSearchResponse](t, `{
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
}`)
	})
	t.Run("response with page (Figure 33)", func(t *testing.T) {
		roundTrip[SubjectSearchResponse](t, `{
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
}`)
	})
}

// TestResourceSearchRoundTrip exercises Resource Search request/response shapes.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.5 (Resource Search), Figures
// 22-23 and 34-35.
// https://openid.net/specs/authorization-api-1_0.html
func TestResourceSearchRoundTrip(t *testing.T) {
	t.Run("request (Figure 22)", func(t *testing.T) {
		roundTrip[ResourceSearchRequest](t, `{
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
}`)
	})
	t.Run("response (Figure 23)", func(t *testing.T) {
		roundTrip[ResourceSearchResponse](t, `{
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
}`)
	})
}

// TestActionSearchRoundTrip exercises Action Search request/response shapes. The
// request intentionally omits the action key.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.6 (Action Search), Figures
// 24-25 and 36-37.
// https://openid.net/specs/authorization-api-1_0.html
func TestActionSearchRoundTrip(t *testing.T) {
	t.Run("request (Figure 24)", func(t *testing.T) {
		roundTrip[ActionSearchRequest](t, `{
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
}`)
	})
	t.Run("response (Figure 25)", func(t *testing.T) {
		roundTrip[ActionSearchResponse](t, `{
  "results": [
    {
      "name": "can_read"
    },
    {
      "name": "can_write"
    }
  ]
}`)
	})
}

// TestPaginationRoundTrip exercises the request and response page objects used
// across the Search APIs.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.2 (Pagination), Figures 15-18.
// https://openid.net/specs/authorization-api-1_0.html
func TestPaginationRoundTrip(t *testing.T) {
	t.Run("initial request limit 2 (Figure 15)", func(t *testing.T) {
		roundTrip[ResourceSearchRequest](t, `{
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
}`)
	})
	t.Run("first response page 1 of 3 (Figure 16)", func(t *testing.T) {
		roundTrip[ResourceSearchResponse](t, `{
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
}`)
	})
	t.Run("second request with token (Figure 17)", func(t *testing.T) {
		roundTrip[ResourceSearchRequest](t, `{
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
}`)
	})
	t.Run("end response next_token empty (Figure 18)", func(t *testing.T) {
		roundTrip[ResourceSearchResponse](t, `{
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
}`)
	})
}

// TestEndOfResultsSentinel verifies that an empty next_token is preserved on the
// wire so that PEPs can detect the end of pagination.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.2.2 (Response page object).
// https://openid.net/specs/authorization-api-1_0.html
func TestEndOfResultsSentinel(t *testing.T) {
	resp := ResourceSearchResponse{
		Page:    &PageResponse{NextToken: "", Count: 1, Total: 3},
		Results: []Resource{{Type: "account", ID: "789"}},
	}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	page, ok := generic["page"].(map[string]any)
	if !ok {
		t.Fatalf("page missing in %s", out)
	}
	if nt, ok := page["next_token"]; !ok || nt != "" {
		t.Errorf("next_token = %v (present=%v), want empty string present", nt, ok)
	}
}

// TestSearchResponseContextUnmarshal verifies that a partial page accompanied by
// a context object parses correctly (Figure 19). The spec example omits
// next_token, so this is an unmarshal-only assertion rather than a strict
// round-trip.
//
// OpenID AuthZEN Authorization API 1.0, Section 8.3 (Search response), Figure 19.
// https://openid.net/specs/authorization-api-1_0.html
func TestSearchResponseContextUnmarshal(t *testing.T) {
	const fixture = `{
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
}`
	var resp ResourceSearchResponse
	if err := json.Unmarshal([]byte(fixture), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Page == nil || resp.Page.Count != 2 || resp.Page.Total != 102 {
		t.Errorf("page = %+v, want count=2 total=102", resp.Page)
	}
	if resp.Context["query_execution_time_ms"] != float64(42) {
		t.Errorf("context = %+v, want query_execution_time_ms=42", resp.Context)
	}
	if len(resp.Results) != 2 {
		t.Errorf("results length = %d, want 2", len(resp.Results))
	}
}
