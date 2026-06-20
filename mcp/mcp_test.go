package mcp

import (
	"errors"
	"reflect"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// TestMethodToAction checks the MCP method -> AuthZEN action mapping via the
// ActionFor accessor (the public API; the underlying map is unexported).
func TestMethodToAction(t *testing.T) {
	cases := []struct {
		method string
		want   string
		known  bool
	}{
		{"tools/call", "mcp.tools.call", true},
		{"tools/list", "mcp.tools.list", true},
		{"resources/read", "mcp.resources.read", true},
		{"resources/list", "mcp.resources.list", true},
		{"prompts/get", "mcp.prompts.get", true},
		{"prompts/list", "mcp.prompts.list", true},
		{"completion/complete", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			got, ok := ActionFor(tc.method)
			if ok != tc.known || got != tc.want {
				t.Fatalf("ActionFor(%q) = (%q, %v), want (%q, %v)", tc.method, got, ok, tc.want, tc.known)
			}
		})
	}
}

// TestSubjectFromToken checks the subject-type heuristic and property carriage.
func TestSubjectFromToken(t *testing.T) {
	cases := []struct {
		name      string
		claims    TokenClaims
		wantType  string
		wantID    string
		wantProps map[string]any
	}{
		{
			name:      "user with scopes",
			claims:    TokenClaims{Subject: "alice@example.com", ClientID: "cli", Scopes: []string{"mcp:tools"}, Audience: "https://mcp.example.com"},
			wantType:  SubjectTypeUser,
			wantID:    "alice@example.com",
			wantProps: map[string]any{"client_id": "cli", "scopes": []string{"mcp:tools"}, "token_audience": "https://mcp.example.com"},
		},
		{
			name:      "client credentials (no sub)",
			claims:    TokenClaims{ClientID: "svc-123", Scopes: []string{"mcp:resources"}},
			wantType:  SubjectTypeClient,
			wantID:    "svc-123",
			wantProps: map[string]any{"client_id": "svc-123", "scopes": []string{"mcp:resources"}},
		},
		{
			name:      "agent via actor claim",
			claims:    TokenClaims{Subject: "alice@example.com", Actor: "agent-7"},
			wantType:  SubjectTypeAgent,
			wantID:    "alice@example.com",
			wantProps: map[string]any{"act": "agent-7"},
		},
		{
			name:      "bare user, no props",
			claims:    TokenClaims{Subject: "bob@example.com"},
			wantType:  SubjectTypeUser,
			wantID:    "bob@example.com",
			wantProps: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SubjectFromToken(tc.claims)
			if got.Type != tc.wantType {
				t.Errorf("type = %q, want %q", got.Type, tc.wantType)
			}
			if got.ID != tc.wantID {
				t.Errorf("id = %q, want %q", got.ID, tc.wantID)
			}
			if !reflect.DeepEqual(got.Properties, tc.wantProps) {
				t.Errorf("properties = %#v, want %#v", got.Properties, tc.wantProps)
			}
		})
	}
}

// TestResourceBuilders checks the per-primitive resource builders.
func TestResourceBuilders(t *testing.T) {
	cases := []struct {
		name string
		got  *authzen.Resource
		want *authzen.Resource
	}{
		{
			name: "tool with server uri",
			got:  ToolResource("search", "https://mcp.example.com"),
			want: &authzen.Resource{Type: ResourceTypeTool, ID: "search", Properties: map[string]any{"server_uri": "https://mcp.example.com"}},
		},
		{
			name: "tool without server uri",
			got:  ToolResource("search", ""),
			want: &authzen.Resource{Type: ResourceTypeTool, ID: "search"},
		},
		{
			name: "resource",
			got:  ResourceResource("file:///etc/hosts"),
			want: &authzen.Resource{Type: ResourceTypeResource, ID: "file:///etc/hosts"},
		},
		{
			name: "prompt with extra props",
			got:  PromptResource("greeting", "https://mcp.example.com", map[string]any{"locale": "en"}),
			want: &authzen.Resource{Type: ResourceTypePrompt, ID: "greeting", Properties: map[string]any{"server_uri": "https://mcp.example.com", "locale": "en"}},
		},
		{
			name: "server",
			got:  ServerResource("https://mcp.example.com"),
			want: &authzen.Resource{Type: ResourceTypeServer, ID: "https://mcp.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Fatalf("got %#v, want %#v", tc.got, tc.want)
			}
		})
	}
}

// TestRequestEvaluationRequest checks request assembly for each primitive and
// the error paths, and that the result passes core AuthZEN validation.
func TestRequestEvaluationRequest(t *testing.T) {
	token := TokenClaims{Subject: "alice@example.com", ClientID: "cli", Scopes: []string{"mcp:tools"}, Audience: "https://mcp.example.com"}

	t.Run("tools/call", func(t *testing.T) {
		req := Request{
			Method:            "tools/call",
			ToolName:          "search",
			Arguments:         map[string]any{"q": "authzen"},
			Token:             token,
			ServerURI:         "https://mcp.example.com",
			Transport:         "http",
			ResourceIndicator: "https://mcp.example.com",
		}
		got, err := req.EvaluationRequest()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := got.Validate(); err != nil {
			t.Fatalf("assembled request failed core validation: %v", err)
		}
		if got.Action.Name != ActionToolsCall {
			t.Errorf("action = %q, want %q", got.Action.Name, ActionToolsCall)
		}
		if got.Resource.Type != ResourceTypeTool || got.Resource.ID != "search" {
			t.Errorf("resource = %#v", got.Resource)
		}
		if got.Subject.Type != SubjectTypeUser || got.Subject.ID != "alice@example.com" {
			t.Errorf("subject = %#v", got.Subject)
		}
		if !reflect.DeepEqual(got.Action.Properties, map[string]any{"arguments": map[string]any{"q": "authzen"}}) {
			t.Errorf("action properties = %#v", got.Action.Properties)
		}
		mcp, ok := got.Context["mcp"].(map[string]any)
		if !ok {
			t.Fatalf("context.mcp missing or wrong type: %#v", got.Context["mcp"])
		}
		if mcp["method"] != "tools/call" || mcp["transport"] != "http" || mcp["resource_indicator"] != "https://mcp.example.com" {
			t.Errorf("context.mcp = %#v", mcp)
		}
		tokCtx, ok := mcp["token"].(map[string]any)
		if !ok {
			t.Fatalf("context.mcp.token missing: %#v", mcp["token"])
		}
		if tokCtx["sub"] != "alice@example.com" || tokCtx["client_id"] != "cli" || tokCtx["audience"] != "https://mcp.example.com" {
			t.Errorf("context.mcp.token = %#v", tokCtx)
		}
	})

	t.Run("list maps to server resource", func(t *testing.T) {
		for _, method := range []string{"tools/list", "resources/list", "prompts/list"} {
			req := Request{Method: method, Token: token, ServerURI: "https://mcp.example.com"}
			got, err := req.EvaluationRequest()
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", method, err)
			}
			if got.Resource.Type != ResourceTypeServer || got.Resource.ID != "https://mcp.example.com" {
				t.Errorf("%s: resource = %#v", method, got.Resource)
			}
		}
	})

	t.Run("resources/read", func(t *testing.T) {
		req := Request{Method: "resources/read", ResourceURI: "file:///x", Token: token}
		got, err := req.EvaluationRequest()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Resource.Type != ResourceTypeResource || got.Resource.ID != "file:///x" {
			t.Errorf("resource = %#v", got.Resource)
		}
	})

	t.Run("prompts/get", func(t *testing.T) {
		req := Request{Method: "prompts/get", PromptName: "greeting", Token: token}
		got, err := req.EvaluationRequest()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Resource.Type != ResourceTypePrompt || got.Resource.ID != "greeting" {
			t.Errorf("resource = %#v", got.Resource)
		}
	})

	errCases := []struct {
		name string
		req  Request
		want error
	}{
		{"unknown method", Request{Method: "nope", Token: token}, ErrUnknownMethod},
		{"missing tool name", Request{Method: "tools/call", Token: token}, ErrMissingToolName},
		{"missing resource uri", Request{Method: "resources/read", Token: token}, ErrMissingResourceURI},
		{"missing prompt name", Request{Method: "prompts/get", Token: token}, ErrMissingPromptName},
		{"missing subject", Request{Method: "tools/list", Token: TokenClaims{}}, ErrMissingSubject},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.req.EvaluationRequest()
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestRequestContextMergePreservesCaller verifies that caller-supplied context
// entries survive assembly and the reserved "mcp" key is added.
func TestRequestContextMergePreservesCaller(t *testing.T) {
	req := Request{
		Method:  "tools/list",
		Token:   TokenClaims{Subject: "alice@example.com"},
		Context: authzen.Context{"time": "1985-10-26T01:22-07:00"},
	}
	got, err := req.EvaluationRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Context["time"] != "1985-10-26T01:22-07:00" {
		t.Errorf("caller context lost: %#v", got.Context)
	}
	if _, ok := got.Context["mcp"]; !ok {
		t.Errorf("reserved mcp key missing: %#v", got.Context)
	}
}
