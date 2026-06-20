package mcp

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	authzen "github.com/SCKelemen/authzen"
)

// assertJSON marshals got, then compares it (decoded back into a generic value)
// against the decoded wantJSON. Both sides pass through encoding/json so the
// comparison is over the literal on-the-wire field names and structure, not Go
// types (for example []string and []any compare equal after a round trip).
func assertJSON(t *testing.T, got any, wantJSON string) {
	t.Helper()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var gotVal, wantVal any
	if err := json.Unmarshal(raw, &gotVal); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal([]byte(wantJSON), &wantVal); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	if !reflect.DeepEqual(gotVal, wantVal) {
		t.Fatalf("JSON mismatch:\n got:  %s\n want: %s", raw, wantJSON)
	}
}

// TestEvaluationRequestJSONWire asserts the literal JSON shape produced by an
// assembled EvaluationRequest, matching the field names of the AuthZEN
// information model and the profile's reserved context.mcp object.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.1 (Access Evaluation Request)
// and Section 5 (Subject/Action/Resource/Context).
// https://openid.net/specs/authorization-api-1_0.html
func TestEvaluationRequestJSONWire(t *testing.T) {
	req := Request{
		Method:            "tools/call",
		ToolName:          "search",
		Arguments:         map[string]any{"q": "authzen"},
		ServerURI:         "https://mcp.example.com",
		Transport:         "http",
		ResourceIndicator: "https://mcp.example.com",
		Token: TokenClaims{
			Subject:  "alice@example.com",
			ClientID: "ide-client",
			Scopes:   []string{"mcp:tools"},
			Audience: "https://mcp.example.com",
		},
	}
	eval, err := req.EvaluationRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const want = `{
      "subject": {
        "type": "user",
        "id": "alice@example.com",
        "properties": {
          "client_id": "ide-client",
          "scopes": ["mcp:tools"],
          "token_audience": "https://mcp.example.com"
        }
      },
      "action": {
        "name": "mcp.tools.call",
        "properties": { "arguments": { "q": "authzen" } }
      },
      "resource": {
        "type": "mcp_tool",
        "id": "search",
        "properties": { "server_uri": "https://mcp.example.com" }
      },
      "context": {
        "mcp": {
          "method": "tools/call",
          "transport": "http",
          "resource_indicator": "https://mcp.example.com",
          "token": {
            "sub": "alice@example.com",
            "client_id": "ide-client",
            "scopes": ["mcp:tools"],
            "audience": "https://mcp.example.com"
          }
        }
      }
    }`
	assertJSON(t, eval, want)
}

// TestToolsCallArgumentsOptional checks that tools/call with no Arguments omits
// action.properties entirely, while populated Arguments are carried.
func TestToolsCallArgumentsOptional(t *testing.T) {
	token := TokenClaims{Subject: "alice@example.com"}

	t.Run("empty arguments -> no action properties", func(t *testing.T) {
		eval, err := Request{Method: "tools/call", ToolName: "search", Token: token}.EvaluationRequest()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if eval.Action.Properties != nil {
			t.Errorf("action.properties = %#v, want nil", eval.Action.Properties)
		}
	})

	t.Run("populated arguments -> action properties", func(t *testing.T) {
		eval, err := Request{Method: "tools/call", ToolName: "search", Arguments: map[string]any{"q": "x"}, Token: token}.EvaluationRequest()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[string]any{"arguments": map[string]any{"q": "x"}}
		if !reflect.DeepEqual(eval.Action.Properties, want) {
			t.Errorf("action.properties = %#v, want %#v", eval.Action.Properties, want)
		}
	})
}

// TestAgentEmptySubjectRejected exercises the documented delegation edge: a
// token with an actor (and client id) but no subject yields type="agent" with
// an empty id, which fails core validation with ErrMissingSubject because
// delegation still requires a principal subject to act on behalf of.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.1 (Subject, id REQUIRED).
// https://openid.net/specs/authorization-api-1_0.html
func TestAgentEmptySubjectRejected(t *testing.T) {
	claims := TokenClaims{Actor: "agent-7", ClientID: "cli"}

	subj := SubjectFromToken(claims)
	if subj.Type != SubjectTypeAgent {
		t.Errorf("type = %q, want %q", subj.Type, SubjectTypeAgent)
	}
	if subj.ID != "" {
		t.Errorf("id = %q, want empty", subj.ID)
	}

	_, err := Request{Method: "tools/list", Token: claims, ServerURI: "https://mcp.example.com"}.EvaluationRequest()
	if !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("err = %v, want ErrMissingSubject", err)
	}
}

// TestConfusedDeputyAudienceCarried is a security regression: when the token's
// audience differs from the request's resource indicator, the profile MUST
// carry both values distinctly in context.mcp so a PDP can compare them and
// reject a token replayed at the wrong resource (a confused-deputy / token
// audience-confusion attack). The profile must not silently drop or merge them.
//
// RFC 8707 - Resource Indicators for OAuth 2.0 (audience binding).
// https://www.rfc-editor.org/rfc/rfc8707
func TestConfusedDeputyAudienceCarried(t *testing.T) {
	const (
		tokenAud  = "https://other.example.com"
		indicator = "https://mcp.example.com"
	)
	eval, err := Request{
		Method:            "tools/call",
		ToolName:          "search",
		ServerURI:         indicator,
		ResourceIndicator: indicator,
		Token:             TokenClaims{Subject: "alice@example.com", Audience: tokenAud},
	}.EvaluationRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mcp, ok := eval.Context["mcp"].(map[string]any)
	if !ok {
		t.Fatalf("context.mcp missing: %#v", eval.Context["mcp"])
	}
	if mcp["resource_indicator"] != indicator {
		t.Errorf("resource_indicator = %#v, want %q", mcp["resource_indicator"], indicator)
	}
	tok, ok := mcp["token"].(map[string]any)
	if !ok {
		t.Fatalf("context.mcp.token missing: %#v", mcp["token"])
	}
	if tok["audience"] != tokenAud {
		t.Errorf("token.audience = %#v, want %q", tok["audience"], tokenAud)
	}
	// Both must be present and distinct so the PDP can detect the mismatch.
	if tok["audience"] == mcp["resource_indicator"] {
		t.Fatalf("audience and resource_indicator were merged/equal: %v", tok["audience"])
	}

	// The subject property token_audience must likewise preserve the token's
	// own audience, independent of the resource indicator.
	if got := eval.Subject.Properties["token_audience"]; got != tokenAud {
		t.Errorf("subject.token_audience = %#v, want %q", got, tokenAud)
	}
}

// compile-time guard: assertJSON is exercised against the core response type
// too, ensuring DenyContext embeds cleanly in an EvaluationResponse.
var _ = authzen.EvaluationResponse{}
