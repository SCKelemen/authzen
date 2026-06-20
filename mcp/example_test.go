package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/mcp"
)

// ExampleRequest_EvaluationRequest shows how an MCP server (acting as an AuthZEN
// PEP) turns an authenticated tools/call into an authzen.EvaluationRequest to
// send to a PDP. The marshaled JSON shows the on-the-wire mapping, including the
// reserved context.mcp object.
func ExampleRequest_EvaluationRequest() {
	req := mcp.Request{
		Method:            "tools/call",
		ToolName:          "search",
		ServerURI:         "https://mcp.example.com",
		Transport:         "http",
		ResourceIndicator: "https://mcp.example.com",
		Token: mcp.TokenClaims{
			Subject: "alice@example.com",
			Scopes:  []string{"mcp:tools"},
		},
	}

	eval, err := req.EvaluationRequest()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	out, _ := json.MarshalIndent(eval, "", "  ")
	fmt.Println(string(out))
	// Output:
	// {
	//   "subject": {
	//     "type": "user",
	//     "id": "alice@example.com",
	//     "properties": {
	//       "scopes": [
	//         "mcp:tools"
	//       ]
	//     }
	//   },
	//   "action": {
	//     "name": "mcp.tools.call"
	//   },
	//   "resource": {
	//     "type": "mcp_tool",
	//     "id": "search",
	//     "properties": {
	//       "server_uri": "https://mcp.example.com"
	//     }
	//   },
	//   "context": {
	//     "mcp": {
	//       "method": "tools/call",
	//       "resource_indicator": "https://mcp.example.com",
	//       "token": {
	//         "scopes": [
	//           "mcp:tools"
	//         ],
	//         "sub": "alice@example.com"
	//       },
	//       "transport": "http"
	//     }
	//   }
	// }
}

// ExampleChallenge_String shows the WWW-Authenticate header value an MCP server
// returns for an insufficient-scope denial.
func ExampleChallenge_String() {
	ch := mcp.InsufficientScope("mcp:tools", "https://api.example.com/.well-known/oauth-protected-resource")
	fmt.Println(ch.String())
	// Output:
	// Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
}

// ExampleParseChallenge shows a client decoding a server's WWW-Authenticate
// challenge to drive OAuth discovery.
func ExampleParseChallenge() {
	ch, err := mcp.ParseChallenge(`Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://api.example.com/prm"`)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(ch.Error)
	fmt.Println(ch.Scope)
	fmt.Println(ch.ResourceMetadata)
	// Output:
	// insufficient_scope
	// mcp:tools
	// https://api.example.com/prm
}

// ExampleEnforcer_Handler shows the middleware enforcing a deny: the wrapped
// handler is never reached, and the client receives a 403 with an OAuth
// WWW-Authenticate challenge and a JSON error body.
func ExampleEnforcer_Handler() {
	// A PDP stand-in that denies with a profile deny context.
	authorizer := mcp.AuthorizerFunc(func(context.Context, authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
		return authzen.EvaluationResponse{
			Decision: false,
			Context:  mcp.DenyContext(mcp.InsufficientScope("mcp:tools", "https://api.example.com/prm")),
		}, nil
	})

	// The caller-supplied extractor (token parsing is deployment-specific).
	extract := func(*http.Request) (mcp.Request, error) {
		return mcp.Request{
			Method:   "tools/call",
			ToolName: "search",
			Token:    mcp.TokenClaims{Subject: "alice@example.com"},
		}, nil
	}

	enforcer := mcp.New(authorizer, extract)
	handler := enforcer.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // never reached on deny
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))

	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("WWW-Authenticate"))
	fmt.Print(rec.Body.String())
	// Output:
	// 403
	// Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://api.example.com/prm"
	// {"error":"insufficient_scope"}
}
