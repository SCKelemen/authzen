package mcp

import (
	"errors"

	authzen "github.com/SCKelemen/authzen"
)

// MCP resource types. Each MCP primitive that can be authorized is mapped to a
// distinct AuthZEN resource type so that a policy can be written per primitive
// class (a tool is a different kind of object than a prompt or a raw resource).
//
// MCP Authorization (2025-06-18), Server Primitives.
// https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
const (
	// ResourceTypeTool is an MCP tool, the target of tools/call and the element
	// type listed by tools/list.
	ResourceTypeTool = "mcp_tool"
	// ResourceTypeResource is an MCP resource, the target of resources/read and
	// the element type listed by resources/list.
	ResourceTypeResource = "mcp_resource"
	// ResourceTypePrompt is an MCP prompt, the target of prompts/get and the
	// element type listed by prompts/list.
	ResourceTypePrompt = "mcp_prompt"
	// ResourceTypeServer is the MCP server (or session) itself, used as the
	// resource for collection-level operations such as tools/list.
	ResourceTypeServer = "mcp_server"
)

// AuthZEN action names for the MCP JSON-RPC methods. The dotted form mirrors the
// MCP method name (for example tools/call -> mcp.tools.call) so that the action
// is stable, namespaced, and unambiguous in a policy.
//
// MCP Authorization (2025-06-18).
// https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
const (
	// ActionToolsCall is the action for the tools/call method.
	ActionToolsCall = "mcp.tools.call"
	// ActionToolsList is the action for the tools/list method.
	ActionToolsList = "mcp.tools.list"
	// ActionResourcesRead is the action for the resources/read method.
	ActionResourcesRead = "mcp.resources.read"
	// ActionResourcesList is the action for the resources/list method.
	ActionResourcesList = "mcp.resources.list"
	// ActionPromptsGet is the action for the prompts/get method.
	ActionPromptsGet = "mcp.prompts.get"
	// ActionPromptsList is the action for the prompts/list method.
	ActionPromptsList = "mcp.prompts.list"
)

// methodToAction maps an MCP JSON-RPC method name to its AuthZEN action name.
// It is the canonical source for the action mapping and is read on the
// authorization hot path; it is kept unexported (read-only) and accessed
// through the ActionFor accessor so it cannot be mutated by callers.
//
// MCP Authorization (2025-06-18).
// https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
var methodToAction = map[string]string{
	"tools/call":     ActionToolsCall,
	"tools/list":     ActionToolsList,
	"resources/read": ActionResourcesRead,
	"resources/list": ActionResourcesList,
	"prompts/get":    ActionPromptsGet,
	"prompts/list":   ActionPromptsList,
}

// AuthZEN subject types produced by SubjectFromToken. The choice of type lets a
// policy distinguish a human end user from a confidential client acting under
// the client-credentials grant, and from an agent acting on behalf of a user
// (token delegation).
//
// OpenID AuthZEN Authorization API 1.0, Section 5.1 (Subject).
// https://openid.net/specs/authorization-api-1_0.html
const (
	// SubjectTypeUser is a human end user (the token carries a subject claim).
	SubjectTypeUser = "user"
	// SubjectTypeClient is a confidential client with no end user (the token
	// carries only a client identifier, e.g. the client-credentials grant).
	SubjectTypeClient = "client"
	// SubjectTypeAgent is an actor acting on behalf of a subject (the token
	// carries a delegation/actor claim).
	SubjectTypeAgent = "agent"
)

// Package errors returned by Request.EvaluationRequest. Callers can test for
// them with errors.Is.
var (
	// ErrUnknownMethod indicates the request method has no mapped AuthZEN
	// action (see ActionFor).
	ErrUnknownMethod = errors.New("mcp: unknown MCP method")
	// ErrMissingToolName indicates a tools/call request did not name a tool.
	ErrMissingToolName = errors.New("mcp: tools/call requires a tool name")
	// ErrMissingResourceURI indicates a resources/read request did not name a
	// resource URI.
	ErrMissingResourceURI = errors.New("mcp: resources/read requires a resource uri")
	// ErrMissingPromptName indicates a prompts/get request did not name a
	// prompt.
	ErrMissingPromptName = errors.New("mcp: prompts/get requires a prompt name")
	// ErrMissingSubject indicates the token carried neither a subject nor a
	// client identifier, so no AuthZEN subject id could be derived.
	ErrMissingSubject = errors.New("mcp: token has neither subject nor client_id")
)

// ActionFor returns the AuthZEN action name mapped to an MCP JSON-RPC method,
// and whether the method is known.
//
// MCP Authorization (2025-06-18).
// https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
func ActionFor(method string) (string, bool) {
	a, ok := methodToAction[method]
	return a, ok
}

// TokenClaims is the subset of OAuth 2.1 / JWT access-token claims this profile
// maps onto an AuthZEN subject and context. It is supplied by the caller after
// the bearer token has already been authenticated; this package does not parse
// or verify tokens.
//
// RFC 6750 - Bearer Token Usage. https://www.rfc-editor.org/rfc/rfc6750
// RFC 8707 - Resource Indicators for OAuth 2.0 (audience binding).
// https://www.rfc-editor.org/rfc/rfc8707
type TokenClaims struct {
	// Subject is the authenticated end user identifier (the "sub" claim).
	Subject string
	// ClientID is the OAuth client identifier (the "client_id" claim).
	ClientID string
	// Scopes are the granted OAuth scopes (the space-delimited "scope" claim,
	// split into items).
	Scopes []string
	// Audience is the resource indicator the token is bound to (the "aud"
	// claim), per RFC 8707.
	Audience string
	// Actor is the delegated actor identifier (the "act.sub" claim) when the
	// token represents an agent acting on behalf of Subject.
	Actor string
}

// SubjectFromToken derives an AuthZEN subject from authenticated token claims.
// The subject type is chosen heuristically: an actor (delegation) claim yields
// an agent; a token with a client id but no subject yields a client; otherwise
// the subject is a user. The subject id is the end-user subject when present,
// falling back to the client id. The remaining claims (client_id, scopes,
// actor, and audience) are carried as subject properties so a policy can reason
// over them.
//
// A token carrying an actor (delegation) claim but an empty subject yields
// type="agent" with an empty id; that subject fails core AuthZEN validation
// (Request.EvaluationRequest returns ErrMissingSubject), because delegation
// still requires a principal subject to act on behalf of.
//
// OpenID AuthZEN Authorization API 1.0, Section 5.1 (Subject).
// https://openid.net/specs/authorization-api-1_0.html
func SubjectFromToken(claims TokenClaims) *authzen.Subject {
	typ := SubjectTypeUser
	id := claims.Subject
	switch {
	case claims.Actor != "":
		typ = SubjectTypeAgent
	case claims.Subject == "" && claims.ClientID != "":
		typ = SubjectTypeClient
		id = claims.ClientID
	}

	props := map[string]any{}
	if claims.ClientID != "" {
		props["client_id"] = claims.ClientID
	}
	if len(claims.Scopes) > 0 {
		props["scopes"] = claims.Scopes
	}
	if claims.Actor != "" {
		props["act"] = claims.Actor
	}
	if claims.Audience != "" {
		props["token_audience"] = claims.Audience
	}
	if len(props) == 0 {
		props = nil
	}

	return &authzen.Subject{Type: typ, ID: id, Properties: props}
}

// ToolResource builds the AuthZEN resource for an MCP tool. The tool name is the
// resource id and the owning server URI (when given) is carried as a property.
// Additional properties may be supplied and are merged last.
func ToolResource(name, serverURI string, properties ...map[string]any) *authzen.Resource {
	props := map[string]any{}
	if serverURI != "" {
		props["server_uri"] = serverURI
	}
	return &authzen.Resource{
		Type:       ResourceTypeTool,
		ID:         name,
		Properties: mergeProps(props, properties...),
	}
}

// ResourceResource builds the AuthZEN resource for an MCP resource. The resource
// URI is the resource id. Additional properties may be supplied and are merged
// last.
func ResourceResource(uri string, properties ...map[string]any) *authzen.Resource {
	return &authzen.Resource{
		Type:       ResourceTypeResource,
		ID:         uri,
		Properties: mergeProps(map[string]any{}, properties...),
	}
}

// PromptResource builds the AuthZEN resource for an MCP prompt. The prompt name
// is the resource id and the owning server URI (when given) is carried as a
// property. Additional properties may be supplied and are merged last.
func PromptResource(name, serverURI string, properties ...map[string]any) *authzen.Resource {
	props := map[string]any{}
	if serverURI != "" {
		props["server_uri"] = serverURI
	}
	return &authzen.Resource{
		Type:       ResourceTypePrompt,
		ID:         name,
		Properties: mergeProps(props, properties...),
	}
}

// ServerResource builds the AuthZEN resource for the MCP server/session itself,
// used for collection-level operations (tools/list, resources/list,
// prompts/list). The server URI is the resource id. Additional properties may
// be supplied and are merged last.
func ServerResource(uri string, properties ...map[string]any) *authzen.Resource {
	return &authzen.Resource{
		Type:       ResourceTypeServer,
		ID:         uri,
		Properties: mergeProps(map[string]any{}, properties...),
	}
}

// mergeProps merges the extra property maps into base (later maps win) and
// returns base, or nil when the result is empty so that the encoded resource
// omits an empty properties object.
func mergeProps(base map[string]any, extra ...map[string]any) map[string]any {
	for _, m := range extra {
		for k, v := range m {
			base[k] = v
		}
	}
	if len(base) == 0 {
		return nil
	}
	return base
}

// Request is the high-level description of an MCP call to authorize. It bundles
// the JSON-RPC method, the targeted primitive's identifier, any call arguments,
// the authenticated token claims, and transport metadata. EvaluationRequest
// assembles these into an authzen.EvaluationRequest.
//
// MCP Authorization (2025-06-18).
// https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
type Request struct {
	// Method is the MCP JSON-RPC method (for example "tools/call"). REQUIRED.
	Method string
	// ToolName is the tool targeted by tools/call. REQUIRED for tools/call.
	ToolName string
	// ResourceURI is the resource targeted by resources/read. REQUIRED for
	// resources/read.
	ResourceURI string
	// PromptName is the prompt targeted by prompts/get. REQUIRED for
	// prompts/get.
	PromptName string
	// Arguments are the call arguments (for tools/call), carried as action
	// properties. OPTIONAL.
	Arguments map[string]any
	// Token holds the authenticated token claims used to build the subject and
	// the token context.
	Token TokenClaims
	// ServerURI identifies the MCP server/session; it is the resource id for
	// collection operations and a property of tool/prompt resources. OPTIONAL.
	ServerURI string
	// Transport names the MCP transport (for example "http" or "stdio"),
	// recorded in the context. OPTIONAL.
	Transport string
	// ResourceIndicator is the RFC 8707 resource indicator (audience) the token
	// is bound to, recorded in the context. OPTIONAL.
	//
	// RFC 8707 - Resource Indicators for OAuth 2.0.
	// https://www.rfc-editor.org/rfc/rfc8707
	ResourceIndicator string
	// Context holds extra top-level context entries to merge under the
	// assembled request's context (the profile reserves the "mcp" key).
	// OPTIONAL.
	Context authzen.Context
}

// EvaluationRequest assembles an authzen.EvaluationRequest from the MCP request.
// It selects the action via ActionFor, derives the subject from the token
// claims, builds the resource for the targeted primitive, and records MCP
// metadata under the context's "mcp" key:
//
//	context.mcp = {
//	  method, transport,
//	  token: { sub, client_id, scopes, act, audience },
//	  resource_indicator,
//	}
//
// It returns an error for an unknown method, a missing primitive identifier, or
// a token from which no subject id can be derived.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.1 (Access Evaluation Request).
// https://openid.net/specs/authorization-api-1_0.html
func (r Request) EvaluationRequest() (authzen.EvaluationRequest, error) {
	actionName, ok := ActionFor(r.Method)
	if !ok {
		return authzen.EvaluationRequest{}, ErrUnknownMethod
	}

	var resource *authzen.Resource
	switch r.Method {
	case "tools/call":
		if r.ToolName == "" {
			return authzen.EvaluationRequest{}, ErrMissingToolName
		}
		resource = ToolResource(r.ToolName, r.ServerURI)
	case "resources/read":
		if r.ResourceURI == "" {
			return authzen.EvaluationRequest{}, ErrMissingResourceURI
		}
		resource = ResourceResource(r.ResourceURI)
	case "prompts/get":
		if r.PromptName == "" {
			return authzen.EvaluationRequest{}, ErrMissingPromptName
		}
		resource = PromptResource(r.PromptName, r.ServerURI)
	default:
		// Collection-level operations (tools/list, resources/list,
		// prompts/list) authorize against the server/session itself.
		resource = ServerResource(r.ServerURI)
	}

	subject := SubjectFromToken(r.Token)
	if subject.ID == "" {
		return authzen.EvaluationRequest{}, ErrMissingSubject
	}

	action := &authzen.Action{Name: actionName}
	if len(r.Arguments) > 0 {
		action.Properties = map[string]any{"arguments": r.Arguments}
	}

	return authzen.EvaluationRequest{
		Subject:  subject,
		Action:   action,
		Resource: resource,
		Context:  r.evaluationContext(),
	}, nil
}

// evaluationContext builds the AuthZEN context, merging any caller-supplied
// Context entries with the profile's reserved "mcp" object.
func (r Request) evaluationContext() authzen.Context {
	mcp := map[string]any{}
	if r.Method != "" {
		mcp["method"] = r.Method
	}
	if r.Transport != "" {
		mcp["transport"] = r.Transport
	}
	if r.ResourceIndicator != "" {
		mcp["resource_indicator"] = r.ResourceIndicator
	}

	token := map[string]any{}
	if r.Token.Subject != "" {
		token["sub"] = r.Token.Subject
	}
	if r.Token.ClientID != "" {
		token["client_id"] = r.Token.ClientID
	}
	if len(r.Token.Scopes) > 0 {
		token["scopes"] = r.Token.Scopes
	}
	if r.Token.Actor != "" {
		token["act"] = r.Token.Actor
	}
	if r.Token.Audience != "" {
		token["audience"] = r.Token.Audience
	}
	if len(token) > 0 {
		mcp["token"] = token
	}

	ctx := authzen.Context{}
	for k, v := range r.Context {
		ctx[k] = v
	}
	ctx["mcp"] = mcp
	return ctx
}
