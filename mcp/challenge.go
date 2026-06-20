package mcp

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
)

// DefaultScheme is the HTTP authentication scheme used by MCP's OAuth 2.1 bearer
// tokens.
//
// RFC 6750 Section 3 - The WWW-Authenticate Response Header Field.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
const DefaultScheme = "Bearer"

// Standard OAuth bearer-token error codes used by MCP for denials.
//
// RFC 6750 Section 3.1 - Error Codes.
// https://www.rfc-editor.org/rfc/rfc6750#section-3.1
const (
	// ErrorInsufficientScope indicates the token lacks the scope required for
	// the request; returned with HTTP 403.
	ErrorInsufficientScope = "insufficient_scope"
	// ErrorInvalidToken indicates the token is expired, revoked, malformed, or
	// otherwise invalid; returned with HTTP 401.
	ErrorInvalidToken = "invalid_token"
)

// Challenge models a WWW-Authenticate Bearer challenge that an MCP server (an
// OAuth 2.1 resource server) returns on a denied or unauthenticated request. It
// renders to a header value via String and to an AuthZEN decision context via
// DenyContext.
//
// The resource_metadata parameter points the client at the Protected Resource
// Metadata document that bootstraps OAuth discovery.
//
// RFC 6750 Section 3 - WWW-Authenticate.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
// RFC 9728 Section 5.1 - WWW-Authenticate Response.
// https://www.rfc-editor.org/rfc/rfc9728#section-5.1
type Challenge struct {
	// Scheme is the authentication scheme; defaults to "Bearer" when empty.
	Scheme string
	// Error is the OAuth error code (for example "insufficient_scope" or
	// "invalid_token"). OPTIONAL.
	Error string
	// ErrorDescription is a human-readable explanation of the error. OPTIONAL.
	ErrorDescription string
	// Scope is the space-delimited scope the client must obtain. OPTIONAL.
	Scope string
	// ResourceMetadata is the URL of the RFC 9728 Protected Resource Metadata
	// document. OPTIONAL.
	ResourceMetadata string
	// Realm is the protection realm. OPTIONAL.
	Realm string
	// Status is the HTTP status code that accompanies the challenge (401 or
	// 403). It is not emitted in the header; it is carried in DenyContext.
	Status int
}

// String renders the challenge as a WWW-Authenticate header value, for example:
//
//	Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
//
// Parameters are emitted in a stable order (realm, error, error_description,
// scope, resource_metadata) and only when set. Values are emitted as RFC 7230
// quoted-strings with embedded quotes and backslashes escaped.
//
// RFC 6750 Section 3 - WWW-Authenticate.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
// RFC 9728 Section 5.1 - WWW-Authenticate Response.
// https://www.rfc-editor.org/rfc/rfc9728#section-5.1
func (c Challenge) String() string {
	// Sanitize the scheme: an auth-scheme is a bare token (RFC 7235 §2.1) with
	// no whitespace or control characters. Stripping them prevents a crafted
	// Scheme from injecting whitespace/CRLF into the header and keeps String an
	// idempotent fixpoint (the parser trims and splits on whitespace, so an
	// unsanitized scheme would not survive a parse/render round trip).
	scheme := sanitizeScheme(c.Scheme)
	if scheme == "" {
		scheme = DefaultScheme
	}

	var params []string
	add := func(key, val string) {
		// Decide emission on the sanitized value so a field consisting only of
		// control characters is omitted entirely rather than emitted as an
		// empty key="" parameter. This also makes rendering an idempotent
		// fixpoint: parsing String output and re-rendering yields the same
		// string.
		if stripControl(val) != "" {
			params = append(params, key+"="+quoteString(val))
		}
	}
	add("realm", c.Realm)
	add("error", c.Error)
	add("error_description", c.ErrorDescription)
	add("scope", c.Scope)
	add("resource_metadata", c.ResourceMetadata)

	if len(params) == 0 {
		return scheme
	}
	return scheme + " " + strings.Join(params, ", ")
}

// DenyContext renders the challenge as the AuthZEN decision context to embed in
// an EvaluationResponse.Context for a deny, allowing the PDP to hand the PEP a
// ready challenge:
//
//	{ "mcp": { "status": 403, "error": "insufficient_scope",
//	  "www_authenticate": { "scope": "...", "resource_metadata": "..." } } }
//
// The fully rendered header value is also included under
// www_authenticate.header for convenience.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.2 (Access Evaluation
// Response) and Section 5.5 (Decision context as the extension point).
// https://openid.net/specs/authorization-api-1_0.html
func DenyContext(c Challenge) map[string]any {
	wa := map[string]any{
		"header": c.String(),
	}
	if c.Scope != "" {
		wa["scope"] = c.Scope
	}
	if c.ResourceMetadata != "" {
		wa["resource_metadata"] = c.ResourceMetadata
	}
	if c.Realm != "" {
		wa["realm"] = c.Realm
	}

	mcp := map[string]any{
		"www_authenticate": wa,
	}
	if c.Status != 0 {
		mcp["status"] = c.Status
	}
	if c.Error != "" {
		mcp["error"] = c.Error
	}

	return map[string]any{"mcp": mcp}
}

// ChallengeFromDenyContext is the inverse of DenyContext: it reconstructs a
// Challenge from an AuthZEN decision context that carries a reserved mcp object
// (as produced by a PDP that understands this profile). It returns ok == false
// when the context has no mcp deny information, so a caller can fall back to a
// default challenge.
//
// When www_authenticate.header is present it is parsed first (recovering the
// scheme and any parameters), then the structured fields (scope,
// resource_metadata, realm, error, status) override it. Numeric status values
// are accepted as int or float64 so a context decoded from JSON (numbers decode
// to float64) is handled as well as one built in-process.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.2 (decision context).
// https://openid.net/specs/authorization-api-1_0.html
func ChallengeFromDenyContext(ctx map[string]any) (Challenge, bool) {
	m, ok := ctx["mcp"].(map[string]any)
	if !ok {
		return Challenge{}, false
	}

	var c Challenge
	found := false

	if wa, ok := m["www_authenticate"].(map[string]any); ok {
		found = true
		if h, ok := stringField(wa["header"]); ok {
			if parsed, err := ParseChallenge(h); err == nil {
				c = parsed
			}
		}
		if s, ok := stringField(wa["scope"]); ok {
			c.Scope = s
		}
		if s, ok := stringField(wa["resource_metadata"]); ok {
			c.ResourceMetadata = s
		}
		if s, ok := stringField(wa["realm"]); ok {
			c.Realm = s
		}
	}
	if s, ok := stringField(m["error"]); ok {
		c.Error = s
		found = true
	}
	if n, ok := intField(m["status"]); ok {
		c.Status = n
		found = true
	}

	return c, found
}

// stringField returns v as a non-empty string, or ok == false otherwise.
func stringField(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// intField returns v as an int, accepting the numeric types that a decision
// context may carry: a native int (built in-process) or a float64 (decoded from
// JSON, where all numbers become float64).
func intField(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// InsufficientScope builds a 403 insufficient_scope challenge naming the scope
// the client must obtain and the Protected Resource Metadata URL for discovery.
//
// RFC 6750 Section 3.1 - Error Codes (insufficient_scope -> 403).
// https://www.rfc-editor.org/rfc/rfc6750#section-3.1
func InsufficientScope(scope, resourceMetadataURL string) Challenge {
	return Challenge{
		Scheme:           DefaultScheme,
		Error:            ErrorInsufficientScope,
		Scope:            scope,
		ResourceMetadata: resourceMetadataURL,
		Status:           http.StatusForbidden,
	}
}

// Unauthorized builds a 401 challenge that points the client at the Protected
// Resource Metadata document to bootstrap OAuth discovery. This is the MCP
// "no/invalid token" response.
//
// RFC 9728 Section 5.1 - WWW-Authenticate Response (resource_metadata).
// https://www.rfc-editor.org/rfc/rfc9728#section-5.1
func Unauthorized(resourceMetadataURL string) Challenge {
	return Challenge{
		Scheme:           DefaultScheme,
		ResourceMetadata: resourceMetadataURL,
		Status:           http.StatusUnauthorized,
	}
}

// ParseChallenge parses a WWW-Authenticate header value into a Challenge. It
// reads the leading scheme token and the comma-separated auth-param list,
// decoding quoted-string values (handling escaped quotes and backslashes).
// Unknown parameters are ignored. It is intended for MCP clients inspecting a
// server's challenge.
//
// RFC 6750 Section 3 - WWW-Authenticate.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
func ParseChallenge(header string) (Challenge, error) {
	s := strings.TrimSpace(header)
	if s == "" {
		return Challenge{}, errors.New("mcp: empty WWW-Authenticate header")
	}

	scheme := s
	rest := ""
	if i := strings.IndexByte(s, ' '); i >= 0 {
		scheme = s[:i]
		rest = s[i+1:]
	}

	params := parseAuthParams(rest)
	return Challenge{
		Scheme:           scheme,
		Error:            params["error"],
		ErrorDescription: params["error_description"],
		Scope:            params["scope"],
		ResourceMetadata: params["resource_metadata"],
		Realm:            params["realm"],
	}, nil
}

// quoteString returns s as an RFC 7230 quoted-string, escaping backslashes and
// double quotes. Control characters (bytes < 0x20 and DEL 0x7f) are stripped
// before quoting: the quoted-string / quoted-pair grammar does not permit CR,
// LF, or other control bytes even when escaped, so they cannot be represented
// in a header value. Removing them prevents a field value containing "\r\n"
// from injecting an extra header line into the emitted WWW-Authenticate value
// (CRLF / response-splitting).
//
// RFC 7230 Section 3.2.6 - Field Value Components (quoted-string = DQUOTE
// *( qdtext / quoted-pair ) DQUOTE; qdtext excludes CTL, and quoted-pair only
// covers HTAB / SP / VCHAR / obs-text, never bare CTL such as CR or LF).
// https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6
func quoteString(s string) string {
	s = stripControl(s)
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// stripControl removes ASCII control characters (bytes < 0x20, including CR and
// LF, plus DEL 0x7f) from s. These bytes are not valid in an HTTP header field
// value; stripping them defends against header injection through a Challenge
// field.
//
// RFC 7230 Section 3.2 - Header Fields (field-content excludes CTL).
// https://www.rfc-editor.org/rfc/rfc7230#section-3.2
func stripControl(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isControl(rune(c)) {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// isControl reports whether r is an ASCII control byte (< 0x20 or DEL 0x7f).
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// sanitizeScheme removes control characters and all (Unicode) whitespace from a
// candidate auth-scheme token, returning a bare token. An auth-scheme contains
// no whitespace, so removing it both defends against header injection through
// the scheme and guarantees the scheme survives a parse/render round trip (the
// parser trims surrounding whitespace and splits the scheme on the first
// space).
//
// RFC 7235 Section 2.1 - Authentication Scheme (auth-scheme = token).
// https://www.rfc-editor.org/rfc/rfc7235#section-2.1
func sanitizeScheme(s string) string {
	return strings.Map(func(r rune) rune {
		if isControl(r) || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// parseAuthParams parses a comma-separated list of key=value auth-params, where
// values may be bare tokens or quoted-strings. Keys are lowercased. Malformed
// trailing input is tolerated and skipped.
//
// RFC 7235 Section 4.1 - WWW-Authenticate (auth-param).
// https://www.rfc-editor.org/rfc/rfc7235#section-4.1
func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	i, n := 0, len(s)
	for i < n {
		// Skip leading separators and whitespace.
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		// Read the key up to '='.
		start := i
		for i < n && s[i] != '=' {
			i++
		}
		if i >= n {
			break
		}
		key := strings.ToLower(strings.TrimSpace(s[start:i]))
		i++ // consume '='

		var val string
		if i < n && s[i] == '"' {
			i++ // consume opening quote
			var b strings.Builder
			for i < n {
				ch := s[i]
				if ch == '\\' && i+1 < n {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if ch == '"' {
					i++ // consume closing quote
					break
				}
				b.WriteByte(ch)
				i++
			}
			val = b.String()
		} else {
			start := i
			for i < n && s[i] != ',' {
				i++
			}
			val = strings.TrimSpace(s[start:i])
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}
