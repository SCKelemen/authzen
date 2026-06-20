package mcp

import (
	"strings"
	"testing"
)

// TestChallengeStringNoHeaderInjection is a security regression: a Challenge
// field carrying CR/LF (or other control characters) must not be able to inject
// an extra header line into the rendered WWW-Authenticate value. The control
// bytes are stripped, so the output is a single line with no embedded CRLF and
// no injected header.
//
// RFC 7230 Section 3.2.6 - Field Value Components (CTL excluded from header
// values, even when escaped).
// https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6
func TestChallengeStringNoHeaderInjection(t *testing.T) {
	cases := []struct {
		name string
		c    Challenge
	}{
		{"crlf in scope", Challenge{Scope: "read\r\nX-Injected: 1"}},
		{"crlf in error", Challenge{Error: "x\r\nX-Injected: 1"}},
		{"crlf in resource_metadata", Challenge{ResourceMetadata: "https://x/y\r\nLocation: https://evil"}},
		{"crlf in realm", Challenge{Realm: "r\r\nSet-Cookie: a=b"}},
		{"lone LF and CR and tab and NUL", Challenge{ErrorDescription: "a\nb\rc\td\x00e"}},
		{"DEL byte", Challenge{Error: "a\x7fb"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.c.String()
			// No CR/LF: the value cannot break onto a second header line.
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("header contains CR/LF: %q", got)
			}
			// No control byte at all leaked through (even tab/NUL/DEL).
			for i := 0; i < len(got); i++ {
				if b := got[i]; b < 0x20 || b == 0x7f {
					t.Fatalf("header contains control byte %#x: %q", b, got)
				}
			}
		})
	}
}

// TestChallengeStringInjectionSingleLine asserts the precise single-line output
// for the canonical CRLF injection payload from the task: the smuggled header
// name appears (as inert data) but on the same line, with the CRLF removed.
func TestChallengeStringInjectionSingleLine(t *testing.T) {
	c := InsufficientScope("read\r\nX-Injected: 1", "https://api.example.com/prm")
	got := c.String()

	if strings.Count(got, "\n") != 0 || strings.Count(got, "\r") != 0 {
		t.Fatalf("expected single-line header, got %q", got)
	}
	const want = `Bearer error="insufficient_scope", scope="readX-Injected: 1", resource_metadata="https://api.example.com/prm"`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// TestParseChallengeVerbatim parses verbatim RFC 6750 §3 / RFC 9728 §5.1 style
// WWW-Authenticate header strings and asserts the parsed fields, then re-renders
// and parses again to confirm the rendered form is stable.
//
// RFC 6750 Section 3 - The WWW-Authenticate Response Header Field.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
// RFC 9728 Section 5.1 - WWW-Authenticate Response (resource_metadata).
// https://www.rfc-editor.org/rfc/rfc9728#section-5.1
func TestParseChallengeVerbatim(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   Challenge
	}{
		{
			// RFC 6750 Section 3.1 - insufficient_scope error response.
			name:   "rfc6750 insufficient_scope",
			header: `Bearer realm="example", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."`,
			want: Challenge{
				Scheme:           "Bearer",
				Realm:            "example",
				Error:            "insufficient_scope",
				ErrorDescription: "The request requires higher privileges than provided by the access token.",
			},
		},
		{
			// RFC 9728 Section 5.1 - resource_metadata pointer for discovery.
			name:   "rfc9728 resource_metadata",
			header: `Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`,
			want: Challenge{
				Scheme:           "Bearer",
				ResourceMetadata: "https://resource.example.com/.well-known/oauth-protected-resource",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseChallenge(tc.header)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parsed %#v, want %#v", got, tc.want)
			}
			// Re-render then re-parse: the rendered form must be a stable
			// fixpoint of the parse/render pair.
			rendered := got.String()
			reparsed, err := ParseChallenge(rendered)
			if err != nil {
				t.Fatalf("reparse %q: %v", rendered, err)
			}
			if reparsed.String() != rendered {
				t.Fatalf("render not stable: %q -> %q", rendered, reparsed.String())
			}
		})
	}
}

// TestParseChallengeMalformed covers malformed and adversarial inputs. The
// parser is best-effort and total: it never errors except on an empty header,
// ignores unknown and unparsable parameters, and never panics.
//
// RFC 7235 Section 4.1 - WWW-Authenticate (auth-param / token68).
// https://www.rfc-editor.org/rfc/rfc7235#section-4.1
func TestParseChallengeMalformed(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   Challenge
	}{
		{
			name:   "unterminated quote",
			header: `Bearer error="insufficient`,
			want:   Challenge{Scheme: "Bearer", Error: "insufficient"},
		},
		{
			name:   "missing equals",
			header: `Bearer realm`,
			want:   Challenge{Scheme: "Bearer"},
		},
		{
			name:   "bare token68 credentials",
			header: `Bearer mF_9.B5f-4.1JqM`,
			want:   Challenge{Scheme: "Bearer"},
		},
		{
			name:   "unquoted value",
			header: `Bearer error=insufficient_scope, scope=mcp:tools`,
			want:   Challenge{Scheme: "Bearer", Error: "insufficient_scope", Scope: "mcp:tools"},
		},
		{
			name:   "unknown params ignored",
			header: `Bearer error="invalid_token", foo="bar", baz="qux"`,
			want:   Challenge{Scheme: "Bearer", Error: "invalid_token"},
		},
		{
			name:   "scheme lowercase still parses params",
			header: `bearer error="insufficient_scope"`,
			want:   Challenge{Scheme: "bearer", Error: "insufficient_scope"},
		},
		{
			name:   "multiple challenges parses first scheme",
			header: `Bearer realm="a", Basic realm="b"`,
			want:   Challenge{Scheme: "Bearer", Realm: "a"},
		},
		{
			name:   "trailing comma and spaces",
			header: `Bearer   error="invalid_token" ,  `,
			want:   Challenge{Scheme: "Bearer", Error: "invalid_token"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseChallenge(tc.header)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parsed %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestParseChallengeSchemeCaseInsensitive asserts that parameter extraction is
// independent of the scheme's letter case (bearer vs Bearer), even though the
// scheme token itself is preserved verbatim.
//
// RFC 7235 Section 2.1 - the auth-scheme is case-insensitive.
// https://www.rfc-editor.org/rfc/rfc7235#section-2.1
func TestParseChallengeSchemeCaseInsensitive(t *testing.T) {
	lower, err := ParseChallenge(`bearer error="insufficient_scope", scope="mcp:tools"`)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	upper, err := ParseChallenge(`Bearer error="insufficient_scope", scope="mcp:tools"`)
	if err != nil {
		t.Fatalf("upper: %v", err)
	}
	if lower.Error != upper.Error || lower.Scope != upper.Scope {
		t.Fatalf("params differ by scheme case: %#v vs %#v", lower, upper)
	}
	if !strings.EqualFold(lower.Scheme, upper.Scheme) {
		t.Fatalf("schemes not case-equivalent: %q vs %q", lower.Scheme, upper.Scheme)
	}
}

// TestDenyContextJSONWire asserts the literal marshaled JSON shape of a deny
// context, including the reserved mcp object and its www_authenticate child.
//
// OpenID AuthZEN Authorization API 1.0, Section 6.2 (Access Evaluation
// Response, decision context).
// https://openid.net/specs/authorization-api-1_0.html
func TestDenyContextJSONWire(t *testing.T) {
	ctx := DenyContext(InsufficientScope("mcp:tools", "https://api.example.com/prm"))

	const want = `{
      "mcp": {
        "status": 403,
        "error": "insufficient_scope",
        "www_authenticate": {
          "scope": "mcp:tools",
          "resource_metadata": "https://api.example.com/prm",
          "header": "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"https://api.example.com/prm\""
        }
      }
    }`
	assertJSON(t, ctx, want)
}
