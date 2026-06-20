package mcp

import (
	"net/http"
	"reflect"
	"testing"
)

// TestChallengeString checks WWW-Authenticate header rendering, including
// quoting and parameter ordering.
func TestChallengeString(t *testing.T) {
	cases := []struct {
		name string
		c    Challenge
		want string
	}{
		{
			name: "insufficient scope",
			c:    InsufficientScope("mcp:tools", "https://api.example.com/.well-known/oauth-protected-resource"),
			want: `Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name: "unauthorized",
			c:    Unauthorized("https://api.example.com/.well-known/oauth-protected-resource"),
			want: `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name: "full ordering with realm and description",
			c:    Challenge{Realm: "mcp", Error: "invalid_token", ErrorDescription: "expired", Scope: "a b", ResourceMetadata: "https://x/y"},
			want: `Bearer realm="mcp", error="invalid_token", error_description="expired", scope="a b", resource_metadata="https://x/y"`,
		},
		{
			name: "empty challenge is bare scheme",
			c:    Challenge{},
			want: "Bearer",
		},
		{
			name: "quotes are escaped",
			c:    Challenge{ErrorDescription: `say "hi"\bye`},
			want: `Bearer error_description="say \"hi\"\\bye"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.String(); got != tc.want {
				t.Fatalf("String() =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

// TestChallengeStatuses checks the status codes set by the constructor helpers.
func TestChallengeStatuses(t *testing.T) {
	if got := InsufficientScope("s", "u").Status; got != http.StatusForbidden {
		t.Errorf("InsufficientScope status = %d, want %d", got, http.StatusForbidden)
	}
	if got := Unauthorized("u").Status; got != http.StatusUnauthorized {
		t.Errorf("Unauthorized status = %d, want %d", got, http.StatusUnauthorized)
	}
}

// TestDenyContext checks the AuthZEN decision-context shape for a deny.
func TestDenyContext(t *testing.T) {
	c := InsufficientScope("mcp:tools", "https://api.example.com/prm")
	ctx := DenyContext(c)

	mcp, ok := ctx["mcp"].(map[string]any)
	if !ok {
		t.Fatalf("ctx.mcp wrong type: %#v", ctx["mcp"])
	}
	if mcp["status"] != http.StatusForbidden {
		t.Errorf("status = %#v", mcp["status"])
	}
	if mcp["error"] != ErrorInsufficientScope {
		t.Errorf("error = %#v", mcp["error"])
	}
	wa, ok := mcp["www_authenticate"].(map[string]any)
	if !ok {
		t.Fatalf("www_authenticate wrong type: %#v", mcp["www_authenticate"])
	}
	if wa["scope"] != "mcp:tools" {
		t.Errorf("scope = %#v", wa["scope"])
	}
	if wa["resource_metadata"] != "https://api.example.com/prm" {
		t.Errorf("resource_metadata = %#v", wa["resource_metadata"])
	}
	if wa["header"] != c.String() {
		t.Errorf("header = %#v, want %q", wa["header"], c.String())
	}
}

// TestParseChallenge checks parsing of WWW-Authenticate values, including
// quoted values, escaping, and ordering independence.
func TestParseChallenge(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   Challenge
	}{
		{
			name:   "full",
			header: `Bearer realm="mcp", error="insufficient_scope", scope="mcp:tools read", resource_metadata="https://x/prm"`,
			want:   Challenge{Scheme: "Bearer", Realm: "mcp", Error: "insufficient_scope", Scope: "mcp:tools read", ResourceMetadata: "https://x/prm"},
		},
		{
			name:   "scheme only",
			header: "Bearer",
			want:   Challenge{Scheme: "Bearer"},
		},
		{
			name:   "escaped quotes",
			header: `Bearer error_description="say \"hi\""`,
			want:   Challenge{Scheme: "Bearer", ErrorDescription: `say "hi"`},
		},
		{
			name:   "reordered params",
			header: `Bearer resource_metadata="https://x/prm", error="invalid_token"`,
			want:   Challenge{Scheme: "Bearer", Error: "invalid_token", ResourceMetadata: "https://x/prm"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseChallenge(tc.header)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestParseChallengeEmpty checks that an empty header is rejected.
func TestParseChallengeEmpty(t *testing.T) {
	if _, err := ParseChallenge("   "); err == nil {
		t.Fatal("expected error for empty header")
	}
}

// TestChallengeRoundTrip checks that rendering then parsing recovers the
// challenge's wire-visible fields.
func TestChallengeRoundTrip(t *testing.T) {
	cases := []Challenge{
		InsufficientScope("mcp:tools", "https://api.example.com/prm"),
		Unauthorized("https://api.example.com/prm"),
		{Realm: "mcp", Error: "invalid_token", ErrorDescription: `it "broke"`, Scope: "a b c", ResourceMetadata: "https://x/y"},
	}
	for _, c := range cases {
		parsed, err := ParseChallenge(c.String())
		if err != nil {
			t.Fatalf("ParseChallenge(%q): %v", c.String(), err)
		}
		// Status is not carried on the wire; compare only header fields.
		want := c
		want.Scheme = DefaultScheme
		want.Status = 0
		if !reflect.DeepEqual(parsed, want) {
			t.Errorf("round-trip mismatch:\n got  %#v\n want %#v", parsed, want)
		}
	}
}
