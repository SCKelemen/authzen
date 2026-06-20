package mcp

import "testing"

// FuzzParseChallenge fuzzes the WWW-Authenticate parser, which consumes
// untrusted server input. It asserts two properties:
//
//  1. ParseChallenge never panics on arbitrary input.
//  2. Rendering is a stable fixpoint: once a parsed Challenge is rendered with
//     String, parsing and rendering it again yields the identical string. This
//     guards against parse/render drift (for example quoting or control-byte
//     handling that is not idempotent).
//
// RFC 6750 Section 3 - The WWW-Authenticate Response Header Field.
// https://www.rfc-editor.org/rfc/rfc6750#section-3
func FuzzParseChallenge(f *testing.F) {
	seeds := []string{
		"",
		"Bearer",
		`Bearer realm="example", error="insufficient_scope", scope="mcp:tools", resource_metadata="https://x/prm"`,
		`Bearer error="insufficient`,
		`Bearer mF_9.B5f-4.1JqM`,
		`bearer error=insufficient_scope , scope=a`,
		`Bearer realm="a", Basic realm="b"`,
		"Bearer error=\"x\r\ny\"",
		`Bearer error="a\"b\\c"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, header string) {
		c, err := ParseChallenge(header)
		if err != nil {
			// The only error path is an empty/blank header; nothing to render.
			return
		}

		// Normalize once, then assert the rendered form is a stable fixpoint.
		normalized := c.String()
		reparsed, err := ParseChallenge(normalized)
		if err != nil {
			t.Fatalf("reparse of rendered header failed: header=%q rendered=%q err=%v", header, normalized, err)
		}
		if got := reparsed.String(); got != normalized {
			t.Fatalf("render not stable:\n header=%q\n once=%q\n twice=%q", header, normalized, got)
		}
	})
}
