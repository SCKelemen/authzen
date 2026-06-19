// Command authzen is a command-line Policy Enforcement Point (PEP) for the
// OpenID AuthZEN Authorization API 1.0. It talks to a Policy Decision Point
// (PDP) over the normative HTTPS + JSON binding using the
// github.com/SCKelemen/authzen/client package, and exposes the four API
// families as subcommands:
//
//   - evaluate    single Access Evaluation        (Section 6)
//   - evaluations batch Access Evaluations        (Section 7)
//   - search      Subject/Resource/Action search  (Section 8)
//   - discover    well-known PDP metadata          (Section 9)
//
// The tool lives in the root module and depends only on the Go standard library
// and the in-repo client; it imports no third-party packages and no gRPC code.
//
// # Exit codes
//
//   - 0  the API call succeeded (a deny is still a successful call).
//   - 1  a transport or API error occurred (network failure, non-2xx HTTP
//     status, or a malformed/invalid request), reported to stderr.
//   - 2  a usage error occurred (missing --url, bad flags, bad subcommand).
//   - N  when --deny-exit-code N (N != 0) is given to "evaluate" and the
//     decision is a deny, the command exits with N so it can gate a script
//     or CI step. A successful allow always exits 0.
//
// OpenID AuthZEN Authorization API 1.0, Section 10 (Transport).
// https://openid.net/specs/authorization-api-1_0.html#name-transport
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/SCKelemen/authzen/client"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable entry point. It dispatches to a subcommand and returns the
// process exit code, reading from stdin and writing user output to stdout and
// diagnostics to stderr. Keeping the I/O streams as parameters lets the test
// suite drive the whole CLI against an httptest PDP without touching the
// process globals.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		rootUsage(stderr)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		rootUsage(stdout)
		return 0
	case "evaluate":
		return runEvaluate(args[1:], stdin, stdout, stderr)
	case "evaluations":
		return runEvaluations(args[1:], stdin, stdout, stderr)
	case "search":
		return runSearch(args[1:], stdin, stdout, stderr)
	case "discover":
		return runDiscover(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "authzen: unknown command %q\n\n", args[0])
		rootUsage(stderr)
		return 2
	}
}

// rootUsage prints the top-level help listing every subcommand.
func rootUsage(w io.Writer) {
	fmt.Fprint(w, `authzen - command-line client for the OpenID AuthZEN Authorization API 1.0

Usage:
  authzen <command> [flags]

Commands:
  evaluate      Make a single Access Evaluation decision (Section 6).
  evaluations   Make a batch of Access Evaluation decisions (Section 7).
  search        Search for subjects, resources, or actions (Section 8).
  discover      Fetch the well-known PDP metadata document (Section 9).

Run "authzen <command> --help" for command-specific flags.

Common flags (accepted by every command):
  --url string        PDP base URL, e.g. https://pdp.example.com (required)
  --token string      OAuth 2.0 bearer token sent in the Authorization header
  --timeout duration  Per-request timeout (default 30s)
  --json              Print the raw JSON response instead of a summary

Exit codes:
  0  successful API call (a deny decision is still a success)
  1  transport or API error (reported to stderr)
  2  usage error (missing --url, bad flags, unknown command)
  N  evaluate only: with --deny-exit-code N (N!=0), a deny exits N

Spec: https://openid.net/specs/authorization-api-1_0.html
`)
}

// globalOpts holds the flags shared by every subcommand.
type globalOpts struct {
	url     string
	token   string
	timeout time.Duration
	json    bool
}

// registerGlobal registers the shared --url/--token/--timeout/--json flags on
// fs and returns the destination struct.
func registerGlobal(fs *flag.FlagSet) *globalOpts {
	o := &globalOpts{}
	fs.StringVar(&o.url, "url", "", "PDP base URL, e.g. https://pdp.example.com (required)")
	fs.StringVar(&o.token, "token", "", "OAuth 2.0 bearer token for the Authorization header")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	fs.BoolVar(&o.json, "json", false, "print the raw JSON response instead of a summary")
	return o
}

// newClient builds a PEP client from the shared options.
//
// OpenID AuthZEN Authorization API 1.0, Section 11.2 (bearer tokens RECOMMENDED).
// https://openid.net/specs/authorization-api-1_0.html
func newClient(g *globalOpts) *client.Client {
	var opts []client.Option
	if g.token != "" {
		opts = append(opts, client.WithBearerToken(g.token))
	}
	return client.New(g.url, opts...)
}

// withTimeout derives a context honoring the configured --timeout. A zero or
// negative timeout means no deadline.
func withTimeout(g *globalOpts) (context.Context, context.CancelFunc) {
	if g.timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), g.timeout)
}

// readRequest loads a full request body from path, or from stdin when path is
// "-". It is used by the --request flags to supply a complete request document.
func readRequest(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

// parseJSONObject parses a JSON object literal into a map. It is used for the
// inline --context and --*-properties flags, which all carry a JSON object.
func parseJSONObject(s string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseRequestJSON decodes a request document supplied via a --request flag.
// Unknown fields are ignored for forward compatibility, matching the PDP's
// decoding rules (Section 10.1.1).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html#name-json-serialization
func parseRequestJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// printJSON writes v as indented JSON.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// parseFlags parses args, mapping flag.ErrHelp to a clean exit. It returns the
// FlagSet parse error (nil on success) and an ok flag that is false when the
// caller should stop. The returned code is meaningful only when ok is false.
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	switch err := fs.Parse(args); err {
	case nil:
		return 0, true
	case flag.ErrHelp:
		// flag already printed usage to the FlagSet output.
		return 0, false
	default:
		// flag already printed the error and usage to the FlagSet output.
		return 2, false
	}
}

// helpRequested reports whether args explicitly ask for help, so a subcommand
// can print its usage to stdout (and exit 0) rather than letting flag print it
// to stderr as part of an error path. Scanning stops at "--".
func helpRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

// decisionLabel renders a boolean decision as the spec's allow/deny semantics
// (true permits, false denies; Section 5.5).
func decisionLabel(decision bool) string {
	if decision {
		return "allow"
	}
	return "deny"
}
