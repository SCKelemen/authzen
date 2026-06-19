package main

import (
	"flag"
	"fmt"
	"io"
)

// discoverUsage prints the help for the discover subcommand.
func discoverUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `authzen discover - fetch the well-known PDP metadata document (Section 9).

Performs an HTTP GET of <url>/.well-known/authzen-configuration and prints the
advertised PDP base URL and endpoints. Use --json for the raw document.

Usage:
  authzen discover --url URL

Flags:
`)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// runDiscover implements the "discover" subcommand.
//
// OpenID AuthZEN Authorization API 1.0, Section 9 (Metadata).
// https://openid.net/specs/authorization-api-1_0.html#name-metadata
func runDiscover(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { discoverUsage(stderr, fs) }

	g := registerGlobal(fs)

	if helpRequested(args) {
		discoverUsage(stdout, fs)
		return 0
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if code, ok := validateGlobal("discover", g, stderr); !ok {
		return code
	}

	ctx, cancel := withTimeout(g)
	defer cancel()

	md, err := newClient(g).Metadata(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "authzen discover: %v\n", err)
		return 1
	}

	if g.json {
		if err := printJSON(stdout, md); err != nil {
			fmt.Fprintf(stderr, "authzen discover: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "policy_decision_point:\t%s\n", md.PolicyDecisionPoint)
	fmt.Fprintf(stdout, "access_evaluation_endpoint:\t%s\n", md.AccessEvaluationEndpoint)
	printIf(stdout, "access_evaluations_endpoint", md.AccessEvaluationsEndpoint)
	printIf(stdout, "search_subject_endpoint", md.SearchSubjectEndpoint)
	printIf(stdout, "search_resource_endpoint", md.SearchResourceEndpoint)
	printIf(stdout, "search_action_endpoint", md.SearchActionEndpoint)
	for _, c := range md.Capabilities {
		fmt.Fprintf(stdout, "capability:\t%s\n", c)
	}
	return 0
}

// printIf prints a "key:\tvalue" line only when value is non-empty, so the
// summary omits unsupported endpoints (an absent endpoint signals the API is
// unsupported; Section 9.1).
func printIf(w io.Writer, key, value string) {
	if value != "" {
		fmt.Fprintf(w, "%s:\t%s\n", key, value)
	}
}
