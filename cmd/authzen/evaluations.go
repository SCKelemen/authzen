package main

import (
	"flag"
	"fmt"
	"io"

	authzen "github.com/SCKelemen/authzen"
)

// evaluationsUsage prints the help for the evaluations subcommand.
func evaluationsUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `authzen evaluations - make a batch of Access Evaluation decisions (Section 7).

Sends a full EvaluationsRequest JSON document to the PDP's boxcar endpoint and
prints one decision per line, numbered in request order. The request supplies
top-level subject/action/resource/context defaults that each member inherits,
plus an optional options.evaluations_semantic.

Usage:
  authzen evaluations --url URL --request <file|->

Flags:
`)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// runEvaluations implements the "evaluations" subcommand.
//
// OpenID AuthZEN Authorization API 1.0, Section 7 (Access Evaluations API).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-api
func runEvaluations(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evaluations", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { evaluationsUsage(stderr, fs) }

	g := registerGlobal(fs)
	var requestPath string
	fs.StringVar(&requestPath, "request", "", "read a full EvaluationsRequest JSON from this file, or - for stdin (required)")

	if helpRequested(args) {
		evaluationsUsage(stdout, fs)
		return 0
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if g.url == "" {
		fmt.Fprintln(stderr, "authzen evaluations: --url is required")
		return 2
	}
	if requestPath == "" {
		fmt.Fprintln(stderr, "authzen evaluations: --request is required")
		return 2
	}

	data, err := readRequest(requestPath, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "authzen evaluations: read request: %v\n", err)
		return 1
	}
	var req authzen.EvaluationsRequest
	if err := parseRequestJSON(data, &req); err != nil {
		fmt.Fprintf(stderr, "authzen evaluations: parse request JSON: %v\n", err)
		return 1
	}

	ctx, cancel := withTimeout(g)
	defer cancel()

	resp, err := newClient(g).EvaluateBatch(ctx, &req)
	if err != nil {
		fmt.Fprintf(stderr, "authzen evaluations: %v\n", err)
		return 1
	}

	if g.json {
		if err := printJSON(stdout, resp); err != nil {
			fmt.Fprintf(stderr, "authzen evaluations: %v\n", err)
			return 1
		}
		return 0
	}
	for i, e := range resp.Evaluations {
		fmt.Fprintf(stdout, "%d\t%s\n", i, decisionLabel(e.Decision))
	}
	return 0
}
