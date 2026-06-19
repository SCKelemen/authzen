package main

import (
	"flag"
	"fmt"
	"io"

	authzen "github.com/SCKelemen/authzen"
)

// evaluateUsage prints the help for the evaluate subcommand.
func evaluateUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `authzen evaluate - make a single Access Evaluation decision (Section 6).

Asks the PDP whether a subject may perform an action on a resource, optionally
within a context. The decision is printed as "allow" or "deny"; a deny is a
successful API call and exits 0 unless --deny-exit-code is set.

Usage:
  authzen evaluate --url URL [entity flags]
  authzen evaluate --url URL --request <file|->

The request may be built from the entity flags, or supplied whole as an
EvaluationRequest JSON document via --request (use "-" to read stdin). When
--request is given, the entity flags are ignored.

Flags:
`)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// runEvaluate implements the "evaluate" subcommand.
//
// OpenID AuthZEN Authorization API 1.0, Section 6 (Access Evaluation API).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluation-api
func runEvaluate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { evaluateUsage(stderr, fs) }

	g := registerGlobal(fs)
	var (
		requestPath  string
		subjectType  string
		subjectID    string
		actionName   string
		resourceType string
		resourceID   string
		contextJSON  string
		subjectProps string
		resourcePrp  string
		actionProps  string
		denyExitCode int
	)
	fs.StringVar(&requestPath, "request", "", "read a full EvaluationRequest JSON from this file, or - for stdin")
	fs.StringVar(&subjectType, "subject-type", "", "subject type, e.g. user (Section 5.1)")
	fs.StringVar(&subjectID, "subject-id", "", "subject id, e.g. alice@example.com (Section 5.1)")
	fs.StringVar(&actionName, "action", "", "action name, e.g. can_read (Section 5.3)")
	fs.StringVar(&resourceType, "resource-type", "", "resource type, e.g. account (Section 5.2)")
	fs.StringVar(&resourceID, "resource-id", "", "resource id, e.g. 123 (Section 5.2)")
	fs.StringVar(&contextJSON, "context", "", "context as an inline JSON object (Section 5.4)")
	fs.StringVar(&subjectProps, "subject-properties", "", "subject properties as an inline JSON object")
	fs.StringVar(&resourcePrp, "resource-properties", "", "resource properties as an inline JSON object")
	fs.StringVar(&actionProps, "action-properties", "", "action properties as an inline JSON object")
	fs.IntVar(&denyExitCode, "deny-exit-code", 0, "exit code to use when the decision is a deny (0 keeps exit 0)")

	if helpRequested(args) {
		evaluateUsage(stdout, fs)
		return 0
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if g.url == "" {
		fmt.Fprintln(stderr, "authzen evaluate: --url is required")
		return 2
	}

	req, code := buildEvaluationRequest(requestPath, stdin, stderr,
		subjectType, subjectID, actionName, resourceType, resourceID,
		contextJSON, subjectProps, resourcePrp, actionProps)
	if req == nil {
		return code
	}

	ctx, cancel := withTimeout(g)
	defer cancel()

	resp, err := newClient(g).Evaluate(ctx, req)
	if err != nil {
		fmt.Fprintf(stderr, "authzen evaluate: %v\n", err)
		return 1
	}

	if g.json {
		if err := printJSON(stdout, resp); err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(stdout, decisionLabel(resp.Decision))
	}

	// A deny is a successful call (Section 10.1.2), so it exits 0 unless the
	// operator opted into a nonzero gate via --deny-exit-code.
	if !resp.Decision && denyExitCode != 0 {
		return denyExitCode
	}
	return 0
}

// buildEvaluationRequest assembles the EvaluationRequest from --request or from
// the entity flags. It returns (nil, code) on error, with the diagnostic
// already written to stderr.
func buildEvaluationRequest(requestPath string, stdin io.Reader, stderr io.Writer,
	subjectType, subjectID, actionName, resourceType, resourceID,
	contextJSON, subjectProps, resourceProps, actionProps string,
) (*authzen.EvaluationRequest, int) {
	var req authzen.EvaluationRequest

	if requestPath != "" {
		data, err := readRequest(requestPath, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: read request: %v\n", err)
			return nil, 1
		}
		if err := parseRequestJSON(data, &req); err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: parse request JSON: %v\n", err)
			return nil, 1
		}
		return &req, 0
	}

	req.Subject = &authzen.Subject{Type: subjectType, ID: subjectID}
	req.Action = &authzen.Action{Name: actionName}
	req.Resource = &authzen.Resource{Type: resourceType, ID: resourceID}

	if contextJSON != "" {
		m, err := parseJSONObject(contextJSON)
		if err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: parse --context JSON: %v\n", err)
			return nil, 2
		}
		req.Context = authzen.Context(m)
	}
	if subjectProps != "" {
		m, err := parseJSONObject(subjectProps)
		if err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: parse --subject-properties JSON: %v\n", err)
			return nil, 2
		}
		req.Subject.Properties = m
	}
	if resourceProps != "" {
		m, err := parseJSONObject(resourceProps)
		if err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: parse --resource-properties JSON: %v\n", err)
			return nil, 2
		}
		req.Resource.Properties = m
	}
	if actionProps != "" {
		m, err := parseJSONObject(actionProps)
		if err != nil {
			fmt.Fprintf(stderr, "authzen evaluate: parse --action-properties JSON: %v\n", err)
			return nil, 2
		}
		req.Action.Properties = m
	}
	return &req, 0
}
