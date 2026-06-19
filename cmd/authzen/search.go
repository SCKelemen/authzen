package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	authzen "github.com/SCKelemen/authzen"
)

// searchRootUsage prints the help for the "search" command group.
func searchRootUsage(w io.Writer) {
	fmt.Fprint(w, `authzen search - search for subjects, resources, or actions (Section 8).

Usage:
  authzen search subject  --url URL [flags]   who can do an action on a resource (Section 8.4)
  authzen search resource --url URL [flags]   which resources a subject can act on (Section 8.5)
  authzen search action   --url URL [flags]   which actions a subject can do on a resource (Section 8.6)

Run "authzen search <kind> --help" for the flags of each search kind.
`)
}

// runSearch dispatches the "search" command to one of its three kinds.
//
// OpenID AuthZEN Authorization API 1.0, Section 8 (Search APIs).
// https://openid.net/specs/authorization-api-1_0.html#name-search-apis
func runSearch(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "authzen search: requires a kind: subject|resource|action")
		searchRootUsage(stderr)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		searchRootUsage(stdout)
		return 0
	case "subject", "resource", "action":
		return runSearchKind(args[0], args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "authzen search: unknown kind %q (want subject|resource|action)\n", args[0])
		searchRootUsage(stderr)
		return 2
	}
}

// searchKindUsage prints the help for a specific search kind.
func searchKindUsage(w io.Writer, kind string, fs *flag.FlagSet) {
	fmt.Fprintf(w, "authzen search %s - %s\n\n", kind, searchKindSummary(kind))
	fmt.Fprintf(w, "Usage:\n  authzen search %s --url URL [entity flags]\n  authzen search %s --url URL --request <file|->\n\n", kind, kind)
	fmt.Fprint(w, "The query may be built from the entity flags, or supplied whole as a search\nrequest JSON document via --request (use \"-\" to read stdin).\n\nFlags:\n")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func searchKindSummary(kind string) string {
	switch kind {
	case "subject":
		return "find the subjects that can perform an action on a resource (Section 8.4)."
	case "resource":
		return "find the resources a subject can perform an action on (Section 8.5)."
	case "action":
		return "find the actions a subject can perform on a resource (Section 8.6)."
	default:
		return ""
	}
}

// runSearchKind implements a single search kind. The action kind ignores the
// --action flag because an Action Search carries no action in its request
// (Section 8.6).
func runSearchKind(kind string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("search "+kind, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { searchKindUsage(stderr, kind, fs) }

	g := registerGlobal(fs)
	var (
		requestPath  string
		subjectType  string
		subjectID    string
		actionName   string
		resourceType string
		resourceID   string
		contextJSON  string
		pageToken    string
		limit        int
	)
	fs.StringVar(&requestPath, "request", "", "read a full search request JSON from this file, or - for stdin")
	fs.StringVar(&subjectType, "subject-type", "", "subject type (Section 5.1)")
	fs.StringVar(&subjectID, "subject-id", "", "subject id (omitted for a subject search; Section 8.4)")
	if kind != "action" {
		fs.StringVar(&actionName, "action", "", "action name (Section 5.3)")
	}
	fs.StringVar(&resourceType, "resource-type", "", "resource type (Section 5.2)")
	fs.StringVar(&resourceID, "resource-id", "", "resource id (omitted for a resource search; Section 8.5)")
	fs.StringVar(&contextJSON, "context", "", "context as an inline JSON object (Section 5.4)")
	fs.StringVar(&pageToken, "page-token", "", "opaque next_token from a prior response, to fetch the next page (Section 8.2.1)")
	fs.IntVar(&limit, "limit", 0, "maximum number of results to request (Section 8.2.1)")

	if helpRequested(args) {
		searchKindUsage(stdout, kind, fs)
		return 0
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if code, ok := validateGlobal("search "+kind, g, stderr); !ok {
		return code
	}

	var ctxObj authzen.Context
	if contextJSON != "" {
		m, err := parseJSONObject(contextJSON)
		if err != nil {
			fmt.Fprintf(stderr, "authzen search %s: parse --context JSON: %v\n", kind, err)
			return 2
		}
		ctxObj = authzen.Context(m)
	}
	var page *authzen.Page
	if pageToken != "" || limit > 0 {
		page = &authzen.Page{Token: pageToken, Limit: limit}
	}

	ctx, cancel := withTimeout(g)
	defer cancel()
	c := newClient(g)

	switch kind {
	case "subject":
		return runSearchSubject(c, ctx, stdin, stdout, stderr,
			requestPath, subjectType, actionName, resourceType, resourceID, ctxObj, page, g.json)
	case "resource":
		return runSearchResource(c, ctx, stdin, stdout, stderr,
			requestPath, subjectType, subjectID, actionName, resourceType, ctxObj, page, g.json)
	case "action":
		return runSearchAction(c, ctx, stdin, stdout, stderr,
			requestPath, subjectType, subjectID, resourceType, resourceID, ctxObj, page, g.json)
	default:
		return 2
	}
}

// searchClient is the subset of *client.Client used by the search helpers; it
// keeps their signatures small and is the smallest seam needed for testing.
type searchClient interface {
	SearchSubjects(ctx context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error)
	SearchResources(ctx context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error)
	SearchActions(ctx context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error)
}

func runSearchSubject(c searchClient, ctx context.Context, stdin io.Reader, stdout, stderr io.Writer,
	requestPath, subjectType, actionName, resourceType, resourceID string,
	ctxObj authzen.Context, page *authzen.Page, asJSON bool,
) int {
	var req authzen.SubjectSearchRequest
	if requestPath != "" {
		data, err := readRequest(requestPath, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "authzen search subject: read request: %v\n", err)
			return 1
		}
		if err := parseRequestJSON(data, &req); err != nil {
			fmt.Fprintf(stderr, "authzen search subject: parse request JSON: %v\n", err)
			return 1
		}
	} else {
		req.Subject = &authzen.Subject{Type: subjectType}
		req.Action = &authzen.Action{Name: actionName}
		req.Resource = &authzen.Resource{Type: resourceType, ID: resourceID}
		req.Context = ctxObj
		req.Page = page
	}
	resp, err := c.SearchSubjects(ctx, &req)
	if err != nil {
		fmt.Fprintf(stderr, "authzen search subject: %v\n", err)
		return 1
	}
	if asJSON {
		return emitJSON(stdout, stderr, "search subject", resp)
	}
	for _, s := range resp.Results {
		fmt.Fprintf(stdout, "%s\t%s\n", s.Type, s.ID)
	}
	printPage(stdout, pageOf(resp.Page))
	return 0
}

func runSearchResource(c searchClient, ctx context.Context, stdin io.Reader, stdout, stderr io.Writer,
	requestPath, subjectType, subjectID, actionName, resourceType string,
	ctxObj authzen.Context, page *authzen.Page, asJSON bool,
) int {
	var req authzen.ResourceSearchRequest
	if requestPath != "" {
		data, err := readRequest(requestPath, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "authzen search resource: read request: %v\n", err)
			return 1
		}
		if err := parseRequestJSON(data, &req); err != nil {
			fmt.Fprintf(stderr, "authzen search resource: parse request JSON: %v\n", err)
			return 1
		}
	} else {
		req.Subject = &authzen.Subject{Type: subjectType, ID: subjectID}
		req.Action = &authzen.Action{Name: actionName}
		req.Resource = &authzen.Resource{Type: resourceType}
		req.Context = ctxObj
		req.Page = page
	}
	resp, err := c.SearchResources(ctx, &req)
	if err != nil {
		fmt.Fprintf(stderr, "authzen search resource: %v\n", err)
		return 1
	}
	if asJSON {
		return emitJSON(stdout, stderr, "search resource", resp)
	}
	for _, r := range resp.Results {
		fmt.Fprintf(stdout, "%s\t%s\n", r.Type, r.ID)
	}
	printPage(stdout, pageOf(resp.Page))
	return 0
}

func runSearchAction(c searchClient, ctx context.Context, stdin io.Reader, stdout, stderr io.Writer,
	requestPath, subjectType, subjectID, resourceType, resourceID string,
	ctxObj authzen.Context, page *authzen.Page, asJSON bool,
) int {
	var req authzen.ActionSearchRequest
	if requestPath != "" {
		data, err := readRequest(requestPath, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "authzen search action: read request: %v\n", err)
			return 1
		}
		if err := parseRequestJSON(data, &req); err != nil {
			fmt.Fprintf(stderr, "authzen search action: parse request JSON: %v\n", err)
			return 1
		}
	} else {
		req.Subject = &authzen.Subject{Type: subjectType, ID: subjectID}
		req.Resource = &authzen.Resource{Type: resourceType, ID: resourceID}
		req.Context = ctxObj
		req.Page = page
	}
	resp, err := c.SearchActions(ctx, &req)
	if err != nil {
		fmt.Fprintf(stderr, "authzen search action: %v\n", err)
		return 1
	}
	if asJSON {
		return emitJSON(stdout, stderr, "search action", resp)
	}
	for _, a := range resp.Results {
		fmt.Fprintln(stdout, a.Name)
	}
	printPage(stdout, pageOf(resp.Page))
	return 0
}

// emitJSON prints v as raw JSON, mapping an encode failure to exit 1.
func emitJSON(stdout, stderr io.Writer, cmd string, v any) int {
	if err := printJSON(stdout, v); err != nil {
		fmt.Fprintf(stderr, "authzen %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

// pageOf returns the next-page token from a response page, or "" when there is
// no further page.
func pageOf(p *authzen.PageResponse) string {
	if p == nil {
		return ""
	}
	return p.NextToken
}

// printPage prints the next-page token line when more results are available, so
// a caller can pass it back via --page-token (Section 8.2.2).
func printPage(w io.Writer, nextToken string) {
	if nextToken != "" {
		fmt.Fprintf(w, "next-page-token: %s\n", nextToken)
	}
}
