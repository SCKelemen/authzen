package main

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authzen "github.com/SCKelemen/authzen"
	"github.com/SCKelemen/authzen/server"
)

// stubPDP is a minimal Policy Decision Point used to back the httptest server in
// these tests. It permits a fixed allow-list of (subject, action, resource) and
// denies everything else, and returns canned search results. A returned error
// is mapped by the server to HTTP 500, which lets us exercise the CLI's
// transport-error path.
//
// OpenID AuthZEN Authorization API 1.0, Section 6, Section 8.
// https://openid.net/specs/authorization-api-1_0.html
type stubPDP struct {
	// failEvaluate, when set, makes Evaluate return an error (HTTP 500).
	failEvaluate bool
	// failSearch, when set, makes every Search* method return an error (HTTP
	// 500), exercising the CLI search transport-error path.
	failSearch bool
	// nextToken, when non-empty, is returned as the page.next_token of every
	// search response so the CLI prints a next-page-token line (Section 8.2.2).
	nextToken string
	// cap, when non-nil, records the most recent search Page seen by the PDP so
	// a test can assert that --page-token/--limit were transmitted. It is a
	// pointer so that the by-value copy the handler holds still shares it.
	cap *capture
}

// capture records request details observed by the stub PDP across the by-value
// copy held inside the server handler.
type capture struct {
	page *authzen.Page
}

// searchPage builds the response page object from the configured nextToken.
func (p stubPDP) searchPage() *authzen.PageResponse {
	if p.nextToken == "" {
		return nil
	}
	return &authzen.PageResponse{NextToken: p.nextToken}
}

// allow reports whether the stub policy permits the request: user alice may
// can_read the todo "1".
func allow(req *authzen.EvaluationRequest) bool {
	return req.Subject != nil && req.Subject.ID == "alice@example.com" &&
		req.Action != nil && req.Action.Name == "can_read" &&
		req.Resource != nil && req.Resource.ID == "1"
}

func (p stubPDP) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if p.failEvaluate {
		return nil, errors.New("policy engine unavailable")
	}
	return &authzen.EvaluationResponse{Decision: allow(req)}, nil
}

func (p stubPDP) SearchSubjects(_ context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	if p.cap != nil {
		p.cap.page = req.Page
	}
	if p.failSearch {
		return nil, errors.New("policy engine unavailable")
	}
	return &authzen.SubjectSearchResponse{
		Page: p.searchPage(),
		Results: []authzen.Subject{
			{Type: "user", ID: "alice@example.com"},
			{Type: "user", ID: "bob@example.com"},
		},
	}, nil
}

func (p stubPDP) SearchResources(_ context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	if p.cap != nil {
		p.cap.page = req.Page
	}
	if p.failSearch {
		return nil, errors.New("policy engine unavailable")
	}
	return &authzen.ResourceSearchResponse{
		Page:    p.searchPage(),
		Results: []authzen.Resource{{Type: "todo", ID: "1"}, {Type: "todo", ID: "2"}},
	}, nil
}

func (p stubPDP) SearchActions(_ context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	if p.cap != nil {
		p.cap.page = req.Page
	}
	if p.failSearch {
		return nil, errors.New("policy engine unavailable")
	}
	return &authzen.ActionSearchResponse{
		Page:    p.searchPage(),
		Results: []authzen.Action{{Name: "can_read"}, {Name: "can_delete"}},
	}, nil
}

// newPDP returns an httptest server fronting the real server package handler
// wired to the stub PDP, plus a teardown function. The metadata document
// advertises the standard endpoints so "discover" has something to print.
//
// The metadata's policy_decision_point MUST match the origin discovery is
// derived from, or the client rejects the document (Section 9.2.3). The server
// is therefore built first and the document is then pointed at its URL, exactly
// as the server package's own round-trip test does.
func newPDP(t *testing.T, pdp stubPDP) (*httptest.Server, func()) {
	t.Helper()
	md := &authzen.Metadata{}
	srv := httptest.NewServer(server.NewHandler(pdp, server.WithMetadata(md)))
	md.PolicyDecisionPoint = srv.URL
	md.AccessEvaluationEndpoint = srv.URL + authzen.DefaultEvaluationPath
	md.AccessEvaluationsEndpoint = srv.URL + authzen.DefaultEvaluationsPath
	md.SearchSubjectEndpoint = srv.URL + authzen.DefaultSearchSubjectPath
	md.SearchResourceEndpoint = srv.URL + authzen.DefaultSearchResourcePath
	md.SearchActionEndpoint = srv.URL + authzen.DefaultSearchActionPath
	return srv, srv.Close
}

// invoke drives the CLI's run function with the given args and stdin, returning
// the exit code and the captured stdout/stderr.
func invoke(args []string, stdin string) (code int, stdout, stderr string) {
	var out, errBuf bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// TestEvaluateAllow drives an allow decision through the flag-built request.
// Spec Section 6 (Access Evaluation API); a true decision permits.
func TestEvaluateAllow(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "allow" {
		t.Fatalf("stdout = %q, want allow", got)
	}
}

// TestEvaluateDeny drives a deny decision. Spec Section 5.5: a false decision is
// still a successful HTTP 200 call, so the default exit code is 0.
func TestEvaluateDeny(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "mallory@example.com",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "deny" {
		t.Fatalf("stdout = %q, want deny", got)
	}
}

// TestEvaluateDenyExitCode verifies the --deny-exit-code scripting gate: a deny
// maps to the requested nonzero exit code, while an allow still exits 0. Spec
// Section 10.1.2 (a deny is not an HTTP error).
func TestEvaluateDenyExitCode(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	// Deny with --deny-exit-code 7 -> exit 7.
	code, stdout, _ := invoke([]string{
		"evaluate", "--url", srv.URL, "--deny-exit-code", "7",
		"--subject-type", "user", "--subject-id", "mallory@example.com",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 7 {
		t.Fatalf("deny exit = %d, want 7", code)
	}
	if got := strings.TrimSpace(stdout); got != "deny" {
		t.Fatalf("stdout = %q, want deny", got)
	}

	// Allow with --deny-exit-code 7 -> still exit 0.
	code, _, _ = invoke([]string{
		"evaluate", "--url", srv.URL, "--deny-exit-code", "7",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("allow exit = %d, want 0", code)
	}
}

// TestEvaluateJSONOutput verifies --json prints the raw EvaluationResponse.
// Spec Section 6.2 (Access Evaluation Response).
func TestEvaluateJSONOutput(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL, "--json",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, `"decision": true`) {
		t.Fatalf("stdout = %q, want decision:true JSON", stdout)
	}
}

// TestEvaluateRequestFromStdin verifies --request - reads a full
// EvaluationRequest JSON from stdin. Spec Figure 14 (full request).
func TestEvaluateRequestFromStdin(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	body := `{
      "subject":  {"type": "user", "id": "alice@example.com"},
      "action":   {"name": "can_read"},
      "resource": {"type": "todo", "id": "1"}
    }`
	code, stdout, stderr := invoke([]string{"evaluate", "--url", srv.URL, "--request", "-"}, body)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "allow" {
		t.Fatalf("stdout = %q, want allow", got)
	}
}

// TestEvaluationsBatch verifies the batch subcommand prints one decision per
// member in request order. Spec Section 7 (Access Evaluations API).
func TestEvaluationsBatch(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	// Top-level subject/action defaults; per-member resources override.
	body := `{
      "subject": {"type": "user", "id": "alice@example.com"},
      "action":  {"name": "can_read"},
      "evaluations": [
        {"resource": {"type": "todo", "id": "1"}},
        {"resource": {"type": "todo", "id": "2"}}
      ]
    }`
	code, stdout, stderr := invoke([]string{"evaluations", "--url", srv.URL, "--request", "-"}, body)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), stdout)
	}
	if !strings.HasSuffix(lines[0], "allow") || !strings.HasSuffix(lines[1], "deny") {
		t.Fatalf("decisions = %q, want [allow deny]", lines)
	}
}

// TestSearchSubject verifies the Subject Search subcommand. Spec Section 8.4
// ("who can do action on resource?").
func TestSearchSubject(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "subject", "--url", srv.URL,
		"--subject-type", "user",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "alice@example.com") || !strings.Contains(stdout, "bob@example.com") {
		t.Fatalf("stdout = %q, want both subjects", stdout)
	}
}

// TestSearchActionJSON verifies the Action Search subcommand with --json. Spec
// Section 8.6 (no action key in the request).
func TestSearchActionJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "action", "--url", srv.URL, "--json",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, `"can_read"`) || !strings.Contains(stdout, `"can_delete"`) {
		t.Fatalf("stdout = %q, want both actions", stdout)
	}
}

// TestDiscover verifies the discover subcommand fetches and prints metadata.
// Spec Section 9 (Metadata).
func TestDiscover(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{"discover", "--url", srv.URL}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "policy_decision_point:") ||
		!strings.Contains(stdout, "access_evaluation_endpoint:") {
		t.Fatalf("stdout = %q, want metadata fields", stdout)
	}
}

// TestMissingURL verifies a usage error (exit 2) with a stderr message when
// --url is omitted.
func TestMissingURL(t *testing.T) {
	code, stdout, stderr := invoke([]string{
		"evaluate",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "--url is required") {
		t.Fatalf("stderr = %q, want --url message", stderr)
	}
}

// TestBadRequestJSON verifies malformed --request JSON is a runtime error
// (exit 1) reported to stderr. Spec Section 10.1.1 (JSON serialization).
func TestBadRequestJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{"evaluate", "--url", srv.URL, "--request", "-"}, "{not json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "parse request JSON") {
		t.Fatalf("stderr = %q, want parse error", stderr)
	}
}

// TestAPIError verifies that a PDP HTTP 500 surfaces as a transport error
// (exit 1) on stderr. Spec Section 10.1.2 (error responses are non-2xx).
func TestAPIError(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{failEvaluate: true})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "authzen evaluate:") {
		t.Fatalf("stderr = %q, want evaluate error", stderr)
	}
}

// TestUnknownCommand verifies an unknown top-level command is a usage error.
func TestUnknownCommand(t *testing.T) {
	code, _, stderr := invoke([]string{"frobnicate"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Fatalf("stderr = %q, want unknown command", stderr)
	}
}

// TestRootHelp verifies the root --help prints to stdout and exits 0.
func TestRootHelp(t *testing.T) {
	code, stdout, _ := invoke([]string{"--help"}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, cmd := range []string{"evaluate", "evaluations", "search", "discover"} {
		if !strings.Contains(stdout, cmd) {
			t.Fatalf("help missing command %q:\n%s", cmd, stdout)
		}
	}
}

// TestInvalidRequestValidation verifies that a request missing a REQUIRED field
// is rejected client-side (exit 1). Spec Section 6.1 (required subject/action/
// resource). The action is omitted here.
func TestInvalidRequestValidation(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	body := `{"subject":{"type":"user","id":"alice@example.com"},"resource":{"type":"todo","id":"1"}}`
	code, _, stderr := invoke([]string{"evaluate", "--url", srv.URL, "--request", "-"}, body)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "authzen evaluate:") {
		t.Fatalf("stderr = %q, want validation error", stderr)
	}
}

// TestSearchResource verifies the Resource Search subcommand (positive). Spec
// Section 8.5 ("which resources can subject act on?").
func TestSearchResource(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "resource", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read",
		"--resource-type", "todo",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "todo\t1") || !strings.Contains(stdout, "todo\t2") {
		t.Fatalf("stdout = %q, want both resources", stdout)
	}
}

// TestSearchResourceJSON verifies the Resource Search --json output path.
func TestSearchResourceJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "resource", "--url", srv.URL, "--json",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, `"results"`) || !strings.Contains(stdout, `"todo"`) {
		t.Fatalf("stdout = %q, want results JSON", stdout)
	}
}

// TestSearchSubjectJSON verifies the Subject Search --json output path.
func TestSearchSubjectJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "subject", "--url", srv.URL, "--json",
		"--subject-type", "user", "--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, `"alice@example.com"`) {
		t.Fatalf("stdout = %q, want subject JSON", stdout)
	}
}

// TestEvaluationsJSON verifies the batch subcommand --json output path. Spec
// Section 7.2 (Access Evaluations Response).
func TestEvaluationsJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	body := `{
      "subject": {"type": "user", "id": "alice@example.com"},
      "action":  {"name": "can_read"},
      "evaluations": [
        {"resource": {"type": "todo", "id": "1"}},
        {"resource": {"type": "todo", "id": "2"}}
      ]
    }`
	code, stdout, stderr := invoke([]string{"evaluations", "--url", srv.URL, "--json", "--request", "-"}, body)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, `"evaluations"`) || !strings.Contains(stdout, `"decision"`) {
		t.Fatalf("stdout = %q, want batch JSON", stdout)
	}
}

// TestDiscoverJSON verifies the discover --json output path. Spec Section 9.
func TestDiscoverJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{"discover", "--url", srv.URL, "--json"}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, `"policy_decision_point"`) ||
		!strings.Contains(stdout, `"access_evaluation_endpoint"`) {
		t.Fatalf("stdout = %q, want metadata JSON", stdout)
	}
}

// TestSearchPaginationFlags verifies that --page-token and --limit are sent in
// the request page object and that a returned next_token is printed so it can
// be passed back. Spec Section 8.2 (pagination).
func TestSearchPaginationFlags(t *testing.T) {
	capt := &capture{}
	srv, closeFn := newPDP(t, stubPDP{nextToken: "tok-2", cap: capt})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "resource", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo",
		"--page-token", "tok-1", "--limit", "5",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if capt.page == nil {
		t.Fatalf("PDP received no page object")
	}
	if capt.page.Token != "tok-1" || capt.page.Limit != 5 {
		t.Fatalf("page = %+v, want token tok-1 limit 5", *capt.page)
	}
	if !strings.Contains(stdout, "next-page-token: tok-2") {
		t.Fatalf("stdout = %q, want next-page-token line", stdout)
	}
}

// TestEvaluateRequestFromFile verifies --request reads a full request from a
// file path (not just stdin). Spec Figure 14.
func TestEvaluateRequestFromFile(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	body := `{
      "subject":  {"type": "user", "id": "alice@example.com"},
      "action":   {"name": "can_read"},
      "resource": {"type": "todo", "id": "1"}
    }`
	path := filepath.Join(t.TempDir(), "req.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp request: %v", err)
	}
	code, stdout, stderr := invoke([]string{"evaluate", "--url", srv.URL, "--request", path}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "allow" {
		t.Fatalf("stdout = %q, want allow", got)
	}
}

// TestEvaluateWithPropertiesAndContext exercises the inline --context and
// --*-properties flag builders. Spec Sections 5.1-5.4.
func TestEvaluateWithPropertiesAndContext(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
		"--context", `{"time":"1985-10-26T01:22-07:00"}`,
		"--subject-properties", `{"department":"Sales"}`,
		"--resource-properties", `{"owner":"alice@example.com"}`,
		"--action-properties", `{"period":"2W"}`,
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "allow" {
		t.Fatalf("stdout = %q, want allow", got)
	}
}

// TestEvaluateBadContextJSON verifies that a malformed --context object is a
// usage error (exit 2) reported to stderr.
func TestEvaluateBadContextJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
		"--context", "{not json",
	}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "parse --context JSON") {
		t.Fatalf("stderr = %q, want context parse error", stderr)
	}
}

// TestEvaluateBadPropertiesJSON verifies that malformed --subject-properties is
// a usage error (exit 2).
func TestEvaluateBadPropertiesJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, _, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
		"--subject-properties", "[]",
	}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "parse --subject-properties JSON") {
		t.Fatalf("stderr = %q, want properties parse error", stderr)
	}
}

// TestEvaluateBadRequestFilePath verifies that a nonexistent --request file is
// a runtime error (exit 1) reported to stderr.
func TestEvaluateBadRequestFilePath(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	code, _, stderr := invoke([]string{"evaluate", "--url", srv.URL, "--request", missing}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "read request") {
		t.Fatalf("stderr = %q, want read error", stderr)
	}
}

// TestEvaluateInvalidEntityFlags verifies that omitting a REQUIRED entity field
// (here --subject-id) is rejected client-side (exit 1). Spec Section 5.1.
func TestEvaluateInvalidEntityFlags(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, _, stderr := invoke([]string{
		"evaluate", "--url", srv.URL,
		"--subject-type", "user",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "authzen evaluate:") {
		t.Fatalf("stderr = %q, want validation error", stderr)
	}
}

// TestEvaluateUnknownFlag verifies an unknown flag is a usage error (exit 2).
func TestEvaluateUnknownFlag(t *testing.T) {
	code, _, stderr := invoke([]string{"evaluate", "--url", "http://x", "--bogus"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stderr == "" {
		t.Fatalf("want a flag error on stderr")
	}
}

// TestSearchAPIError verifies a PDP HTTP 500 during search surfaces as a
// transport error (exit 1) on stderr. Spec Section 10.1.2.
func TestSearchAPIError(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{failSearch: true})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"search", "subject", "--url", srv.URL,
		"--subject-type", "user", "--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "authzen search subject:") {
		t.Fatalf("stderr = %q, want search error", stderr)
	}
}

// TestSearchRequestFromFile verifies search --request reads a full search
// request JSON from a file. Spec Section 8.4.
func TestSearchRequestFromFile(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	body := `{
      "subject":  {"type": "user"},
      "action":   {"name": "can_read"},
      "resource": {"type": "todo", "id": "1"}
    }`
	path := filepath.Join(t.TempDir(), "search.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp request: %v", err)
	}
	code, stdout, stderr := invoke([]string{"search", "subject", "--url", srv.URL, "--request", path}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "alice@example.com") {
		t.Fatalf("stdout = %q, want subjects", stdout)
	}
}

// TestSearchBadRequestJSON verifies malformed search --request JSON is a runtime
// error (exit 1).
func TestSearchBadRequestJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, _, stderr := invoke([]string{"search", "action", "--url", srv.URL, "--request", "-"}, "{bad")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "parse request JSON") {
		t.Fatalf("stderr = %q, want parse error", stderr)
	}
}

// TestSearchBadContextJSON verifies a malformed search --context is a usage
// error (exit 2).
func TestSearchBadContextJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, _, stderr := invoke([]string{
		"search", "action", "--url", srv.URL,
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--resource-type", "todo", "--resource-id", "1",
		"--context", "{bad",
	}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "parse --context JSON") {
		t.Fatalf("stderr = %q, want context parse error", stderr)
	}
}

// TestSearchMissingURL verifies search without --url is a usage error (exit 2).
func TestSearchMissingURL(t *testing.T) {
	code, _, stderr := invoke([]string{
		"search", "subject",
		"--subject-type", "user", "--action", "can_read",
		"--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--url is required") {
		t.Fatalf("stderr = %q, want --url message", stderr)
	}
}

// TestSearchNoKind verifies "search" with no target is a usage error (exit 2).
func TestSearchNoKind(t *testing.T) {
	code, _, stderr := invoke([]string{"search"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "requires a kind") {
		t.Fatalf("stderr = %q, want kind message", stderr)
	}
}

// TestSearchUnknownKind verifies an unknown search target is a usage error.
func TestSearchUnknownKind(t *testing.T) {
	code, _, stderr := invoke([]string{"search", "widget", "--url", "http://x"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown kind") {
		t.Fatalf("stderr = %q, want unknown kind message", stderr)
	}
}

// TestEvaluationsMissingRequest verifies the batch subcommand requires
// --request (exit 2).
func TestEvaluationsMissingRequest(t *testing.T) {
	code, _, stderr := invoke([]string{"evaluations", "--url", "http://x"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--request is required") {
		t.Fatalf("stderr = %q, want --request message", stderr)
	}
}

// TestEvaluationsMissingURL verifies the batch subcommand requires --url.
func TestEvaluationsMissingURL(t *testing.T) {
	code, _, stderr := invoke([]string{"evaluations", "--request", "-"}, "{}")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--url is required") {
		t.Fatalf("stderr = %q, want --url message", stderr)
	}
}

// TestEvaluationsBadJSON verifies malformed batch --request JSON is a runtime
// error (exit 1).
func TestEvaluationsBadJSON(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, _, stderr := invoke([]string{"evaluations", "--url", srv.URL, "--request", "-"}, "{bad")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "parse request JSON") {
		t.Fatalf("stderr = %q, want parse error", stderr)
	}
}

// TestDiscoverMissingURL verifies discover requires --url (exit 2).
func TestDiscoverMissingURL(t *testing.T) {
	code, _, stderr := invoke([]string{"discover"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--url is required") {
		t.Fatalf("stderr = %q, want --url message", stderr)
	}
}

// TestDiscoverAPIError verifies a missing metadata document (HTTP 404) is a
// transport error (exit 1) on stderr. Spec Section 9.2.
func TestDiscoverAPIError(t *testing.T) {
	// A handler with no metadata configured returns 404 at the well-known URL.
	srv := httptest.NewServer(server.NewHandler(stubPDP{}))
	defer srv.Close()

	code, stdout, stderr := invoke([]string{"discover", "--url", srv.URL}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "authzen discover:") {
		t.Fatalf("stderr = %q, want discover error", stderr)
	}
}

// TestNoArgs verifies that invoking with no arguments prints usage to stderr
// and exits 2.
func TestNoArgs(t *testing.T) {
	code, _, stderr := invoke(nil, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Fatalf("stderr = %q, want usage", stderr)
	}
}

// TestSubcommandHelp verifies that every subcommand's --help exits 0 and prints
// its usage to stdout (not stderr).
func TestSubcommandHelp(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"evaluate", []string{"evaluate", "--help"}, "authzen evaluate"},
		{"evaluations", []string{"evaluations", "--help"}, "authzen evaluations"},
		{"search-root", []string{"search", "--help"}, "authzen search"},
		{"search-subject", []string{"search", "subject", "--help"}, "authzen search subject"},
		{"search-resource", []string{"search", "resource", "--help"}, "authzen search resource"},
		{"search-action", []string{"search", "action", "--help"}, "authzen search action"},
		{"discover", []string{"discover", "--help"}, "authzen discover"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := invoke(tc.args, "")
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty (help goes to stdout)", stderr)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Fatalf("stdout = %q, want contains %q", stdout, tc.want)
			}
		})
	}
}

// TestZeroTimeout verifies that --timeout 0 (no deadline) still works.
func TestZeroTimeout(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, stdout, stderr := invoke([]string{
		"evaluate", "--url", srv.URL, "--timeout", "0",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "allow" {
		t.Fatalf("stdout = %q, want allow", got)
	}
}

// TestTokenForwarded verifies that --token is accepted and the call succeeds; a
// bearer token is RECOMMENDED by the spec (Section 11.2).
func TestTokenForwarded(t *testing.T) {
	srv, closeFn := newPDP(t, stubPDP{})
	defer closeFn()

	code, _, stderr := invoke([]string{
		"evaluate", "--url", srv.URL, "--token", "secret-token",
		"--subject-type", "user", "--subject-id", "alice@example.com",
		"--action", "can_read", "--resource-type", "todo", "--resource-id", "1",
	}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
}

// compile-time assurance that the stub satisfies the server PDP interface.
var _ server.PDP = stubPDP{}
