// Package server implements a Policy Decision Point (PDP) for the OpenID
// AuthZEN Authorization API 1.0 over the normative HTTPS + JSON binding.
//
// Users supply a PDP implementation (the decision logic) and obtain an
// http.Handler from NewHandler that wires the standard routes: the Access
// Evaluation API (Section 6), the Access Evaluations / batch API (Section 7),
// the Subject, Resource, and Action Search APIs (Section 8), and the well-known
// metadata document (Section 9). The handler enforces the transport rules of
// Section 10.1: POST with Content-Type application/json, HTTP 200 with a JSON
// body on success, and the documented status codes on error. A deny is a
// successful HTTP 200 with {"decision": false}; it is never an HTTP error
// (Section 10.1.2).
//
// OpenID AuthZEN Authorization API 1.0, Section 10 (Transport).
// https://openid.net/specs/authorization-api-1_0.html#name-transport
package server

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"

	authzen "github.com/SCKelemen/authzen"
)

// PDP is the decision logic a user implements. The handler adapts these methods
// to the HTTPS + JSON binding. Implementations receive requests that have
// already passed the package's structural validation (the REQUIRED fields are
// present), and return the corresponding response or a non-nil error. A returned
// error is mapped to HTTP 500; to deny access, return a response with
// Decision == false and HTTP 200 (Section 10.1.2), not an error.
//
// Batch evaluation is optional: an implementation that also satisfies
// BatchEvaluator handles /access/v1/evaluations itself; otherwise the handler
// derives the batch result by looping Evaluate via EvaluateBatch, honoring the
// requested evaluations_semantic.
//
// OpenID AuthZEN Authorization API 1.0, Section 6, Section 8.
// https://openid.net/specs/authorization-api-1_0.html
type PDP interface {
	// Evaluate decides a single Access Evaluation request (Section 6).
	Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)
	// SearchSubjects answers a Subject Search (Section 8.4).
	SearchSubjects(ctx context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error)
	// SearchResources answers a Resource Search (Section 8.5).
	SearchResources(ctx context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error)
	// SearchActions answers an Action Search (Section 8.6).
	SearchActions(ctx context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error)
}

// BatchEvaluator is an optional interface a PDP may implement to handle the
// Access Evaluations (batch) API directly, for example to evaluate members in
// parallel. When a PDP does not implement it, the handler falls back to
// EvaluateBatch.
//
// OpenID AuthZEN Authorization API 1.0, Section 7 (Access Evaluations API).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-api
type BatchEvaluator interface {
	EvaluateBatch(ctx context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error)
}

// EvaluateBatch is the default Access Evaluations implementation. It resolves
// the top-level subject/action/resource/context defaults onto each member
// (Section 7.1.1), then evaluates them one at a time honoring the requested
// evaluations_semantic (Section 7.1.2.1):
//
//   - execute_all (default): evaluate every member and return all decisions in
//     request order;
//   - deny_on_first_deny: stop at and include the first deny (logical AND);
//   - permit_on_first_permit: stop at and include the first permit (logical OR).
//
// Per-evaluation resilience (Section 7.2.1): a backend error from a single
// member does NOT fail the whole boxcar. The offending member is given a
// fail-safe closed decision (decision=false) with the error surfaced in that
// item's response context under the "error" key ({status, message}), and the
// remaining members still evaluate. For deny_on_first_deny an errored member is
// a deny and therefore short-circuits; for permit_on_first_permit it is not a
// permit and evaluation continues. Decisions default closed (Section 5.5).
//
// A genuine request-wide failure (a cancelled or expired context) is returned
// as a non-nil error, which the handler maps to HTTP 500; that is the only
// condition that fails the entire request.
//
// OpenID AuthZEN Authorization API 1.0, Section 7 (Access Evaluations API) and
// Section 7.2.1 (Errors in batch).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-api
func EvaluateBatch(ctx context.Context, pdp PDP, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	semantic := authzen.SemanticExecuteAll
	if req.Options != nil && req.Options.EvaluationsSemantic != "" {
		semantic = req.Options.EvaluationsSemantic
	}

	resolved := req.Resolved()
	out := make([]authzen.EvaluationResponse, 0, len(resolved))
	for i := range resolved {
		resp, err := pdp.Evaluate(ctx, &resolved[i])
		if err != nil {
			// A cancelled/expired context is a genuine request-wide failure:
			// abort the whole batch so the handler can return HTTP 500.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			// Otherwise this is a per-member failure. Record a fail-safe closed
			// decision with the error in the item's context (Section 7.2.1) and
			// keep evaluating the remaining members.
			resp = &authzen.EvaluationResponse{
				Decision: false,
				Context: map[string]any{
					"error": authzen.EvaluationError{
						Status:  http.StatusInternalServerError,
						Message: err.Error(),
					},
				},
			}
		}
		out = append(out, *resp)

		switch semantic {
		case authzen.SemanticDenyOnFirstDeny:
			if !resp.Decision {
				return &authzen.EvaluationsResponse{Evaluations: out}, nil
			}
		case authzen.SemanticPermitOnFirstPermit:
			if resp.Decision {
				return &authzen.EvaluationsResponse{Evaluations: out}, nil
			}
		}
	}
	return &authzen.EvaluationsResponse{Evaluations: out}, nil
}

// Handler is an http.Handler that serves the AuthZEN APIs for a PDP. Build one
// with NewHandler.
type Handler struct {
	pdp      PDP
	metadata *authzen.Metadata
	mux      *http.ServeMux

	evaluationPath     string
	evaluationsPath    string
	searchSubjectPath  string
	searchResourcePath string
	searchActionPath   string
}

// HandlerOption configures a Handler built with NewHandler.
type HandlerOption func(*Handler)

// WithMetadata configures the document served at
// /.well-known/authzen-configuration. When no metadata is configured the
// well-known endpoint responds 404, signaling that discovery is unsupported.
//
// OpenID AuthZEN Authorization API 1.0, Section 9 (Metadata).
// https://openid.net/specs/authorization-api-1_0.html#name-metadata
func WithMetadata(md *authzen.Metadata) HandlerOption {
	return func(h *Handler) { h.metadata = md }
}

// WithEvaluationPath overrides the Access Evaluation route (default
// /access/v1/evaluation).
func WithEvaluationPath(p string) HandlerOption {
	return func(h *Handler) { h.evaluationPath = p }
}

// WithEvaluationsPath overrides the Access Evaluations route (default
// /access/v1/evaluations).
func WithEvaluationsPath(p string) HandlerOption {
	return func(h *Handler) { h.evaluationsPath = p }
}

// WithSearchSubjectPath overrides the Subject Search route (default
// /access/v1/search/subject).
func WithSearchSubjectPath(p string) HandlerOption {
	return func(h *Handler) { h.searchSubjectPath = p }
}

// WithSearchResourcePath overrides the Resource Search route (default
// /access/v1/search/resource).
func WithSearchResourcePath(p string) HandlerOption {
	return func(h *Handler) { h.searchResourcePath = p }
}

// WithSearchActionPath overrides the Action Search route (default
// /access/v1/search/action).
func WithSearchActionPath(p string) HandlerOption {
	return func(h *Handler) { h.searchActionPath = p }
}

// NewHandler builds an http.Handler serving the AuthZEN APIs for pdp. Routing
// uses net/http.ServeMux. Each API path is matched regardless of method so the
// handler can return JSON errors with correct status codes (405 for the wrong
// method, 415 for the wrong media type, ...); a catch-all route returns a JSON
// 404 for unknown paths.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport), Table 1.
// https://openid.net/specs/authorization-api-1_0.html#name-transport
func NewHandler(pdp PDP, opts ...HandlerOption) *Handler {
	h := &Handler{
		pdp:                pdp,
		evaluationPath:     authzen.DefaultEvaluationPath,
		evaluationsPath:    authzen.DefaultEvaluationsPath,
		searchSubjectPath:  authzen.DefaultSearchSubjectPath,
		searchResourcePath: authzen.DefaultSearchResourcePath,
		searchActionPath:   authzen.DefaultSearchActionPath,
	}
	for _, opt := range opts {
		opt(h)
	}

	mux := http.NewServeMux()
	// Patterns are registered without a method so the handler controls the
	// 405/415 responses and their JSON bodies. More specific patterns take
	// precedence over the "/" catch-all (Go 1.22 ServeMux precedence rules).
	mux.HandleFunc(h.evaluationPath, h.handleEvaluation)
	mux.HandleFunc(h.evaluationsPath, h.handleEvaluations)
	mux.HandleFunc(h.searchSubjectPath, h.handleSearchSubject)
	mux.HandleFunc(h.searchResourcePath, h.handleSearchResource)
	mux.HandleFunc(h.searchActionPath, h.handleSearchAction)
	mux.HandleFunc(authzen.WellKnownConfigurationPath, h.handleMetadata)
	mux.HandleFunc("/", h.handleNotFound)
	h.mux = mux

	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// handleEvaluation serves POST /access/v1/evaluation (Section 6).
func (h *Handler) handleEvaluation(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.EvaluationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := h.pdp.Evaluate(r.Context(), &req)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// handleEvaluations serves POST /access/v1/evaluations (Section 7). It delegates
// to a BatchEvaluator PDP when available, otherwise to the default EvaluateBatch
// loop.
func (h *Handler) handleEvaluations(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.EvaluationsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	var (
		resp *authzen.EvaluationsResponse
		err  error
	)
	if be, ok := h.pdp.(BatchEvaluator); ok {
		resp, err = be.EvaluateBatch(r.Context(), &req)
	} else {
		resp, err = EvaluateBatch(r.Context(), h.pdp, &req)
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// handleSearchSubject serves POST /access/v1/search/subject (Section 8.4).
func (h *Handler) handleSearchSubject(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.SubjectSearchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	// The searched subject carries a type only; any supplied id MUST be ignored
	// (Section 8.4). Strip it before handing the request to the PDP.
	if req.Subject != nil {
		req.Subject.ID = ""
	}
	resp, err := h.pdp.SearchSubjects(r.Context(), &req)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// handleSearchResource serves POST /access/v1/search/resource (Section 8.5).
func (h *Handler) handleSearchResource(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.ResourceSearchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	// The searched resource carries a type only; any supplied id MUST be ignored
	// (Section 8.5). Strip it before handing the request to the PDP.
	if req.Resource != nil {
		req.Resource.ID = ""
	}
	resp, err := h.pdp.SearchResources(r.Context(), &req)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// handleSearchAction serves POST /access/v1/search/action (Section 8.6).
func (h *Handler) handleSearchAction(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.ActionSearchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := h.pdp.SearchActions(r.Context(), &req)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// handleMetadata serves GET /.well-known/authzen-configuration (Section 9.2).
func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed: metadata requires GET")
		return
	}
	if h.metadata == nil {
		writeError(w, r, http.StatusNotFound, "metadata not configured")
		return
	}
	writeJSON(w, r, http.StatusOK, h.metadata)
}

// handleNotFound serves the JSON 404 for unmatched paths.
func (h *Handler) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "unknown endpoint: "+r.URL.Path)
}

// requirePost enforces that an API request uses POST with a JSON body. It writes
// a 405 for any other method and a 415 when the Content-Type is not
// application/json, returning false in either case (Section 10.1).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport).
// https://openid.net/specs/authorization-api-1_0.html#name-transport
func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed: this endpoint requires POST")
		return false
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported media type: Content-Type must be application/json")
		return false
	}
	return true
}

// isJSONContentType reports whether the Content-Type header denotes
// application/json (ignoring any parameters such as charset).
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "application/json"
}

// decodeJSON decodes the request body into v, writing a 400 JSON error and
// returning false on malformed input. Unknown fields are ignored for forward
// compatibility (Section 10.1.1).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html#name-json-serialization
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeError(w, r, http.StatusBadRequest, "malformed JSON request body: "+err.Error())
		return false
	}
	return true
}

// errorBody is the JSON shape used for transport-level error responses. The
// specification describes the error body as a message string (Table 2); this
// PDP wraps that message in a small JSON object so that every response,
// including errors, is application/json.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2 (Error responses).
// https://openid.net/specs/authorization-api-1_0.html#name-error-responses
type errorBody struct {
	Error string `json:"error"`
}

// writeError writes a JSON error response with the given status code.
func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	writeJSON(w, r, status, errorBody{Error: message})
}

// writeJSON serializes v as JSON with the given status code, always setting
// Content-Type: application/json and echoing any X-Request-ID supplied by the
// PEP (Section 10.1.3).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.3 (Request identification).
// https://openid.net/specs/authorization-api-1_0.html#name-request-identification
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if id := r.Header.Get("X-Request-ID"); id != "" {
		w.Header().Set("X-Request-ID", id)
	}
	w.WriteHeader(status)
	// A trailing error from the encoder cannot be reported once the status
	// line has been written; ignore it deliberately.
	_ = json.NewEncoder(w).Encode(v)
}

// compile-time assurance that Handler satisfies http.Handler.
var _ http.Handler = (*Handler)(nil)
