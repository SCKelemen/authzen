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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
	"strings"

	authzen "github.com/SCKelemen/authzen"
)

// Transport-hardening defaults. All are configurable via HandlerOptions; the
// constants document the sane zero-value fallbacks applied by NewHandler.
const (
	// DefaultMaxBodyBytes caps the number of bytes a handler will read from a
	// request body before rejecting it with HTTP 413. It defends the PDP
	// against unbounded, pre-authentication request bodies (a DoS vector).
	// Override with WithMaxBodyBytes.
	DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

	// DefaultMaxBatchSize caps the number of member evaluations accepted by the
	// Access Evaluations (batch) API before fan-out. A request exceeding it is
	// rejected with HTTP 400, bounding the work a single request can schedule.
	// Override with WithMaxBatchSize.
	DefaultMaxBatchSize = 1000

	// maxRequestIDLen caps the length of a client-supplied X-Request-ID that the
	// PDP will echo (Section 10.1.3). Combined with charset filtering this
	// prevents header-reflection abuse (oversized values, header/response
	// splitting via control characters).
	maxRequestIDLen = 128
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
// Error hygiene: the per-member "error" object NEVER carries the raw backend
// error message by default, since that can leak internal detail to the caller
// (the same risk addressed for top-level HTTP 500s). Instead it carries a
// generic message and a correlation id, while the full detail is logged
// server-side against that id via the configured slog logger. Pass
// WithBatchVerboseErrors(true) (wired from the handler's WithVerboseErrors) to
// include the real message in the response - intended only for trusted/debug
// environments. Configure the logger with WithBatchErrorLogger; when unset it
// defaults to slog.Default().
//
// A genuine request-wide failure (a cancelled or expired context) is returned
// as a non-nil error, which the handler maps to HTTP 500; that is the only
// condition that fails the entire request.
//
// OpenID AuthZEN Authorization API 1.0, Section 7 (Access Evaluations API) and
// Section 7.2.1 (Errors in batch).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-api
func EvaluateBatch(ctx context.Context, pdp PDP, req *authzen.EvaluationsRequest, opts ...BatchOption) (*authzen.EvaluationsResponse, error) {
	cfg := batchConfig{logger: slog.Default()}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}

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
			// decision with a REDACTED error in the item's context (Section
			// 7.2.1) and keep evaluating the remaining members. The full detail
			// is logged server-side against the correlation id; only a generic
			// message (or, when verbose, the real one) reaches the caller.
			resp = &authzen.EvaluationResponse{
				Decision: false,
				Context: map[string]any{
					"error": cfg.memberError(i, err),
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

// genericMemberErrorMessage is the redacted message placed in a batch member's
// error context when its backend evaluation fails. It intentionally reveals
// nothing about the underlying cause; the detail is logged server-side.
const genericMemberErrorMessage = "internal error evaluating this request"

// batchConfig controls per-member error redaction in EvaluateBatch. Its zero
// value (after normalization) logs to slog.Default() and redacts member errors.
type batchConfig struct {
	logger        *slog.Logger
	verboseErrors bool
}

// BatchOption configures EvaluateBatch, primarily its per-member error hygiene.
type BatchOption func(*batchConfig)

// WithBatchErrorLogger sets the slog.Logger used to record the full detail of a
// per-member backend error (against the correlation id surfaced to the caller).
// A nil logger resets to slog.Default(). The handler wires its own logger here
// so batch and top-level errors land in the same place.
func WithBatchErrorLogger(l *slog.Logger) BatchOption {
	return func(c *batchConfig) { c.logger = l }
}

// WithBatchVerboseErrors controls whether a per-member error context carries the
// real backend error message. It defaults to false (the message is redacted to a
// generic string plus a correlation id). Enable it only in trusted/debug
// environments; the handler wires this from WithVerboseErrors.
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2.1 (Errors in batch).
// https://openid.net/specs/authorization-api-1_0.html
func WithBatchVerboseErrors(enabled bool) BatchOption {
	return func(c *batchConfig) { c.verboseErrors = enabled }
}

// memberError builds the redacted EvaluationError for a failed batch member. It
// generates a correlation id, logs the full error against it, and returns a
// generic (or, when verbose, the real) message that always carries the
// correlation id so an operator can find the matching log line.
func (c batchConfig) memberError(index int, err error) authzen.EvaluationError {
	cid := newCorrelationID()
	c.logger.Error("AuthZEN batch member error",
		slog.Int("member_index", index),
		slog.String("error", err.Error()),
		slog.String("correlation_id", cid),
	)
	message := genericMemberErrorMessage
	if c.verboseErrors {
		message = err.Error()
	}
	return authzen.EvaluationError{
		Status:  http.StatusInternalServerError,
		Message: fmt.Sprintf("%s (correlation id: %s)", message, cid),
	}
}

// Handler is an http.Handler that serves the AuthZEN APIs for a PDP. Build one
// with NewHandler.
type Handler struct {
	pdp      PDP
	metadata *authzen.Metadata
	mux      *http.ServeMux
	// handler is the request-serving chain (recovery middleware wrapping mux).
	handler http.Handler

	evaluationPath     string
	evaluationsPath    string
	searchSubjectPath  string
	searchResourcePath string
	searchActionPath   string

	// maxBodyBytes is the per-request body cap (HTTP 413 when exceeded). A
	// non-positive value is normalized to DefaultMaxBodyBytes by NewHandler.
	maxBodyBytes int64
	// maxBatchSize is the cap on batch members (HTTP 400 when exceeded). A
	// non-positive value is normalized to DefaultMaxBatchSize by NewHandler.
	maxBatchSize int
	// verboseErrors, when true, returns the underlying error detail to the
	// client instead of a generic message. Default OFF to avoid leaking
	// backend internals (Section 10.1.2). Server-side logging is unaffected.
	verboseErrors bool
	// logger records server-side error/panic detail. Never nil after
	// NewHandler (defaults to slog.Default()).
	logger *slog.Logger
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

// WithMaxBodyBytes overrides the per-request body cap enforced by every
// body-reading handler. A request whose body exceeds the cap is rejected with
// HTTP 413 (Payload Too Large) before the PDP is invoked. A non-positive value
// resets the cap to DefaultMaxBodyBytes.
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *Handler) { h.maxBodyBytes = n }
}

// WithMaxBatchSize overrides the cap on the number of member evaluations
// accepted by the Access Evaluations (batch) API. A request exceeding the cap
// is rejected with HTTP 400 before any fan-out. A non-positive value resets the
// cap to DefaultMaxBatchSize.
//
// OpenID AuthZEN Authorization API 1.0, Section 7 (Access Evaluations API).
// https://openid.net/specs/authorization-api-1_0.html#name-access-evaluations-api
func WithMaxBatchSize(n int) HandlerOption {
	return func(h *Handler) { h.maxBatchSize = n }
}

// WithVerboseErrors controls whether client-facing error bodies carry the
// underlying error detail. It defaults to false: clients receive a generic
// message while the detail is logged server-side with a correlation id. Enable
// it only in trusted/debug environments (Section 10.1.2).
func WithVerboseErrors(enabled bool) HandlerOption {
	return func(h *Handler) { h.verboseErrors = enabled }
}

// WithErrorLogger sets the slog.Logger used to record server-side error and
// panic detail. A nil logger resets to slog.Default().
func WithErrorLogger(l *slog.Logger) HandlerOption {
	return func(h *Handler) { h.logger = l }
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
		maxBodyBytes:       DefaultMaxBodyBytes,
		maxBatchSize:       DefaultMaxBatchSize,
	}
	for _, opt := range opts {
		opt(h)
	}
	// Normalize zero/negative knobs to their sane defaults so a misconfigured
	// option can never disable the safety limits.
	if h.maxBodyBytes <= 0 {
		h.maxBodyBytes = DefaultMaxBodyBytes
	}
	if h.maxBatchSize <= 0 {
		h.maxBatchSize = DefaultMaxBatchSize
	}
	if h.logger == nil {
		h.logger = slog.Default()
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
	// Wrap routing in panic-recovery middleware so a panic in the PDP or a
	// handler always fails closed to a generic 500 (never a leaked stack).
	h.handler = h.recoverMiddleware(mux)

	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

// recoverMiddleware wraps next so that any panic is recovered and converted to
// a generic HTTP 500. The panic value and stack are logged server-side with a
// correlation id; they are never sent to the client. If the wrapped handler has
// not yet written a response, a generic JSON 500 is emitted (fail closed); if a
// response was already partially written, the panic is logged and the connection
// is left for the server to tear down.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2 (Error responses): a PDP
// failure is an HTTP 500 with a JSON body and no sensitive detail.
// https://openid.net/specs/authorization-api-1_0.html#name-error-responses
func (h *Handler) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recoveryWriter{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// http.ErrAbortHandler is the documented way to abort a handler;
			// propagate it so the server can handle it as intended.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			cid := correlationID(r)
			h.logger.Error("panic recovered in AuthZEN handler",
				slog.Any("panic", rec),
				slog.String("path", r.URL.Path),
				slog.String("correlation_id", cid),
				slog.String("stack", string(debug.Stack())),
			)
			if !rw.wroteHeader {
				writeErrorWithID(w, r, http.StatusInternalServerError, "internal server error", cid)
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

// recoveryWriter tracks whether the response status line has been written so the
// recovery middleware knows whether it can still emit a clean 500.
type recoveryWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (rw *recoveryWriter) WriteHeader(code int) {
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *recoveryWriter) Write(b []byte) (int, error) {
	rw.wroteHeader = true
	return rw.ResponseWriter.Write(b)
}

// handleEvaluation serves POST /access/v1/evaluation (Section 6).
func (h *Handler) handleEvaluation(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.EvaluationRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := h.pdp.Evaluate(r.Context(), &req)
	if err != nil {
		h.writeServerError(w, r, http.StatusInternalServerError, err)
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
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	// Bound the fan-out BEFORE evaluating any member: a single request must not
	// be able to schedule unbounded work. This is a client-supplied-shape error
	// (HTTP 400), reported with a clear, non-sensitive message.
	if n := len(req.Evaluations); n > h.maxBatchSize {
		writeError(w, r, http.StatusBadRequest,
			fmt.Sprintf("batch too large: %d evaluations exceeds the maximum of %d", n, h.maxBatchSize))
		return
	}

	var (
		resp *authzen.EvaluationsResponse
		err  error
	)
	if be, ok := h.pdp.(BatchEvaluator); ok {
		resp, err = be.EvaluateBatch(r.Context(), &req)
	} else {
		// Wire the handler's logger and verbose switch so per-member errors are
		// redacted (and logged) with the same hygiene as top-level 500s.
		resp, err = EvaluateBatch(r.Context(), h.pdp, &req,
			WithBatchErrorLogger(h.logger),
			WithBatchVerboseErrors(h.verboseErrors))
	}
	if err != nil {
		h.writeServerError(w, r, http.StatusInternalServerError, err)
		return
	}
	// Ensure the server handler path never marshals a null evaluations array: an
	// empty result MUST serialize as [] (a JSON array), not null. The default
	// EvaluateBatch always returns a non-nil slice; a custom BatchEvaluator might
	// not, so normalize here (Section 7.2). Core marshaling for nested types is
	// owned by the core package.
	if resp != nil && resp.Evaluations == nil {
		resp.Evaluations = []authzen.EvaluationResponse{}
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// handleSearchSubject serves POST /access/v1/search/subject (Section 8.4).
func (h *Handler) handleSearchSubject(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req authzen.SubjectSearchRequest
	if !h.decodeJSON(w, r, &req) {
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
		h.writeServerError(w, r, http.StatusInternalServerError, err)
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
	if !h.decodeJSON(w, r, &req) {
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
		h.writeServerError(w, r, http.StatusInternalServerError, err)
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
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := h.pdp.SearchActions(r.Context(), &req)
	if err != nil {
		h.writeServerError(w, r, http.StatusInternalServerError, err)
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
// application/json, returning false in either case.
//
// Conformance note (deliberate handling vs the spec's status-code table):
// AuthZEN defines the request binding as "POST ... Content-Type:
// application/json" (Section 10.1) but its error table (Table 2) only
// enumerates 200/400/401/403/500. We deliberately ALSO use the standard HTTP
// transport codes the table does not list:
//   - 405 Method Not Allowed for a non-POST method, and
//   - 415 Unsupported Media Type for a non-JSON Content-Type,
//
// because they are the correct, least-surprising HTTP semantics and let a PEP
// distinguish a transport mistake from an authorization decision (a deny is
// always a 200 with {"decision": false}, never a 4xx; Section 10.1.2). Both
// responses still carry the JSON {"error": ...} body shape (see errorBody).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport), Table 2
// (Status codes).
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

// decodeJSON decodes the request body into v, writing a JSON error and returning
// false on failure. The body is wrapped in an http.MaxBytesReader capped at
// h.maxBodyBytes so an unbounded (potentially pre-authentication) body cannot
// exhaust memory: exceeding the cap yields HTTP 413 (Payload Too Large). Other
// malformed input yields HTTP 400. Unknown fields are ignored for forward
// compatibility (Section 10.1.1).
//
// The 400 body is intentionally generic (it does not echo the parser's error
// text) to avoid leaking input-shape detail; the precise decode error is not
// security-sensitive but is omitted for consistency with the error-hygiene
// policy (Section 10.1.2).
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.1 (JSON Serialization).
// https://openid.net/specs/authorization-api-1_0.html#name-json-serialization
func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("request body too large: limit is %d bytes", h.maxBodyBytes))
			return false
		}
		writeError(w, r, http.StatusBadRequest, "malformed JSON request body")
		return false
	}
	return true
}

// errorBody is the JSON shape used for transport-level error responses.
//
// Conformance note (deliberate body shape): the specification's error table
// (Table 2) describes an error simply as a "Reason" string; it does not mandate
// a JSON envelope. This PDP deliberately wraps that reason in a small JSON
// object, {"error": "<reason>"}, so that EVERY response the PDP emits -
// successes and errors alike - is valid application/json and a PEP can parse it
// uniformly. The optional request_id field carries the correlation id for a
// server-side error so an operator can find the matching log line without the
// PDP leaking backend detail to the caller.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2 (Error responses), Table
// 2 (Status codes).
// https://openid.net/specs/authorization-api-1_0.html#name-error-responses
type errorBody struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// writeError writes a JSON error response with the given status code.
func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	writeJSON(w, r, status, errorBody{Error: message})
}

// writeErrorWithID writes a JSON error response carrying a correlation id, so an
// operator can tie a generic client-facing error back to the detailed
// server-side log entry.
func writeErrorWithID(w http.ResponseWriter, r *http.Request, status int, message, requestID string) {
	writeJSON(w, r, status, errorBody{Error: message, RequestID: requestID})
}

// writeServerError handles a backend/PDP failure. It NEVER returns the raw
// error to the client (an info-leak risk, especially on HTTP 500 paths).
// Instead it generates a correlation id, logs the full error detail server-side
// against that id, and returns a generic message plus the id to the client.
// When verbose errors are explicitly enabled (WithVerboseErrors), the detail is
// echoed to the client as well - intended only for trusted/debug environments.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.2 (Error responses).
// https://openid.net/specs/authorization-api-1_0.html#name-error-responses
func (h *Handler) writeServerError(w http.ResponseWriter, r *http.Request, status int, err error) {
	cid := correlationID(r)
	h.logger.Error("AuthZEN handler error",
		slog.String("error", err.Error()),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("correlation_id", cid),
	)
	message := "internal server error"
	if h.verboseErrors {
		message = err.Error()
	}
	writeErrorWithID(w, r, status, message, cid)
}

// correlationID derives a stable id for one request: it reuses a sanitized
// client-supplied X-Request-ID when present (so client and server logs line up),
// otherwise it generates a fresh random id. It never returns attacker-controlled
// raw input.
func correlationID(r *http.Request) string {
	if id := sanitizeRequestID(r.Header.Get("X-Request-ID")); id != "" {
		return id
	}
	return newCorrelationID()
}

// newCorrelationID returns a random hex correlation id, or "unknown" if the
// system RNG is unavailable (which should never happen in practice).
func newCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// sanitizeRequestID bounds an echoed, client-supplied request id (Section
// 10.1.3). It truncates to maxRequestIDLen bytes and strips every character
// outside a conservative allowlist (ASCII alphanumerics plus '-', '_', '.').
// This prevents header-reflection abuse: oversized values and response/header
// splitting via CR/LF or other control characters.
func sanitizeRequestID(id string) string {
	if id == "" {
		return ""
	}
	if len(id) > maxRequestIDLen {
		id = id[:maxRequestIDLen]
	}
	var b strings.Builder
	b.Grow(len(id))
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// writeJSON serializes v as JSON with the given status code, always setting
// Content-Type: application/json and echoing any X-Request-ID supplied by the
// PEP after sanitizing it (Section 10.1.3). The sanitized value caps length and
// charset to prevent header-reflection abuse.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1.3 (Request identification).
// https://openid.net/specs/authorization-api-1_0.html#name-request-identification
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if id := sanitizeRequestID(r.Header.Get("X-Request-ID")); id != "" {
		w.Header().Set("X-Request-ID", id)
	}
	w.WriteHeader(status)
	// A trailing error from the encoder cannot be reported once the status
	// line has been written; ignore it deliberately.
	_ = json.NewEncoder(w).Encode(v)
}

// compile-time assurance that Handler satisfies http.Handler.
var _ http.Handler = (*Handler)(nil)
