package approval

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	authzen "github.com/SCKelemen/authzen"
)

// PollPattern is the net/http (Go 1.22+) routing pattern for the approval poll
// endpoint. The {id} wildcard captures the opaque approval identifier.
//
// The path mirrors the AuthZEN evaluation endpoint family (/access/v1/...,
// Section 10.1, Table 1); polling for an asynchronous decision is an extension
// to that family.
//
// OpenID AuthZEN Authorization API 1.0, Section 10.1 (Transport / paths).
// https://openid.net/specs/authorization-api-1_0.html
const PollPattern = "GET /access/v1/approval/{id}"

// Handler serves the approval poll endpoint over net/http using only the
// standard library. It exposes GET /access/v1/approval/{id}, returning the
// current decision as an authzen.EvaluationResponse: a pending request yields a
// fail-safe deny carrying the approval object, an approved request yields a
// permit, and the other terminal states yield a deny. An unknown identifier
// yields HTTP 404.
//
// The poll model follows RFC 8628's token-endpoint polling: the client polls
// until the request is decided or expires, honoring the interval in the pending
// response.
//
// RFC 8628 Section 3.4 - Device Access Token Request (polling).
// https://www.rfc-editor.org/rfc/rfc8628#section-3.4
//
// # Security: no built-in auth or rate limiting
//
// This Handler has NO built-in authentication, authorization, or rate limiting.
// Its only access control is the unguessability of the 256-bit opaque approval
// identifier, which it treats as a bearer capability: anyone who presents a
// valid id learns that decision. Operators MUST deploy it behind authentication,
// rate limiting (to blunt id brute-forcing, despite the high entropy — RFC 8628
// Section 5.2), and TLS. Enforcement of these controls is deliberately out of
// scope for this stdlib-only handler.
type Handler struct {
	store *Store
	mux   *http.ServeMux
}

// NewHandler returns a Handler backed by store.
func NewHandler(store *Store) *Handler {
	h := &Handler{store: store, mux: http.NewServeMux()}
	h.mux.HandleFunc(PollPattern, h.servePoll)
	return h
}

// ServeHTTP implements http.Handler, dispatching to the registered routes. A
// path match with the wrong method yields 405 and a non-matching path yields
// 404, both supplied by the underlying ServeMux.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// servePoll handles GET /access/v1/approval/{id}.
func (h *Handler) servePoll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	a, err := h.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "approval not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// While pending, advertise the minimum poll interval to the client via the
	// Retry-After header, mirroring RFC 8628's interval guidance so a PEP can
	// back off without parsing the body.
	//
	// RFC 8628 Section 3.5 - Device Access Token Response (interval / slow_down).
	// https://www.rfc-editor.org/rfc/rfc8628#section-3.5
	if a.Status == StatusPending && a.Interval > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(a.Interval))
	}
	writeJSON(w, http.StatusOK, Response(a))
}

// writeJSON writes v as an application/json response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// A poll response reflects an authorization decision (a capability state)
	// and must not be cached by clients or intermediaries. Set both the HTTP/1.1
	// directive and the legacy HTTP/1.0 header for older intermediaries.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error object using the AuthZEN EvaluationError helper
// shape (status + message).
//
// OpenID AuthZEN Authorization API 1.0, Section 7.2.1 (error object).
// https://openid.net/specs/authorization-api-1_0.html
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, authzen.EvaluationError{Status: status, Message: msg})
}
