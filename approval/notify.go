package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Delivery modes for a resolved approval, mirroring the CIBA backchannel token
// delivery modes. "poll" requires no callback; "ping" and "push" cause the PDP
// (here, an explicitly-constructed Notifier) to POST to the client's
// CallbackURL.
//
// OpenID CIBA Core 1.0, Section 7.2 (Token Delivery Modes) and Section 10
// (Ping/Push Callback). The ping notification carries only an identifier and
// the client then fetches the result; the push notification carries the full
// result.
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
const (
	// DeliveryPoll is the default, network-free mode: the client polls the
	// status endpoint and the Notifier performs no network I/O.
	DeliveryPoll = "poll"
	// DeliveryPing causes a small notification (approval_id + status) to be
	// POSTed to CallbackURL; the client then polls for the full result.
	DeliveryPing = "ping"
	// DeliveryPush causes the full authzen.EvaluationResponse (decision plus the
	// approval context) to be POSTed to CallbackURL.
	DeliveryPush = "push"
)

// DefaultNotifyTimeout bounds a single callback POST when the Notifier uses its
// default HTTP client. It is deliberately short: a callback is a best-effort
// side channel, not a critical path.
const DefaultNotifyTimeout = 10 * time.Second

// Notifier-related sentinel errors, testable with errors.Is.
var (
	// ErrNoValidator indicates the Notifier was asked to dispatch a callback
	// but has no URL validator. The Notifier fails closed: with no validator it
	// refuses to POST to any URL.
	ErrNoValidator = errors.New("approval: notifier has no URL validator (fail-closed)")
	// ErrNoCallbackURL indicates a ping/push delivery was requested for an
	// approval that carries no callback_url.
	ErrNoCallbackURL = errors.New("approval: approval has no callback_url")
	// ErrNilApproval indicates Notify was called with a nil approval.
	ErrNilApproval = errors.New("approval: nil approval")
)

// pingNotification is the minimal body sent in DeliveryPing mode: just enough
// for the client to identify the request and learn it has resolved, after which
// it fetches the full result from the status endpoint.
//
// OpenID CIBA Core 1.0, Section 10.2 (Ping Callback) — the notification carries
// an identifier, not the tokens/result.
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
type pingNotification struct {
	ID     string `json:"approval_id"`
	Status Status `json:"status"`
}

// Notifier delivers resolved-approval callbacks to a client's CallbackURL using
// the CIBA ping/push semantics. It is an OPT-IN, explicitly-constructed
// component: the core Store and Handler never make network requests. Because it
// dereferences a client-supplied URL, it is a server-side request forgery
// (SSRF) surface and is therefore SAFE BY DEFAULT — it refuses to POST anywhere
// unless a caller-supplied Validate function approves the target URL.
//
// # Delivery contract: at-most-once, no retry
//
// Notify performs a SINGLE delivery attempt and does NOT retry. Wired to the
// Store's OnResolve hook (which itself fires at most once per approval), a
// failed callback is simply dropped — Notify returns the error to the caller but
// nothing re-sends it. Delivery is therefore at-most-once and best-effort, never
// guaranteed. A client MUST treat the poll endpoint as the source of truth and
// be able to recover the decision by polling even if no callback ever arrives;
// the callback is only an optimization to avoid waiting for the next poll.
// Callers that need stronger delivery guarantees must add their own retry,
// queueing, or reconciliation around Notify.
//
// OpenID CIBA Core 1.0, Section 7.2 / Section 10 (delivery modes, callbacks).
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
type Notifier struct {
	// HTTPClient is the client used to POST callbacks. When nil, a default
	// client with DefaultNotifyTimeout is used. The default client does NOT
	// follow redirects (a redirect to an internal address would be an SSRF
	// bypass).
	HTTPClient *http.Client
	// Validate is REQUIRED. It is called with the parsed CallbackURL before any
	// network request; a non-nil error aborts the callback with no I/O. A nil
	// Validate makes the Notifier fail closed (reject every URL): the Notifier
	// will never POST to an arbitrary URL by default. The host allow-list and
	// any further policy are the caller's responsibility; AllowList is a ready
	// made https + host allow-list implementation.
	Validate func(*url.URL) error
}

// NewNotifier returns a Notifier with the default HTTP client (see
// DefaultNotifyTimeout, no redirect following) and the supplied URL validator.
// Passing a nil validate makes the Notifier fail closed.
func NewNotifier(validate func(*url.URL) error) *Notifier {
	return &Notifier{
		HTTPClient: defaultHTTPClient(),
		Validate:   validate,
	}
}

// defaultHTTPClient builds the Notifier's default client: a bounded timeout and
// a redirect policy that refuses to follow redirects. Returning
// http.ErrUseLastResponse surfaces the 3xx response as-is, which Notify then
// treats as a non-2xx failure — so a redirect cannot be used to bounce a
// validated URL to an unvalidated (for example internal) address.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultNotifyTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// deliveryMode selects the effective delivery mode from an approval's Delivery
// list. push takes precedence over ping (it conveys strictly more), and the
// absence of either is treated as poll (no network).
func deliveryMode(delivery []string) string {
	ping := false
	for _, d := range delivery {
		switch d {
		case DeliveryPush:
			return DeliveryPush
		case DeliveryPing:
			ping = true
		}
	}
	if ping {
		return DeliveryPing
	}
	return DeliveryPoll
}

// Notify delivers a callback for a resolved approval according to its Delivery
// mode:
//
//   - poll (or no delivery mode): a no-op; no network request is made.
//   - ping: POSTs {approval_id, status} JSON to CallbackURL.
//   - push: POSTs the full authzen.EvaluationResponse to CallbackURL.
//
// It fails closed: ping/push require a non-nil Validate that approves the parsed
// CallbackURL, otherwise Notify returns an error and performs no I/O. The POST
// honors ctx (cancellation and deadlines). A non-2xx response (including any
// unfollowed redirect) is reported as an error.
//
// OpenID CIBA Core 1.0, Section 10 (Ping/Push Callback).
// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
func (n *Notifier) Notify(ctx context.Context, a *Approval) error {
	if a == nil {
		return ErrNilApproval
	}

	switch deliveryMode(a.Delivery) {
	case DeliveryPoll:
		// Poll-only: the client fetches the status itself; no network here.
		return nil
	case DeliveryPing:
		body, err := json.Marshal(pingNotification{ID: a.ID, Status: a.Status})
		if err != nil {
			return err
		}
		return n.post(ctx, a.CallbackURL, body)
	case DeliveryPush:
		body, err := json.Marshal(Response(a))
		if err != nil {
			return err
		}
		return n.post(ctx, a.CallbackURL, body)
	default:
		// Unreachable: deliveryMode only returns the three constants.
		return fmt.Errorf("approval: unsupported delivery mode")
	}
}

// post validates the raw callback URL and, only if the validator approves,
// POSTs body as application/json honoring ctx. It is the single choke point
// through which every Notifier network request must pass.
func (n *Notifier) post(ctx context.Context, rawURL string, body []byte) error {
	// Fail closed: with no validator we never dereference a client URL.
	if n.Validate == nil {
		return ErrNoValidator
	}
	if rawURL == "" {
		return ErrNoCallbackURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("approval: invalid callback_url: %w", err)
	}
	if err := n.Validate(u); err != nil {
		return fmt.Errorf("approval: callback_url rejected: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := n.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused; ignore the body.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("approval: callback returned status %d", resp.StatusCode)
	}
	return nil
}

// AllowList returns a Validate function suitable for Notifier.Validate that
// accepts only https URLs whose host is in the provided allow-list (compared
// case-insensitively). It is the recommended baseline policy: https-only blocks
// cleartext callbacks and the host allow-list blocks SSRF to arbitrary
// (including internal/metadata) hosts. An empty allow-list rejects everything.
func AllowList(hosts ...string) func(*url.URL) error {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		set[strings.ToLower(h)] = struct{}{}
	}
	return func(u *url.URL) error {
		if u == nil {
			return errors.New("approval: nil callback URL")
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return fmt.Errorf("approval: scheme %q not allowed (https required)", u.Scheme)
		}
		if _, ok := set[strings.ToLower(u.Hostname())]; !ok {
			return fmt.Errorf("approval: host %q not in allow-list", u.Hostname())
		}
		return nil
	}
}
