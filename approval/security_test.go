package approval

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestCreateIDEntropy asserts that a minted approval_id decodes to exactly
// idEntropyBytes (256 bits) of base64url data, so a regression that weakens the
// entropy budget fails here. The unguessability of the poll handle is the only
// thing protecting a pending decision from being polled/forged by a third
// party.
//
// RFC 8628 Section 5.2 - Device Code Brute Forcing (high-entropy device_code).
// https://www.rfc-editor.org/rfc/rfc8628#section-5.2
func TestCreateIDEntropy(t *testing.T) {
	s := NewStore()
	created, err := s.Create(NewPending(&RequestRef{Type: "payment"}))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(created.ID)
	if err != nil {
		t.Fatalf("approval_id is not valid base64url (%q): %v", created.ID, err)
	}
	if len(raw) != idEntropyBytes {
		t.Fatalf("approval_id entropy = %d bytes, want %d (256-bit)", len(raw), idEntropyBytes)
	}
	if idEntropyBytes*8 != 256 {
		t.Fatalf("idEntropyBytes = %d, want 32 (256-bit)", idEntropyBytes)
	}
}

// TestCreateIDsAreUnique is a light sanity check that the entropy source is
// actually being read per-create (no constant/collision regression).
func TestCreateIDsAreUnique(t *testing.T) {
	s := NewStore()
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		a, err := s.Create(NewPending(nil))
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		if _, dup := seen[a.ID]; dup {
			t.Fatalf("duplicate approval_id minted: %q", a.ID)
		}
		seen[a.ID] = struct{}{}
	}
}

// errReader is an io.Reader that always fails, used to drive the
// entropy-exhaustion path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }

// shortReader returns fewer bytes than requested then EOF, exercising the
// io.ReadFull short-read guard (a partial read must still be treated as a
// failure rather than yielding a weak identifier).
type shortReader struct{ n int }

func (r *shortReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, io.EOF
	}
	n := r.n
	if n > len(p) {
		n = len(p)
	}
	r.n -= n
	return n, nil
}

// TestCreateEntropyFailure verifies that when the RNG fails, Create returns an
// error and stores nothing (so a caller that ignores the error cannot end up
// with an un-minted, empty-ID approval). The RNG is injectable purely for this
// test; production uses crypto/rand.Reader.
func TestCreateEntropyFailure(t *testing.T) {
	cases := map[string]io.Reader{
		"read error": errReader{},
		"short read": &shortReader{n: idEntropyBytes - 1},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewStore()
			s.rand = src

			got, err := s.Create(NewPending(&RequestRef{Type: "payment"}))
			if err == nil {
				t.Fatalf("Create with failing RNG returned nil error (got %+v)", got)
			}
			if got != nil {
				t.Fatalf("Create with failing RNG returned non-nil approval: %+v", got)
			}

			// Nothing should have been recorded.
			s.mu.Lock()
			n := len(s.items)
			s.mu.Unlock()
			if n != 0 {
				t.Fatalf("store holds %d items after failed Create, want 0", n)
			}
		})
	}
}

// TestNewStoreUsesCryptoRand documents the secure default: a freshly
// constructed Store wires its entropy source to crypto/rand.Reader.
func TestNewStoreUsesCryptoRand(t *testing.T) {
	if s := NewStore(); s.rand != rand.Reader {
		t.Fatalf("NewStore rand = %v, want crypto/rand.Reader", s.rand)
	}
}

// TestNoURLDereference documents the SSRF posture: poll_url and callback_url are
// carried verbatim and are NEVER dereferenced by this package. The package adds
// no network behavior; validating these untrusted URLs is the PEP's
// responsibility. We point both fields at a live test server and drive the full
// lifecycle (Create -> Get -> Approve -> Get -> handler poll); the server must
// receive zero requests.
func TestNoURLDereference(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewStore()
	// Attacker-controlled URLs, pointing back at our observer, carried verbatim
	// through the store from creation onward.
	pending := NewPending(&RequestRef{Type: "payment", Actions: []string{"transfer"}})
	pending.PollURL = srv.URL + "/poll"
	pending.CallbackURL = srv.URL + "/callback"
	created, err := s.Create(pending)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Get(created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	if _, err := s.Approve(created.ID, "manager@example.com", &Grant{ExpiresAt: &exp}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.Get(created.ID); err != nil {
		t.Fatalf("Get after approve: %v", err)
	}

	// Drive the poll handler too, since it also echoes the stored URLs.
	h := NewHandler(s)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/v1/approval/"+created.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want 200", rec.Code)
	}

	// Also exercise the response builders, which embed the URLs in context.
	_ = PendingResponse(created)
	_ = ApprovedResponse(created)
	_ = Response(created)

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("package dereferenced an untrusted URL: observer saw %d request(s)", got)
	}
}
