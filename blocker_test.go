package caddyblocker

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidate_validConfig(t *testing.T) {
	b := &Blocker{
		BlockCountries:  []string{"CN", "RU"},
		BlockContinents: []string{"AS"},
		BlockASNs:       []uint{12345},
		BlockCIDRs:      []string{"10.0.0.0/8"},
		BlockIPs:        []string{"1.2.3.4"},
		AllowIPs:        []string{"5.6.7.8"},
		ResponseStatus:  403,
	}
	if err := b.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_invalidCountryCode(t *testing.T) {
	b := &Blocker{BlockCountries: []string{"china"}}
	if err := b.Validate(); err == nil {
		t.Error("expected error for invalid country code")
	}
}

func TestValidate_invalidContinentCode(t *testing.T) {
	b := &Blocker{BlockContinents: []string{"XX"}}
	if err := b.Validate(); err == nil {
		t.Error("expected error for invalid continent code")
	}
}

func TestValidate_invalidResponseStatus(t *testing.T) {
	b := &Blocker{ResponseStatus: 99}
	if err := b.Validate(); err == nil {
		t.Error("expected error for response_status < 100")
	}
}

func TestValidate_zeroASN(t *testing.T) {
	b := &Blocker{BlockASNs: []uint{0}}
	if err := b.Validate(); err == nil {
		t.Error("expected error for ASN = 0")
	}
}

func TestValidate_invalidRedirectURL(t *testing.T) {
	b := &Blocker{RedirectURL: "not a url"}
	if err := b.Validate(); err == nil {
		t.Error("expected error for invalid redirect_url")
	}
}

func TestValidate_validRedirectURL(t *testing.T) {
	b := &Blocker{RedirectURL: "https://example.com/blocked"}
	if err := b.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// nextHandler records whether the next handler was called.
type nextHandler struct{ called bool }

func (n *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	n.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestServeHTTP_allowedIP_passesThrough(t *testing.T) {
	b := &Blocker{}
	b.allowIPs = []net.IP{net.ParseIP("1.2.3.4")}
	b.blockIPs = []net.IP{net.ParseIP("1.2.3.4")} // block also set — allow wins

	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()

	if err := b.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("want next handler to be called for allowed IP")
	}
}

func TestServeHTTP_blockedIP_returns403(t *testing.T) {
	b := &Blocker{}
	b.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	rec := httptest.NewRecorder()

	if err := b.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.called {
		t.Error("want next handler to NOT be called for blocked IP")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestServeHTTP_trustedProxySpoofedXFF_usesRightmostUntrusted(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}
	b.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 9.9.9.9")
	rec := httptest.NewRecorder()

	if err := b.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.called {
		t.Error("want next handler to NOT be called for blocked client IP from XFF")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestServeHTTP_indeterminateClientIP_failOpenByDefault(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()

	if err := b.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("want next handler called when client IP is indeterminate and fail_closed is false")
	}
}

func TestServeHTTP_indeterminateClientIP_failClosed(t *testing.T) {
	b := &Blocker{FailClosed: true}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()

	if err := b.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.called {
		t.Error("want next handler to NOT be called when client IP is indeterminate and fail_closed is true")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestServeHTTP_customStatusAndBody(t *testing.T) {
	b := &Blocker{
		ResponseStatus: 451,
		ResponseBody:   "Unavailable For Legal Reasons",
	}
	b.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	rec := httptest.NewRecorder()

	_ = b.ServeHTTP(rec, req, &nextHandler{})
	if rec.Code != 451 {
		t.Errorf("want 451, got %d", rec.Code)
	}
	if rec.Body.String() != "Unavailable For Legal Reasons" {
		t.Errorf("want custom body, got %q", rec.Body.String())
	}
}

func TestServeHTTP_customHeaders(t *testing.T) {
	b := &Blocker{
		ResponseHeaders: map[string]string{"X-Block-Reason": "ip-block"},
	}
	b.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	rec := httptest.NewRecorder()

	_ = b.ServeHTTP(rec, req, &nextHandler{})
	if rec.Header().Get("X-Block-Reason") != "ip-block" {
		t.Errorf("want X-Block-Reason header, got %q", rec.Header().Get("X-Block-Reason"))
	}
}

func TestServeHTTP_redirectURL(t *testing.T) {
	b := &Blocker{RedirectURL: "https://example.com/blocked"}
	b.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	rec := httptest.NewRecorder()

	_ = b.ServeHTTP(rec, req, &nextHandler{})
	if rec.Code != http.StatusFound {
		t.Errorf("want 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/blocked" {
		t.Errorf("want redirect Location, got %q", loc)
	}
}

func TestServeHTTP_noRules_passesThrough(t *testing.T) {
	b := &Blocker{}
	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()

	_ = b.ServeHTTP(rec, req, next)
	if !next.called {
		t.Error("want next handler called when no rules configured")
	}
}

func TestServeHTTP_asnBlockWithIPAllowException(t *testing.T) {
	b := &Blocker{}
	b.BlockASNs = []uint{12345}
	b.asnDB = &mockASNReader{asn: 12345}
	b.allowIPs = []net.IP{net.ParseIP("1.2.3.4")}

	next := &nextHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()

	_ = b.ServeHTTP(rec, req, next)
	if !next.called {
		t.Error("want allow rule to win over block_asn for 1.2.3.4")
	}
}
