package caddyblocker

import (
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Blocker{})
}

// Blocker is a Caddy HTTP middleware that blocks or allows requests based on
// IP address, CIDR range, ASN, country, and continent. Allow rules always take
// precedence over block rules, enabling fine-grained exceptions (e.g. block an
// entire country but whitelist specific IPs from it).
//
// Geo and ASN lookups require MaxMind GeoLite2/GeoIP2 .mmdb database files.
// If a database is missing or unreadable, the corresponding rule types are
// silently skipped (fail-open) and all other rules continue to apply.
type Blocker struct {
	BlockerCore

	// TrustedProxies lists IPs or CIDRs of trusted reverse proxies
	// (e.g. ["127.0.0.1", "10.0.0.0/8"]). When the direct connection arrives
	// from a trusted proxy, the real client IP is resolved from
	// X-Forwarded-For by walking the header right-to-left and returning the
	// first hop not in this list. Both plain IPs and CIDR notation are accepted.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// FailClosed controls behaviour when the real client IP cannot be
	// determined (e.g. the connection is from a trusted proxy but
	// X-Forwarded-For contains no usable non-proxy address).
	//
	// false (default): the request is passed through (fail-open).
	// true:            the request is blocked with the configured block response.
	//
	// Set this to true in high-security environments where an indeterminate
	// client IP should never be allowed through.
	FailClosed bool `json:"fail_closed,omitempty"`

	// ResponseStatus is the HTTP status code returned to blocked clients.
	// Defaults to 403 if unset. Ignored when redirect_url is set.
	ResponseStatus int `json:"response_status,omitempty"`

	// ResponseBody is the response body returned to blocked clients.
	// Defaults to "Forbidden" if unset. Ignored when redirect_url is set.
	ResponseBody string `json:"response_body,omitempty"`

	// ResponseHeaders are extra HTTP headers added to block responses
	// (e.g. {"Content-Type": "text/html; charset=utf-8"}).
	// Ignored when redirect_url is set.
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// RedirectURL, when set, causes blocked requests to receive a 302
	// redirect to this URL instead of the status/body/headers response.
	RedirectURL string `json:"redirect_url,omitempty"`

	// --- Compiled HTTP-specific state (set by Provision, not exported) ---
	trustedCIDRs []*net.IPNet
	trustedIPs   []net.IP
}

// CaddyModule returns the Caddy module information.
func (Blocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.blocker",
		New: func() caddy.Module { return new(Blocker) },
	}
}

// Provision implements caddy.Provisioner. It opens the MaxMind databases and
// pre-compiles all CIDR and IP strings for fast per-request matching.
func (b *Blocker) Provision(ctx caddy.Context) error {
	if err := b.BlockerCore.Provision(ctx); err != nil {
		return err
	}

	var err error
	b.trustedCIDRs, b.trustedIPs, err = parseMixedIPsAndCIDRs(b.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}

	return nil
}

// Validate implements caddy.Validator. It checks config values for correctness.
func (b *Blocker) Validate() error {
	if err := b.BlockerCore.Validate(); err != nil {
		return err
	}

	if b.RedirectURL != "" {
		if _, err := url.ParseRequestURI(b.RedirectURL); err != nil {
			return fmt.Errorf("invalid redirect_url %q: %w", b.RedirectURL, err)
		}
	}

	if b.ResponseStatus != 0 && (b.ResponseStatus < 100 || b.ResponseStatus > 599) {
		return fmt.Errorf("response_status must be 100-599, got %d", b.ResponseStatus)
	}

	if _, _, err := parseMixedIPsAndCIDRs(b.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. Evaluation order:
//
//  1. Extract the real client IP (respecting trusted_proxies / X-Forwarded-For).
//  2. If the client IP is indeterminate and fail_closed is true, block.
//  3. If any allow rule matches, pass the request to the next handler immediately.
//  4. If any block rule matches, return the configured block response.
//  5. Default: pass through.
func (b *Blocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := b.extractClientIP(r)
	if clientIP == nil && b.FailClosed {
		if !b.DisableLogging && b.logger != nil {
			b.logger.Info("request blocked",
				zap.String("plugin", "caddy-blocker"),
				zap.String("reason", "fail_closed"),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("method", r.Method),
				zap.String("uri", r.RequestURI),
			)
		}
		b.writeBlockResponse(w, r)
		return nil
	}

	if b.isAllowed(clientIP) {
		return next.ServeHTTP(w, r)
	}

	if b.isBlocked(clientIP) {
		if !b.DisableLogging && b.logger != nil {
			b.logger.Info("request blocked",
				zap.String("plugin", "caddy-blocker"),
				zap.String("reason", "block_rule"),
				zap.String("client_ip", clientIP.String()),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("method", r.Method),
				zap.String("uri", r.RequestURI),
			)
		}
		b.writeBlockResponse(w, r)
		return nil
	}

	return next.ServeHTTP(w, r)
}

// writeBlockResponse writes the configured block response to w.
// If RedirectURL is set, it issues a 302. Otherwise it writes the configured
// status code, headers, and body.
func (b *Blocker) writeBlockResponse(w http.ResponseWriter, r *http.Request) {
	if b.RedirectURL != "" {
		http.Redirect(w, r, b.RedirectURL, http.StatusFound)
		return
	}

	for k, v := range b.ResponseHeaders {
		w.Header().Set(k, v)
	}

	status := b.ResponseStatus
	if status == 0 {
		status = http.StatusForbidden
	}

	body := b.ResponseBody
	if body == "" {
		body = "Forbidden"
	}

	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

// Interface assertions — fail at compile time if Blocker breaks any contract.
var (
	_ caddy.Module                = (*Blocker)(nil)
	_ caddy.Provisioner           = (*Blocker)(nil)
	_ caddy.Validator             = (*Blocker)(nil)
	_ caddy.CleanerUpper          = (*Blocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*Blocker)(nil)
)
