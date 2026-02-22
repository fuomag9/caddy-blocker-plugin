package caddyblocker

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Blocker{})
}

// Blocker is a Caddy HTTP middleware that blocks or allows requests
// based on IP, CIDR, ASN, country, and continent rules.
type Blocker struct {
	// --- Configurable fields (JSON) ---
	GeoIPDBPath     string            `json:"geoip_db,omitempty"`
	ASNDBPath       string            `json:"asn_db,omitempty"`
	BlockCountries  []string          `json:"block_countries,omitempty"`
	BlockContinents []string          `json:"block_continents,omitempty"`
	BlockASNs       []uint            `json:"block_asns,omitempty"`
	BlockCIDRs      []string          `json:"block_cidrs,omitempty"`
	BlockIPs        []string          `json:"block_ips,omitempty"`
	AllowCountries  []string          `json:"allow_countries,omitempty"`
	AllowContinents []string          `json:"allow_continents,omitempty"`
	AllowASNs       []uint            `json:"allow_asns,omitempty"`
	AllowCIDRs      []string          `json:"allow_cidrs,omitempty"`
	AllowIPs        []string          `json:"allow_ips,omitempty"`
	TrustedProxies  []string          `json:"trusted_proxies,omitempty"`
	ResponseStatus  int               `json:"response_status,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RedirectURL     string            `json:"redirect_url,omitempty"`

	// --- Compiled state (set by Provision, not exported) ---
	logger       *zap.Logger
	geoipDB      countryReader
	asnDB        asnReader
	blockCIDRs   []*net.IPNet
	allowCIDRs   []*net.IPNet
	blockIPs     []net.IP
	allowIPs     []net.IP
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
	b.logger = ctx.Logger(b)

	if b.GeoIPDBPath != "" {
		r, err := geoip2.Open(b.GeoIPDBPath)
		if err != nil {
			b.logger.Warn("failed to open geoip_db; country/continent rules disabled",
				zap.String("path", b.GeoIPDBPath), zap.Error(err))
		} else {
			b.geoipDB = r
		}
	}

	if b.ASNDBPath != "" {
		r, err := geoip2.Open(b.ASNDBPath)
		if err != nil {
			b.logger.Warn("failed to open asn_db; ASN rules disabled",
				zap.String("path", b.ASNDBPath), zap.Error(err))
		} else {
			b.asnDB = r
		}
	}

	var err error
	b.blockCIDRs, b.blockIPs, err = compileCIDRsAndIPs(b.BlockCIDRs, b.BlockIPs)
	if err != nil {
		return fmt.Errorf("block rules: %w", err)
	}
	b.allowCIDRs, b.allowIPs, err = compileCIDRsAndIPs(b.AllowCIDRs, b.AllowIPs)
	if err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}
	b.trustedCIDRs, b.trustedIPs, err = parseMixedIPsAndCIDRs(b.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}

	return nil
}

var countryCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)

var validContinents = map[string]bool{
	"AF": true, "AN": true, "AS": true,
	"EU": true, "NA": true, "OC": true, "SA": true,
}

// Validate implements caddy.Validator. It checks config values for correctness.
func (b *Blocker) Validate() error {
	if b.RedirectURL != "" {
		if _, err := url.ParseRequestURI(b.RedirectURL); err != nil {
			return fmt.Errorf("invalid redirect_url %q: %w", b.RedirectURL, err)
		}
	}

	if b.ResponseStatus != 0 && (b.ResponseStatus < 100 || b.ResponseStatus > 599) {
		return fmt.Errorf("response_status must be 100-599, got %d", b.ResponseStatus)
	}

	for _, c := range append(b.BlockCountries, b.AllowCountries...) {
		if !countryCodeRe.MatchString(c) {
			return fmt.Errorf("invalid country code %q (must be 2 uppercase letters, e.g. \"US\")", c)
		}
	}

	for _, c := range append(b.BlockContinents, b.AllowContinents...) {
		if !validContinents[c] {
			return fmt.Errorf("invalid continent code %q (must be one of AF, AN, AS, EU, NA, OC, SA)", c)
		}
	}

	for _, asn := range append(b.BlockASNs, b.AllowASNs...) {
		if asn == 0 {
			return fmt.Errorf("ASN numbers must be > 0")
		}
	}

	// Validate CIDR and IP strings in block/allow rules
	if _, _, err := compileCIDRsAndIPs(b.BlockCIDRs, b.BlockIPs); err != nil {
		return fmt.Errorf("block rules: %w", err)
	}
	if _, _, err := compileCIDRsAndIPs(b.AllowCIDRs, b.AllowIPs); err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}
	if _, _, err := parseMixedIPsAndCIDRs(b.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}

	return nil
}

// Cleanup implements caddy.CleanerUpper. It closes the MaxMind database handles.
func (b *Blocker) Cleanup() error {
	if r, ok := b.geoipDB.(*geoip2.Reader); ok && r != nil {
		_ = r.Close()
	}
	if r, ok := b.asnDB.(*geoip2.Reader); ok && r != nil {
		_ = r.Close()
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
// Allow rules take full precedence — if any allow rule matches, the request
// passes to the next handler regardless of any block rules.
func (b *Blocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := b.extractClientIP(r)

	if b.isAllowed(clientIP) {
		return next.ServeHTTP(w, r)
	}

	if b.isBlocked(clientIP) {
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
