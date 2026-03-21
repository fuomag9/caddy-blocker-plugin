package caddyblocker

import (
	"fmt"
	"net"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

var countryCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)

var validContinents = map[string]bool{
	"AF": true, "AN": true, "AS": true,
	"EU": true, "NA": true, "OC": true, "SA": true,
}

// BlockerCore holds the rule configuration and compiled state shared between
// the HTTP middleware handler (Blocker) and the L4 connection matcher (L4Blocker).
type BlockerCore struct {
	// GeoIPDBPath is the path to a MaxMind GeoLite2-Country, GeoLite2-City,
	// GeoIP2-Country, or GeoIP2-City .mmdb file. Required for block_countries
	// and block_continents / allow_countries and allow_continents rules.
	GeoIPDBPath string `json:"geoip_db,omitempty"`

	// ASNDBPath is the path to a MaxMind GeoLite2-ASN or GeoIP2-ASN .mmdb
	// file. Required for block_asns / allow_asns rules.
	ASNDBPath string `json:"asn_db,omitempty"`

	// BlockCountries lists ISO 3166-1 alpha-2 country codes whose traffic
	// should be blocked (e.g. ["CN", "RU", "KP"]).
	BlockCountries []string `json:"block_countries,omitempty"`

	// BlockContinents lists MaxMind continent codes whose traffic should be
	// blocked. Valid values: AF, AN, AS, EU, NA, OC, SA.
	BlockContinents []string `json:"block_continents,omitempty"`

	// BlockASNs lists Autonomous System Numbers whose traffic should be blocked.
	BlockASNs []uint `json:"block_asns,omitempty"`

	// BlockCIDRs lists CIDR ranges whose traffic should be blocked
	// (e.g. ["192.0.2.0/24", "2001:db8::/32"]).
	BlockCIDRs []string `json:"block_cidrs,omitempty"`

	// BlockIPs lists individual IP addresses to block.
	BlockIPs []string `json:"block_ips,omitempty"`

	// AllowCountries, AllowContinents, AllowASNs, AllowCIDRs, AllowIPs mirror
	// their Block counterparts but grant access. Allow rules are evaluated
	// before block rules — a matching allow rule always passes the request
	// through, regardless of any block rules that would otherwise match.
	AllowCountries  []string `json:"allow_countries,omitempty"`
	AllowContinents []string `json:"allow_continents,omitempty"`
	AllowASNs       []uint   `json:"allow_asns,omitempty"`
	AllowCIDRs      []string `json:"allow_cidrs,omitempty"`
	AllowIPs        []string `json:"allow_ips,omitempty"`

	// DisableLogging suppresses the INFO log entry that is emitted whenever a
	// request is blocked. Logging is enabled by default; set this to true to
	// silence block events (e.g. to reduce noise in high-traffic environments).
	DisableLogging bool `json:"disable_logging,omitempty"`

	// --- Compiled state (set by Provision, not exported) ---
	logger     *zap.Logger
	geoipDB    countryReader
	asnDB      asnReader
	blockCIDRs []*net.IPNet
	allowCIDRs []*net.IPNet
	blockIPs   []net.IP
	allowIPs   []net.IP
}

// Provision opens the MaxMind databases and pre-compiles all CIDR and IP
// strings for fast per-request matching.
func (c *BlockerCore) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger()

	if c.GeoIPDBPath != "" {
		r, err := geoip2.Open(c.GeoIPDBPath)
		if err != nil {
			c.logger.Warn("failed to open geoip_db; country/continent rules disabled",
				zap.String("path", c.GeoIPDBPath), zap.Error(err))
		} else {
			c.geoipDB = r
		}
	}

	if c.ASNDBPath != "" {
		r, err := geoip2.Open(c.ASNDBPath)
		if err != nil {
			c.logger.Warn("failed to open asn_db; ASN rules disabled",
				zap.String("path", c.ASNDBPath), zap.Error(err))
		} else {
			c.asnDB = r
		}
	}

	var err error
	c.blockCIDRs, c.blockIPs, err = compileCIDRsAndIPs(c.BlockCIDRs, c.BlockIPs)
	if err != nil {
		return fmt.Errorf("block rules: %w", err)
	}
	c.allowCIDRs, c.allowIPs, err = compileCIDRsAndIPs(c.AllowCIDRs, c.AllowIPs)
	if err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}

	return nil
}

// Validate checks rule config values for correctness.
func (c *BlockerCore) Validate() error {
	for _, cc := range append(c.BlockCountries, c.AllowCountries...) {
		if !countryCodeRe.MatchString(cc) {
			return fmt.Errorf("invalid country code %q (must be 2 uppercase letters, e.g. \"US\")", cc)
		}
	}

	for _, cc := range append(c.BlockContinents, c.AllowContinents...) {
		if !validContinents[cc] {
			return fmt.Errorf("invalid continent code %q (must be one of AF, AN, AS, EU, NA, OC, SA)", cc)
		}
	}

	for _, asn := range append(c.BlockASNs, c.AllowASNs...) {
		if asn == 0 {
			return fmt.Errorf("ASN numbers must be > 0")
		}
	}

	if _, _, err := compileCIDRsAndIPs(c.BlockCIDRs, c.BlockIPs); err != nil {
		return fmt.Errorf("block rules: %w", err)
	}
	if _, _, err := compileCIDRsAndIPs(c.AllowCIDRs, c.AllowIPs); err != nil {
		return fmt.Errorf("allow rules: %w", err)
	}

	return nil
}

// Cleanup closes the MaxMind database handles.
func (c *BlockerCore) Cleanup() error {
	if r, ok := c.geoipDB.(*geoip2.Reader); ok && r != nil {
		_ = r.Close()
	}
	if r, ok := c.asnDB.(*geoip2.Reader); ok && r != nil {
		_ = r.Close()
	}
	return nil
}
