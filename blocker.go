package caddyblocker

import (
	"net"

	"go.uber.org/zap"
)

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
