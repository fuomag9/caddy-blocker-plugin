package caddyblocker

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// compileCIDRsAndIPs parses CIDR strings and IP strings into compiled values.
// Returns an error if any string is invalid.
func compileCIDRsAndIPs(cidrStrings []string, ipStrings []string) ([]*net.IPNet, []net.IP, error) {
	var cidrs []*net.IPNet
	var ips []net.IP

	for _, s := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		cidrs = append(cidrs, ipNet)
	}

	for _, s := range ipStrings {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address %q", s)
		}
		ips = append(ips, ip)
	}

	return cidrs, ips, nil
}

// parseMixedIPsAndCIDRs parses a slice of strings where each entry is either a
// plain IP address (e.g. "127.0.0.1") or a CIDR range (e.g. "10.0.0.0/8").
// Entries containing "/" are treated as CIDRs; all others as plain IPs.
// Used for trusted_proxies, which commonly contains a mix of both forms.
func parseMixedIPsAndCIDRs(entries []string) ([]*net.IPNet, []net.IP, error) {
	var cidrs []*net.IPNet
	var ips []net.IP

	for _, s := range entries {
		if strings.Contains(s, "/") {
			_, ipNet, err := net.ParseCIDR(s)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
			}
			cidrs = append(cidrs, ipNet)
		} else {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid IP address %q", s)
			}
			ips = append(ips, ip)
		}
	}

	return cidrs, ips, nil
}

// extractClientIP returns the real client IP for the request.
//
// If the direct connection (RemoteAddr) is not a trusted proxy, that address
// is returned as-is.
//
// When RemoteAddr is a trusted proxy, the X-Forwarded-For header is walked
// right-to-left. The rightmost entry is the one appended by the last proxy
// (which you control), making it the hardest to spoof. The first entry from
// the right that is not in trusted_proxies is the real client. This prevents
// a client from bypassing a block by prepending a spoofed IP to XFF.
//
// Returns nil when the client IP cannot be determined (e.g. the direct
// connection is a trusted proxy but XFF is absent or all its entries are also
// trusted proxies). The caller handles nil according to fail_closed.
func (b *Blocker) extractClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)

	if b.isTrustedProxy(remoteIP) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := parseForwardedIP(parts[i])
				if ip != nil && !b.isTrustedProxy(ip) {
					return ip
				}
			}
		}
		// All XFF entries were trusted proxies or no XFF header present.
		// Return nil — indeterminate client IP, caller treats as no-match (fail-open).
		return nil
	}
	return remoteIP
}

// parseForwardedIP parses a single comma-separated field from an
// X-Forwarded-For header. It trims whitespace and strips an optional port
// suffix (some proxy implementations include port numbers, e.g. "1.2.3.4:567").
// Returns nil if the field is empty or cannot be parsed as an IP address.
func parseForwardedIP(part string) net.IP {
	candidate := strings.TrimSpace(part)
	if candidate == "" {
		return nil
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return ip
	}
	if h, _, err := net.SplitHostPort(candidate); err == nil {
		return net.ParseIP(h)
	}
	return nil
}

// isTrustedProxy reports whether ip matches any entry in trustedIPs or trustedCIDRs.
func (b *Blocker) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, trusted := range b.trustedIPs {
		if trusted.Equal(ip) {
			return true
		}
	}
	for _, cidr := range b.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// isAllowed reports whether ip matches any allow rule.
// An allow match causes the request to pass immediately (bypasses block rules).
func (c *BlockerCore) isAllowed(ip net.IP) bool {
	return c.matchesRules(ip,
		c.allowIPs, c.allowCIDRs,
		c.AllowASNs, c.AllowCountries, c.AllowContinents,
	)
}

// isBlocked reports whether ip matches any block rule.
func (c *BlockerCore) isBlocked(ip net.IP) bool {
	return c.matchesRules(ip,
		c.blockIPs, c.blockCIDRs,
		c.BlockASNs, c.BlockCountries, c.BlockContinents,
	)
}

// matchesRules checks ip against compiled IP/CIDR lists, ASN numbers,
// country codes, and continent codes. Returns true on the first match.
// If a required DB reader is nil, those rule types are skipped (fail-open).
func (c *BlockerCore) matchesRules(
	ip net.IP,
	ips []net.IP,
	cidrs []*net.IPNet,
	asns []uint,
	countries []string,
	continents []string,
) bool {
	if ip == nil {
		return false
	}

	// Exact IP match
	for _, ruleIP := range ips {
		if ruleIP.Equal(ip) {
			return true
		}
	}

	// CIDR containment
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	// ASN match (requires asnDB)
	if len(asns) > 0 && c.asnDB != nil {
		if record, err := c.asnDB.ASN(ip); err == nil {
			for _, asn := range asns {
				if uint(record.AutonomousSystemNumber) == asn {
					return true
				}
			}
		}
	}

	// Country / continent match (requires geoipDB)
	if (len(countries) > 0 || len(continents) > 0) && c.geoipDB != nil {
		if record, err := c.geoipDB.Country(ip); err == nil {
			for _, country := range countries {
				if record.Country.IsoCode == country {
					return true
				}
			}
			for _, continent := range continents {
				if record.Continent.Code == continent {
					return true
				}
			}
		}
	}

	return false
}
