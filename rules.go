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

// parseMixedIPsAndCIDRs accepts a slice of strings where each entry is either
// a plain IP address (e.g. "127.0.0.1") or a CIDR range (e.g. "10.0.0.0/8").
// Returns separate slices of compiled CIDRs and IPs.
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

// extractClientIP returns the best-effort real client IP for the request.
// If RemoteAddr is from a trusted proxy, it walks X-Forwarded-For right-to-left
// and returns the first IP that is not itself a trusted proxy.
// Returns nil if the client IP is indeterminate (fail-open).
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
func (b *Blocker) isAllowed(ip net.IP) bool {
	return b.matchesRules(ip,
		b.allowIPs, b.allowCIDRs,
		b.AllowASNs, b.AllowCountries, b.AllowContinents,
	)
}

// isBlocked reports whether ip matches any block rule.
func (b *Blocker) isBlocked(ip net.IP) bool {
	return b.matchesRules(ip,
		b.blockIPs, b.blockCIDRs,
		b.BlockASNs, b.BlockCountries, b.BlockContinents,
	)
}

// matchesRules checks ip against compiled IP/CIDR lists, ASN numbers,
// country codes, and continent codes. Returns true on the first match.
// If a required DB reader is nil, those rule types are skipped (fail-open).
func (b *Blocker) matchesRules(
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
	if len(asns) > 0 && b.asnDB != nil {
		if record, err := b.asnDB.ASN(ip); err == nil {
			for _, asn := range asns {
				if uint(record.AutonomousSystemNumber) == asn {
					return true
				}
			}
		}
	}

	// Country / continent match (requires geoipDB)
	if (len(countries) > 0 || len(continents) > 0) && b.geoipDB != nil {
		if record, err := b.geoipDB.Country(ip); err == nil {
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
