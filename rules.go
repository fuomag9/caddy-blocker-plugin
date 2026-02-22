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

// extractClientIP returns the best-effort real client IP for the request.
// If RemoteAddr is from a trusted proxy, it walks X-Forwarded-For left-to-right
// and returns the first IP that is not itself a trusted proxy.
func (b *Blocker) extractClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)

	if b.isTrustedProxy(remoteIP) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			for _, part := range strings.Split(xff, ",") {
				ip := net.ParseIP(strings.TrimSpace(part))
				if ip != nil && !b.isTrustedProxy(ip) {
					return ip
				}
			}
		}
	}
	return remoteIP
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
