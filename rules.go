package caddyblocker

import (
	"fmt"
	"net"
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
