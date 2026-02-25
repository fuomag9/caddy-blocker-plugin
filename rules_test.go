package caddyblocker

import (
	"net"
	"net/http"
	"testing"
)

func TestCompileCIDRsAndIPs_valid(t *testing.T) {
	cidrs, ips, err := compileCIDRsAndIPs(
		[]string{"10.0.0.0/8", "2001:db8::/32"},
		[]string{"1.2.3.4", "::1"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 2 {
		t.Errorf("want 2 CIDRs, got %d", len(cidrs))
	}
	if len(ips) != 2 {
		t.Errorf("want 2 IPs, got %d", len(ips))
	}
}

func TestCompileCIDRsAndIPs_invalidCIDR(t *testing.T) {
	_, _, err := compileCIDRsAndIPs([]string{"not-a-cidr"}, nil)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestCompileCIDRsAndIPs_invalidIP(t *testing.T) {
	_, _, err := compileCIDRsAndIPs(nil, []string{"not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestCompileCIDRsAndIPs_nil(t *testing.T) {
	cidrs, ips, err := compileCIDRsAndIPs(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cidrs != nil || ips != nil {
		t.Errorf("want nil slices for empty input")
	}
}

func TestCompileCIDRsAndIPs_ipv6CIDR(t *testing.T) {
	cidrs, _, err := compileCIDRsAndIPs([]string{"2001:db8::/32"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testIP := net.ParseIP("2001:db8::1")
	if !cidrs[0].Contains(testIP) {
		t.Errorf("want CIDR to contain 2001:db8::1")
	}
}

func TestExtractClientIP_directConnection(t *testing.T) {
	b := &Blocker{}
	r := &http.Request{RemoteAddr: "1.2.3.4:5678"}
	ip := b.extractClientIP(r)
	if !ip.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("want 1.2.3.4, got %v", ip)
	}
}

func TestExtractClientIP_trustedProxyXFF(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     http.Header{"X-Forwarded-For": []string{"5.6.7.8, 127.0.0.1"}},
	}
	ip := b.extractClientIP(r)
	if !ip.Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("want 5.6.7.8, got %v", ip)
	}
}

func TestExtractClientIP_trustedProxyXFF_rightToLeft(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	// A client can spoof the left side of XFF when proxies append; we must use
	// the nearest untrusted hop from the right.
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4, 9.9.9.9"}},
	}
	ip := b.extractClientIP(r)
	if !ip.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("want 9.9.9.9 from right-to-left parse, got %v", ip)
	}
}

func TestExtractClientIP_noXFFHeader(t *testing.T) {
	// Trusted proxy but no XFF header — client IP is indeterminate, return nil
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     http.Header{},
	}
	ip := b.extractClientIP(r)
	if ip != nil {
		t.Errorf("want nil for indeterminate client IP, got %v", ip)
	}
}

func TestExtractClientIP_ipv6(t *testing.T) {
	b := &Blocker{}
	r := &http.Request{RemoteAddr: "[2001:db8::1]:5678"}
	ip := b.extractClientIP(r)
	if !ip.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("want 2001:db8::1, got %v", ip)
	}
}

func TestExtractClientIP_allXFFTrusted_returnsNil(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")}

	// All XFF entries are trusted — should return nil (indeterminate)
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     http.Header{"X-Forwarded-For": []string{"10.0.0.1, 127.0.0.1"}},
	}
	ip := b.extractClientIP(r)
	if ip != nil {
		t.Errorf("want nil when all XFF entries are trusted, got %v", ip)
	}
}

func TestExtractClientIP_xffWithPort(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	// Some proxies include port in XFF — should still parse correctly
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     http.Header{"X-Forwarded-For": []string{"5.6.7.8:9999, 127.0.0.1"}},
	}
	ip := b.extractClientIP(r)
	if !ip.Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("want 5.6.7.8 (port stripped), got %v", ip)
	}
}

func TestParseMixedIPsAndCIDRs_plainIPsAndCIDRs(t *testing.T) {
	cidrs, ips, err := parseMixedIPsAndCIDRs([]string{"127.0.0.1", "10.0.0.0/8", "::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 {
		t.Errorf("want 1 CIDR, got %d", len(cidrs))
	}
	if len(ips) != 2 {
		t.Errorf("want 2 IPs, got %d", len(ips))
	}
}

func TestParseMixedIPsAndCIDRs_invalidEntry(t *testing.T) {
	_, _, err := parseMixedIPsAndCIDRs([]string{"not-valid"})
	if err == nil {
		t.Fatal("expected error for invalid entry")
	}
}

func TestMatchesRules_ipExactMatch(t *testing.T) {
	b := &Blocker{}
	b.blockIPs = []net.IP{net.ParseIP("1.2.3.4")}

	if !b.isBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("want 1.2.3.4 to be blocked")
	}
	if b.isBlocked(net.ParseIP("1.2.3.5")) {
		t.Error("want 1.2.3.5 to not be blocked")
	}
}

func TestMatchesRules_cidrMatch(t *testing.T) {
	b := &Blocker{}
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	b.blockCIDRs = []*net.IPNet{ipNet}

	if !b.isBlocked(net.ParseIP("10.5.5.5")) {
		t.Error("want 10.5.5.5 to be blocked (inside 10.0.0.0/8)")
	}
	if b.isBlocked(net.ParseIP("11.0.0.1")) {
		t.Error("want 11.0.0.1 to not be blocked")
	}
}

func TestMatchesRules_asnMatch(t *testing.T) {
	b := &Blocker{}
	b.BlockASNs = []uint{12345}
	b.asnDB = &mockASNReader{asn: 12345}

	if !b.isBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("want IP with ASN 12345 to be blocked")
	}
}

func TestMatchesRules_asnMatch_nilDB(t *testing.T) {
	b := &Blocker{}
	b.BlockASNs = []uint{12345}
	b.asnDB = nil

	if b.isBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("want fail-open when asnDB is nil")
	}
}

func TestMatchesRules_countryMatch(t *testing.T) {
	b := &Blocker{}
	b.BlockCountries = []string{"CN"}
	b.geoipDB = &mockCountryReader{isoCode: "CN"}

	if !b.isBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("want IP from CN to be blocked")
	}
}

func TestMatchesRules_continentMatch(t *testing.T) {
	b := &Blocker{}
	b.BlockContinents = []string{"AS"}
	b.geoipDB = &mockCountryReader{continentCode: "AS"}

	if !b.isBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("want IP from AS continent to be blocked")
	}
}

func TestMatchesRules_allowWinsOverBlock(t *testing.T) {
	b := &Blocker{}
	b.BlockASNs = []uint{12345}
	b.asnDB = &mockASNReader{asn: 12345}
	b.allowIPs = []net.IP{net.ParseIP("1.2.3.4")}

	if !b.isAllowed(net.ParseIP("1.2.3.4")) {
		t.Error("want 1.2.3.4 to be allowed")
	}
}

func TestMatchesRules_nilIP(t *testing.T) {
	b := &Blocker{}
	b.blockIPs = []net.IP{net.ParseIP("1.2.3.4")}
	if b.isBlocked(nil) {
		t.Error("nil IP should not match any rule")
	}
}

func TestMatchesRules_ipv6Match(t *testing.T) {
	b := &Blocker{}
	b.blockIPs = []net.IP{net.ParseIP("2001:db8::1")}
	if !b.isBlocked(net.ParseIP("2001:db8::1")) {
		t.Error("want IPv6 address to be blocked")
	}
}
