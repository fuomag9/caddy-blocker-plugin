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

func TestExtractClientIP_noXFFHeader(t *testing.T) {
	b := &Blocker{}
	b.trustedIPs = []net.IP{net.ParseIP("127.0.0.1")}

	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     http.Header{},
	}
	ip := b.extractClientIP(r)
	if !ip.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("want 127.0.0.1, got %v", ip)
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
