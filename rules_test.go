package caddyblocker

import (
	"net"
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
