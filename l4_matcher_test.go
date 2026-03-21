package caddyblocker

import (
	"net"
	"testing"

	"github.com/mholt/caddy-l4/layer4"
)

// mockConn implements net.Conn with a configurable RemoteAddr.
type mockConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr { return m.remoteAddr }
func (m *mockConn) LocalAddr() net.Addr  { return &mockAddr{network: "tcp", addr: "127.0.0.1:0"} }

type mockAddr struct {
	network string
	addr    string
}

func (a *mockAddr) Network() string { return a.network }
func (a *mockAddr) String() string  { return a.addr }

func newMockConnection(remoteAddr string) *layer4.Connection {
	conn := &mockConn{
		remoteAddr: &mockAddr{network: "tcp", addr: remoteAddr},
	}
	cx := layer4.WrapConnection(conn, []byte{}, nil)
	return cx
}

func TestL4Blocker_blockedIP(t *testing.T) {
	m := &L4Blocker{}
	m.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	cx := newMockConnection("9.9.9.9:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("want Match to return true for blocked IP")
	}
}

func TestL4Blocker_allowedIP(t *testing.T) {
	m := &L4Blocker{}
	m.blockIPs = []net.IP{net.ParseIP("1.2.3.4")}
	m.allowIPs = []net.IP{net.ParseIP("1.2.3.4")}

	cx := newMockConnection("1.2.3.4:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("want Match to return false when IP is allowed (allow wins over block)")
	}
}

func TestL4Blocker_unmatchedIP(t *testing.T) {
	m := &L4Blocker{}
	m.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	cx := newMockConnection("1.2.3.4:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("want Match to return false for unblocked IP")
	}
}

func TestL4Blocker_cidrBlock(t *testing.T) {
	m := &L4Blocker{}
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	m.blockCIDRs = []*net.IPNet{ipNet}

	cx := newMockConnection("10.5.5.5:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("want Match to return true for IP in blocked CIDR")
	}
}

func TestL4Blocker_asnBlock(t *testing.T) {
	m := &L4Blocker{}
	m.BlockASNs = []uint{12345}
	m.asnDB = &mockASNReader{asn: 12345}

	cx := newMockConnection("1.2.3.4:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("want Match to return true for IP with blocked ASN")
	}
}

func TestL4Blocker_countryBlock(t *testing.T) {
	m := &L4Blocker{}
	m.BlockCountries = []string{"CN"}
	m.geoipDB = &mockCountryReader{isoCode: "CN"}

	cx := newMockConnection("1.2.3.4:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("want Match to return true for IP from blocked country")
	}
}

func TestL4Blocker_continentBlock(t *testing.T) {
	m := &L4Blocker{}
	m.BlockContinents = []string{"AS"}
	m.geoipDB = &mockCountryReader{continentCode: "AS"}

	cx := newMockConnection("1.2.3.4:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("want Match to return true for IP from blocked continent")
	}
}

func TestL4Blocker_unparseableAddr(t *testing.T) {
	m := &L4Blocker{}
	m.blockIPs = []net.IP{net.ParseIP("9.9.9.9")}

	cx := newMockConnection("not-an-ip")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("want Match to return false for unparseable address")
	}
}

func TestL4Blocker_ipv6(t *testing.T) {
	m := &L4Blocker{}
	m.blockIPs = []net.IP{net.ParseIP("2001:db8::1")}

	cx := newMockConnection("[2001:db8::1]:5678")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("want Match to return true for blocked IPv6 address")
	}
}

func TestL4Blocker_noRules(t *testing.T) {
	m := &L4Blocker{}

	cx := newMockConnection("1.2.3.4:1234")
	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("want Match to return false when no rules configured")
	}
}
