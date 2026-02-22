package caddyblocker

import (
	"net"
	"testing"

	"github.com/oschwald/geoip2-golang"
)

// mockCountryReader is a test double for countryReader.
type mockCountryReader struct {
	isoCode       string
	continentCode string
	err           error
}

func (m *mockCountryReader) Country(ip net.IP) (*geoip2.Country, error) {
	if m.err != nil {
		return nil, m.err
	}
	r := &geoip2.Country{}
	r.Country.IsoCode = m.isoCode
	r.Continent.Code = m.continentCode
	return r, nil
}

// mockASNReader is a test double for asnReader.
type mockASNReader struct {
	asn uint
	err error
}

func (m *mockASNReader) ASN(ip net.IP) (*geoip2.ASN, error) {
	if m.err != nil {
		return nil, m.err
	}
	r := &geoip2.ASN{}
	r.AutonomousSystemNumber = m.asn
	return r, nil
}

func TestMockCountryReaderImplementsInterface(t *testing.T) {
	var _ countryReader = &mockCountryReader{}
}

func TestMockASNReaderImplementsInterface(t *testing.T) {
	var _ asnReader = &mockASNReader{}
}
