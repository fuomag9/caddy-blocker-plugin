package caddyblocker

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// countryReader can look up country and continent information for an IP.
// *geoip2.Reader satisfies this interface.
type countryReader interface {
	Country(ip net.IP) (*geoip2.Country, error)
}

// asnReader can look up ASN information for an IP.
// *geoip2.Reader satisfies this interface.
type asnReader interface {
	ASN(ip net.IP) (*geoip2.ASN, error)
}
