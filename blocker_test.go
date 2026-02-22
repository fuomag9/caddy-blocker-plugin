package caddyblocker

import (
	"testing"
)

func TestValidate_validConfig(t *testing.T) {
	b := &Blocker{
		BlockCountries:  []string{"CN", "RU"},
		BlockContinents: []string{"AS"},
		BlockASNs:       []uint{12345},
		BlockCIDRs:      []string{"10.0.0.0/8"},
		BlockIPs:        []string{"1.2.3.4"},
		AllowIPs:        []string{"5.6.7.8"},
		ResponseStatus:  403,
	}
	if err := b.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_invalidCountryCode(t *testing.T) {
	b := &Blocker{BlockCountries: []string{"china"}}
	if err := b.Validate(); err == nil {
		t.Error("expected error for invalid country code")
	}
}

func TestValidate_invalidContinentCode(t *testing.T) {
	b := &Blocker{BlockContinents: []string{"XX"}}
	if err := b.Validate(); err == nil {
		t.Error("expected error for invalid continent code")
	}
}

func TestValidate_invalidResponseStatus(t *testing.T) {
	b := &Blocker{ResponseStatus: 99}
	if err := b.Validate(); err == nil {
		t.Error("expected error for response_status < 100")
	}
}

func TestValidate_zeroASN(t *testing.T) {
	b := &Blocker{BlockASNs: []uint{0}}
	if err := b.Validate(); err == nil {
		t.Error("expected error for ASN = 0")
	}
}

func TestValidate_invalidRedirectURL(t *testing.T) {
	b := &Blocker{RedirectURL: "not a url"}
	if err := b.Validate(); err == nil {
		t.Error("expected error for invalid redirect_url")
	}
}

func TestValidate_validRedirectURL(t *testing.T) {
	b := &Blocker{RedirectURL: "https://example.com/blocked"}
	if err := b.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
