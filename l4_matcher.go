package caddyblocker

import (
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(L4Blocker{})
}

// L4Blocker is a caddy-l4 connection matcher that blocks or allows connections
// based on IP address, CIDR range, ASN, country, and continent — the same
// rules as the HTTP Blocker middleware but applied at Layer 4.
//
// Match returns true when the connection's remote IP is blocked (matches a
// block rule and no allow rule), meaning the route matches and its handlers
// (e.g. "close") will execute. This follows caddy-l4 matcher conventions.
//
// Unlike the HTTP middleware, there is no X-Forwarded-For / trusted proxy
// support at Layer 4 — only the direct RemoteAddr is used.
type L4Blocker struct {
	BlockerCore
}

// CaddyModule returns the Caddy module information.
func (L4Blocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.blocker",
		New: func() caddy.Module { return new(L4Blocker) },
	}
}

// Provision implements caddy.Provisioner.
func (m *L4Blocker) Provision(ctx caddy.Context) error {
	return m.BlockerCore.Provision(ctx)
}

// Validate implements caddy.Validator.
func (m *L4Blocker) Validate() error {
	return m.BlockerCore.Validate()
}

// Match implements layer4.ConnMatcher. It returns true when the connection's
// remote IP is blocked (matches a block rule and no allow rule).
func (m *L4Blocker) Match(cx *layer4.Connection) (bool, error) {
	remote := cx.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	clientIP := net.ParseIP(host)
	if clientIP == nil {
		return false, nil
	}

	if m.isAllowed(clientIP) {
		return false, nil
	}
	if m.isBlocked(clientIP) {
		if !m.DisableLogging && m.logger != nil {
			m.logger.Info("connection blocked",
				zap.String("plugin", "caddy-blocker"),
				zap.String("reason", "block_rule"),
				zap.String("client_ip", clientIP.String()),
				zap.String("remote_addr", remote),
			)
		}
		return true, nil
	}
	return false, nil
}

// Interface assertions.
var (
	_ caddy.Module       = (*L4Blocker)(nil)
	_ caddy.Provisioner  = (*L4Blocker)(nil)
	_ caddy.Validator    = (*L4Blocker)(nil)
	_ caddy.CleanerUpper = (*L4Blocker)(nil)
	_ layer4.ConnMatcher = (*L4Blocker)(nil)
)
