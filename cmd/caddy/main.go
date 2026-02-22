// Command caddy is a custom Caddy build that includes the blocker plugin.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Load Caddy's standard modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Load the blocker plugin (registers http.handlers.blocker via init()).
	_ "caddy-blocker-plugin"
)

func main() {
	caddycmd.Main()
}
