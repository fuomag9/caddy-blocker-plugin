// Command caddy is a custom Caddy build that includes the blocker plugin.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Load Caddy's standard modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Load caddy-l4 standard modules.
	_ "github.com/mholt/caddy-l4/layer4"

	// Load the blocker plugin (registers http.handlers.blocker
	// and layer4.matchers.blocker via init()).
	_ "github.com/fuomag9/caddy-blocker-plugin"
)

func main() {
	caddycmd.Main()
}
