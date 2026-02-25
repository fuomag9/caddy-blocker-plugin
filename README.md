# caddy-blocker-plugin

A [Caddy v2](https://caddyserver.com) HTTP middleware that blocks or allows requests based on:

- **IP address** — exact match
- **CIDR range** — e.g. `10.0.0.0/8`
- **ASN** — Autonomous System Number via MaxMind database
- **Country** — ISO 3166-1 alpha-2 code via MaxMind database
- **Continent** — AF, AN, AS, EU, NA, OC, SA via MaxMind database

Rules can be freely mixed. **Allow rules always win over block rules**, so you can block an entire country or ASN while explicitly whitelisting specific IPs from it.

IPv4 and IPv6 are fully supported throughout.

---

## Installation

### With xcaddy (recommended)

```bash
xcaddy build --with github.com/fuomag9/caddy-blocker-plugin
```

### Standalone binary

```bash
git clone https://github.com/fuomag9/caddy-blocker-plugin
cd caddy-blocker-plugin
go build -o caddy ./cmd/caddy
```

Verify the plugin is loaded:

```bash
./caddy list-modules | grep blocker
# http.handlers.blocker
```

---

## GeoIP / ASN databases

Country, continent, and ASN blocking require MaxMind `.mmdb` database files. The free
[GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) databases work out of the box. Commercial [GeoIP2](https://www.maxmind.com/en/geoip2-databases) databases use the same format and are also supported.

Download the relevant databases from MaxMind and point the plugin at them with `geoip_db` and `asn_db`.

If a database file is missing or unreadable, the corresponding rule types (country/continent or ASN) are **silently skipped** and other rules continue to work (fail-open).

---

## Configuration

The plugin is configured as a JSON handler with the name `"blocker"` inside a Caddy route.

### Full JSON reference

```json
{
  "handler": "blocker",

  "geoip_db": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
  "asn_db":   "/usr/share/GeoIP/GeoLite2-ASN.mmdb",

  "block_countries":   ["CN", "RU", "KP"],
  "block_continents":  ["AF"],
  "block_asns":        [12345, 67890],
  "block_cidrs":       ["192.0.2.0/24", "198.51.100.0/24"],
  "block_ips":         ["203.0.113.1"],

  "allow_countries":   ["US"],
  "allow_continents":  [],
  "allow_asns":        [11111],
  "allow_cidrs":       ["10.0.0.0/8"],
  "allow_ips":         ["1.2.3.4"],

  "trusted_proxies":   ["127.0.0.1", "10.0.0.0/8"],
  "fail_closed":       false,

  "response_status":   403,
  "response_body":     "<h1>Access Denied</h1>",
  "response_headers":  { "Content-Type": "text/html; charset=utf-8" },
  "redirect_url":      ""
}
```

### Field reference

| Field | Type | Default | Description |
|---|---|---|---|
| `geoip_db` | string | — | Path to a GeoLite2/GeoIP2 Country or City `.mmdb` file |
| `asn_db` | string | — | Path to a GeoLite2/GeoIP2 ASN `.mmdb` file |
| `block_countries` | []string | — | ISO 3166-1 alpha-2 country codes to block (e.g. `"CN"`) |
| `block_continents` | []string | — | Continent codes to block: `AF` `AN` `AS` `EU` `NA` `OC` `SA` |
| `block_asns` | []uint | — | Autonomous System Numbers to block |
| `block_cidrs` | []string | — | CIDR ranges to block |
| `block_ips` | []string | — | Individual IP addresses to block |
| `allow_countries` | []string | — | Country codes to allow (wins over block rules) |
| `allow_continents` | []string | — | Continent codes to allow (wins over block rules) |
| `allow_asns` | []uint | — | ASNs to allow (wins over block rules) |
| `allow_cidrs` | []string | — | CIDR ranges to allow (wins over block rules) |
| `allow_ips` | []string | — | Individual IPs to allow (wins over block rules) |
| `trusted_proxies` | []string | — | IPs or CIDRs of trusted reverse proxies for `X-Forwarded-For` |
| `fail_closed` | bool | `false` | If `true`, block requests when client IP cannot be determined from trusted proxy headers |
| `response_status` | int | `403` | HTTP status code for blocked responses |
| `response_body` | string | `"Forbidden"` | Response body for blocked responses (plain text or HTML) |
| `response_headers` | map[string]string | — | Extra headers added to blocked responses |
| `redirect_url` | string | — | If set, blocked requests receive a `302` redirect here instead of a body response |

---

## Rule evaluation

For every request:

1. **Extract client IP** from `RemoteAddr`. If the direct connection comes from a `trusted_proxies` address, `X-Forwarded-For` is parsed from right to left and the nearest non-trusted IP is used.
2. **Indeterminate client IP** — if no usable client IP is found, requests pass through by default; set `fail_closed: true` to block instead.
3. **Check allow rules** — if any allow rule matches, the request passes immediately to the next handler (block rules are not evaluated).
4. **Check block rules** — if any block rule matches, the configured block response is returned.
5. **Default** — no rules matched, request passes through.

---

## Examples

### Block a country, allow one IP from it

```json
{
  "handler": "blocker",
  "geoip_db": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
  "block_countries": ["CN"],
  "allow_ips": ["1.2.3.4"],
  "response_status": 403,
  "response_body": "Access denied."
}
```

`1.2.3.4` passes even if its country resolves to `CN`.

### Block an ASN but whitelist a CIDR from it

```json
{
  "handler": "blocker",
  "asn_db": "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
  "block_asns": [12345],
  "allow_cidrs": ["203.0.113.0/24"],
  "response_status": 403
}
```

### Redirect blocked visitors

```json
{
  "handler": "blocker",
  "geoip_db": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
  "block_continents": ["AF", "AS"],
  "redirect_url": "https://example.com/not-available"
}
```

### Full Caddy JSON config

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":8080"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "blocker",
                  "geoip_db": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
                  "asn_db":   "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
                  "block_countries": ["CN", "RU", "KP"],
                  "block_asns": [12345],
                  "allow_ips": ["1.2.3.4"],
                  "trusted_proxies": ["127.0.0.1"],
                  "response_status": 403,
                  "response_body": "<h1>Access Denied</h1>",
                  "response_headers": {
                    "Content-Type": "text/html; charset=utf-8"
                  }
                },
                {
                  "handler": "reverse_proxy",
                  "upstreams": [{"dial": "localhost:3000"}]
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

---

## Behind a reverse proxy

Set `trusted_proxies` to the IP(s) or CIDR(s) of your upstream proxy (e.g. nginx, Cloudflare, a load balancer). The plugin then resolves client IP from `X-Forwarded-For` by walking from right to left and picking the first non-trusted hop, which is safer when upstream proxies append to existing headers.

Both plain IPs and CIDR notation are accepted:

```json
"trusted_proxies": ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"]
```

---

## License

MIT
