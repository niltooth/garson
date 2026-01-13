# garson
Minimal static file server with zero external dependencies. Useful for quickly
sharing files between machines.

## Usage
```
go run .
  -dir string
        directory to serve (default ".")
  -port int
        optional port (0 picks a random available port)
  -user string
        basic auth username (default: current OS user; random password generated each start)
  -open-browser
        open browser after start when supported (default true)
  -open-host string
        host used when auto-opening: local, hostname, lan (default "lan")
  -max-runtime duration
        max runtime before automatic shutdown, 0 disables (default 1h0m0s)
  -tls
        enable TLS with cached self-signed cert (default true)
  -tls-cert string
        path to TLS certificate (overrides generated self-signed)
  -tls-key string
        path to TLS private key (overrides generated self-signed)
  -config string
        path to config file (default XDG config)
```

Examples:
- Serve the current directory on a random port (HTTPS): `go run .`
- Serve `/tmp/files` on port 8080: `go run . -dir /tmp/files -port 8080`
- Supply a custom username: `go run . -user admin`
- Skip auto-opening a browser (headless): `go run . -open-browser=false`
- Auto-open uses the generated credentials in the URL so the first tab is already authenticated; disable with `-open-browser=false` if you prefer to copy/paste creds manually.
- Use your DNS-resolvable hostname: `go run . -open-host=hostname`
- Prefer your LAN IP if available: `go run . -open-host=lan`
- Limit to 30 minutes of runtime: `go run . -max-runtime=30m`
- Disable TLS (serve plain HTTP): `go run . -tls=false`
- Use your own cert/key: set `cert_file`/`key_file` in the config or pass `-tls-cert`/`-tls-key`
- Custom config location: `go run . -config /tmp/garson.toml`

TLS: By default a self-signed certificate is generated and cached in
`$XDG_CACHE_HOME/garson/tls` (or `~/.cache/garson/tls`). Delete the files to
force regeneration.

Config: A config file is auto-created if missing at
`$XDG_CONFIG_HOME/garson/config.toml` (or `~/.config/garson/config.toml`).
You can set `cert_file`, `key_file`, and `tls_cache` there.

## Build
```
go build -o garson .
```

