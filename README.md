# etrade-local-proxy

A Rust-based local HTTPS proxy for the [ETrade API](https://developer.etrade.com/documentation)
that structurally isolates the read-only surface of the API. Because ETrade API
access is all-or-nothing, this proxy exposes only read (`GET`) calls under
`/v1/accounts/*` and completely omits the write portion of the API.

See **[CONCEPT.md](CONCEPT.md)** for the full design, security model, and
behavior.

## Quick start

Set your ETrade consumer credentials (held in memory only, never persisted):

```sh
export ETRADE_CONSUMER_KEY="your-consumer-key"
export ETRADE_CONSUMER_SECRET="your-consumer-secret"
```

Run the proxy (live ETrade by default; add `--sandbox` to target the ETrade
sandbox, `--port` to change the loopback port, default `8443`, and
`--request-timeout-secs` to change the overall timeout for proxied requests,
default `30`):

```sh
cargo run -- --sandbox
```

On startup it generates a self-signed TLS certificate (printing its SHA-256
fingerprint), runs the OAuth 1.0a flow — it prints an authorize URL for you to
open in a browser, then prompts for the verifier code — and validates the token
with a single `GET /v1/accounts/list` before serving. It binds only to
`127.0.0.1`.

While running, it sends a signed `GET /v1/accounts/list` every 30 minutes to keep
the token from going idle (~2h). This cannot extend ETrade's hard token expiry
at midnight US Eastern; after that the proxy exits with an error and must be
restarted to re-authorize.

```sh
# readiness signal for clients
curl -k https://127.0.0.1:8443/internal/status
# -> {"authorized":true}

# a proxied read call (ETrade returns XML by default)
curl -k https://127.0.0.1:8443/etrade-api/v1/accounts/list

# the Accept header is passed through, so you can ask ETrade for JSON
curl -k -H "Accept: application/json" https://127.0.0.1:8443/etrade-api/v1/accounts/list

# writes are structurally rejected (verb-level, never forwarded upstream)
curl -k -X POST https://127.0.0.1:8443/etrade-api/v1/accounts/list -i
# -> 405
```

## Keeping credentials in the OS keychain

Instead of exporting the consumer key and secret in your shell profile, keep
them in the OS secret store and set the variables for the proxy's command only.
Leaving the value off the store command makes it prompt, which keeps the secret
out of shell history and `ps` output.

macOS (Keychain, via `security`):

```sh
security add-generic-password -U -a "$USER" -s etrade-consumer-key -w
security add-generic-password -U -a "$USER" -s etrade-consumer-secret -w

ETRADE_CONSUMER_KEY="$(security find-generic-password -a "$USER" -s etrade-consumer-key -w)" \
ETRADE_CONSUMER_SECRET="$(security find-generic-password -a "$USER" -s etrade-consumer-secret -w)" \
cargo run -- --sandbox
```

Linux (Secret Service, via `secret-tool` from libsecret):

```sh
secret-tool store --label="etrade consumer key" service etrade-consumer-key
secret-tool store --label="etrade consumer secret" service etrade-consumer-secret

ETRADE_CONSUMER_KEY="$(secret-tool lookup service etrade-consumer-key)" \
ETRADE_CONSUMER_SECRET="$(secret-tool lookup service etrade-consumer-secret)" \
cargo run -- --sandbox
```

Notes:

- Don't pipe stdin into the proxy; it reads the OAuth verifier from stdin.
- macOS may ask for permission the first time `security` reads an item.
  Choosing "Always Allow" lets it read the item without asking again.
- The proxy's environment is readable by other processes running as your user.
  This keeps secrets out of files and dotfiles; it does not hide them from your
  own account.

## Timeouts and errors

The proxy bounds every call to E*TRADE: a **10 s connect timeout** and a
**30 s overall request timeout** (connect, send, and reading the full response
body). `--request-timeout-secs` changes the overall timeout for proxied
requests only. The OAuth flow, the startup probe and the keep-alive keep 30 s.
A connect timeout is also reported as `upstream_timeout`, with the overall
timeout in `timeout_seconds`.

Errors the proxy generates itself use the statuses below, with
`Content-Type: application/json` and a body such as
`{"error": "upstream_timeout", "timeout_seconds": 30}`:

| Situation | Status | `error` |
|---|---|---|
| upstream call timed out | 504 | `upstream_timeout` |
| other upstream failure (connect error, reset, bad TLS, etc.) | 502 | `upstream_error` |
| upstream body over the 8 MiB size cap | 502 | `upstream_too_large` |
| proxy not ready (no token yet) | 503 | `not_ready` |

- `error` always matches `^[a-z][a-z0-9_]{0,39}$`.
- `timeout_seconds` appears for `upstream_timeout` only and is the overall
  timeout in effect.
- Bodies contain fixed strings and numbers only: never the URL, account key,
  headers, token material, or the upstream response.
- Replies from E*TRADE itself (for example a `401` or `500`) pass through
  unchanged.

**Clients should wait longer than the overall timeout (about 40 s by default,
the proxy's 30 s plus 10 s)** so the proxy's verdict is the one they see. A
shorter client timeout fails first and looks like a proxy that is down.

## License

[MIT](LICENSE)
