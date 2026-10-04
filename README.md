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
sandbox, `--port` to change the loopback port, default `8443`):

```sh
cargo run -- --sandbox
```

On startup it generates a self-signed TLS certificate (printing its SHA-256
fingerprint), runs the OAuth 1.0a flow — it prints an authorize URL for you to
open in a browser, then prompts for the verifier code — and validates the token
with a single `GET /v1/accounts/list` before serving. It binds only to
`127.0.0.1`.

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

## License

[MIT](LICENSE)
