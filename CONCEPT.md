This project is a Rust-based local proxy for the [ETrade API](https://developer.etrade.com/documentation).  Because API access is all-or-nothing, the local proxy is intended as intentional isolation that exposes only the read surface of the API and completely omits the write portion from a proxy perspective.

Design:

- The proxy should be implemented in Rust using idiomatic functional approaches.
- The local proxy should run as a CLI application.
- The local proxy should start up an HTTPS endpoint bound only to the local loopback interface (`127.0.0.1`). It must never bind to a non-loopback address, as it holds live brokerage credentials in memory.
- The local proxy should perform the authorization workflow of acquiring an access token on startup.  See [Get Request Token](https://apisb.etrade.com/docs/api/authorization/request_token.html), [Authorize Application](https://apisb.etrade.com/docs/api/authorization/authorize.html), [Get Access Token](https://apisb.etrade.com/docs/api/authorization/get_access_token.html) and API calls.
  - ETrade uses OAuth 1.0a. The authorization step requires human interaction: the proxy displays the authorize URL on the console, the user opens it in a browser and approves access, ETrade displays a verifier code, and the user pastes that code back into the proxy at a stdin prompt. The proxy then exchanges the verifier for an access token.

Credentials and configuration:

- The ETrade consumer key and consumer secret are read from environment variables (`ETRADE_CONSUMER_KEY` and `ETRADE_CONSUMER_SECRET`).
- The access token is held in memory only. It is never persisted to disk. A fresh OAuth authorization flow runs on every startup, and only at startup.
- The proxy targets the live ETrade environment by default. A `--sandbox` flag switches the upstream host to the ETrade sandbox (`apisb.etrade.com`) for the API and both OAuth token legs; without the flag the live host (`api.etrade.com`) is used. The flag encapsulates the host difference so callers never deal with the `apisb` vs `api` distinction directly. The authorize URL (`us.etrade.com`) is the same in both environments. This read-only sandbox/live toggle does not weaken the safety model: isolation rests on the GET-only verb filtering described below, which applies identically in both environments, so there is no way to reach a write endpoint regardless of host.

Proxy surface (read-only by design):

- The proxy forwards the `/v1/accounts/*` portion of the ETrade API, exposed under an `/etrade-api` prefix on local endpoints (so a local request to `/etrade-api/v1/accounts/...` maps to the ETrade `/v1/accounts/...` path).
- Only HTTP `GET` requests are proxied. This is a hard structural rule enforced on the HTTP verb, not merely a URL pattern — a path-glob allow-list alone is insufficient because write operations (for example, order placement, a `POST` under `/v1/accounts/{accountIdKey}/orders/*`) share a path prefix with read operations. Any non-`GET` request to the proxy is rejected without being forwarded upstream. This structurally omits the write portion of the API.
- The client's `Accept` request header is passed through to ETrade so a client can select the response representation. ETrade returns XML by default; a client sending `Accept: application/json` receives JSON. No other client request headers are forwarded (the proxy adds only its own OAuth `Authorization` header). `Accept` is not part of the OAuth 1.0a signature base string, so forwarding it does not affect request signing.

Startup authorization validation:

- After the OAuth flow produces an access token and before the proxy begins serving, the proxy makes a single signed, lightweight read call to validate that the token actually works: `GET /v1/accounts/list` (the lightest accounts read; no parameters, no account id required). This uses the same signed-GET machinery as the proxy forward path.
- On success (HTTP 2xx), the proxy logs a terse console confirmation (e.g. `info: authorization validated via GET /v1/accounts/list (HTTP 200)`). The 2xx status is the entire authorization signal; the response body (which ETrade returns as XML) is not parsed, and no account data is logged.
- On failure (non-2xx response or network error), the proxy fails fast: it logs the failure and exits with an error rather than coming up. A proxy that cannot make a validated API call is worse than one that reports the problem immediately; there is no point keeping a non-working connection alive.

Keep-alive:
- ETrade access tokens go inactive after roughly 2 hours idle. After the server is up, a background task makes the same signed `GET /v1/accounts/list` call as the startup probe every 30 minutes (a shell constant; no CLI flag) to reset the idle timer. The first call fires one interval after startup. Each call draws its own fresh nonce/timestamp. It is an internal outbound call, not a proxy route, and does not change `/internal/status` or the GET-only surface.
- Keep-alive resets the idle timeout only. It cannot and does not try to extend the hard token expiry at midnight US Eastern; after that the proxy must be restarted to re-authorize.
- A pure core classifier maps each result to an action. 2xx: log `info: keep-alive OK (HTTP 200)`. HTTP 401/403 (token expired or revoked): fatal; the proxy logs that the token expired and to restart to re-authorize, then exits non-zero (consistent with fail-fast). Any other failure (transport error, 5xx, other non-2xx): transient; log a `warn:` line and retry at the next interval. Only status codes are logged, never account data.
- Termination: `main` selects on the server future and the keep-alive future; the keep-alive future ends only with a fatal error, which propagates through `anyhow` to a non-zero exit (no `process::exit` in the shell).
Outbound timeouts:
- Every outbound HTTP client is built by one shell constructor (`shell::http`) with a 10s connect timeout and a 30s overall request timeout (covering connect, send, and reading the full body), so a hung or half-open connection cannot block forever.
- Keep-alive treats a timeout as a transient transport failure (`warn:` line, retry next interval). The startup probe and the OAuth flow fail on timeout like any transport error. The proxy forward path returns `504 Gateway Timeout` for an upstream timeout (other upstream failures remain `502`).
Status endpoint:

- The local proxy should support a `/internal/status` endpoint that returns a JSON document.  The document should contain `{"authorized":true}` or `{"authorized":false}` depending on whether the authorization workflow has been completed.  (Clients of the proxy will use this to determine whether to make calls against the API.)
