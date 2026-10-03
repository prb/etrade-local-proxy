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
- The proxy targets the live ETrade environment. There is no sandbox toggle by design; safety rests entirely on the read-only proxy surface described below.

Proxy surface (read-only by design):

- The proxy forwards the `/v1/accounts/*` portion of the ETrade API, exposed under an `/etrade-api` prefix on local endpoints (so a local request to `/etrade-api/v1/accounts/...` maps to the ETrade `/v1/accounts/...` path).
- Only HTTP `GET` requests are proxied. This is a hard structural rule enforced on the HTTP verb, not merely a URL pattern — a path-glob allow-list alone is insufficient because write operations (for example, order placement, a `POST` under `/v1/accounts/{accountIdKey}/orders/*`) share a path prefix with read operations. Any non-`GET` request to the proxy is rejected without being forwarded upstream. This structurally omits the write portion of the API.

Status endpoint:

- The local proxy should support a `/internal/status` endpoint that returns a JSON document.  The document should contain `{"authorized":true}` or `{"authorized":false}` depending on whether the authorization workflow has been completed.  (Clients of the proxy will use this to determine whether to make calls against the API.)
