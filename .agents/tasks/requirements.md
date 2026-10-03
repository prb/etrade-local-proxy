# Requirements: ETrade Local Read-Only Proxy

## Summary

A from-scratch Rust CLI application that runs a local HTTPS reverse proxy in
front of the live ETrade API. The proxy's purpose is **structural isolation of
the read surface**: because ETrade API access is all-or-nothing, this proxy
exposes only `GET` requests against the `/v1/accounts/*` read endpoints and
makes the write portion of the API unreachable by construction. It holds live
brokerage OAuth credentials in memory only, binds only to loopback, and serves
over TLS.

The code must follow the workspace's idiomatic-functional-Rust steering
(`.kiro/steering/rust-functional-style.md`): a pure functional core (OAuth
signing, request filtering, URL mapping, serialization) behind a thin
imperative shell (TLS server, outbound HTTP client, stdin/stdout prompts,
config loading, clock/RNG). Errors are values (`thiserror` per module,
`anyhow` only at the `main` edge). Non-determinism (clock, nonce) is injected so
the core is deterministic and property-testable. The authorization lifecycle is
modeled as a typestate rather than a boolean flag.

This is a security-sensitive system. The requirements below are the testable
contract; the hard security invariants (loopback-only bind, `GET`-only
forwarding) are called out explicitly and must be covered by tests.

## Functional Requirements

### FR-1 — Rust CLI binary crate
- The deliverable is a Cargo **binary** crate that runs as a command-line
  application.
- It is structured as a thin imperative shell over a pure functional core, per
  the steering doc. The core (signature construction, request admission
  decision, path mapping, status serialization) must be unit-testable with plain
  values, no network, no async runtime, no mocks.
- Fallible library-style modules expose typed error enums via `thiserror`;
  `anyhow` is permitted only at the `main`/CLI boundary.

### FR-2 — Configuration from environment
- The ETrade **consumer key** is read from `ETRADE_CONSUMER_KEY`.
- The ETrade **consumer secret** is read from `ETRADE_CONSUMER_SECRET`.
- The **listen port** is configurable, defaulting to `8443`.
- If either required environment variable is missing or empty, startup fails
  with a clear, non-panicking error that names the missing variable, and the
  process exits with a non-zero status before binding any socket.

### FR-3 — OAuth 1.0a authorization flow on startup
- On every startup, and only at startup, the application performs the full
  ETrade OAuth 1.0a three-leg flow:
  1. **Get request token** from the ETrade request-token endpoint.
  2. **Display the authorize URL** on the console. The URL has the form
     `https://us.etrade.com/e/t/etws/authorize?key={consumer_key}&token={request_token}`.
  3. **Prompt on stdin** for the verifier code the user obtains after approving
     access in the browser.
  4. **Exchange the verifier** for an access token at the access-token endpoint.
- Request signing uses **HMAC-SHA1** with the consumer secret and, once
  available, the token secret, per OAuth 1.0a.
- The nonce and timestamp used in signing are **injected** into the core signing
  function (supplied by the shell) so the core remains deterministic and
  testable.
- No browser is launched by the application; it only prints the URL and reads
  the verifier from stdin.

### FR-4 — Credentials in memory only
- The access token and token secret are held **in memory only** and are never
  written to disk, logs, or any persistent store.
- There is no token caching or reuse across runs; a fresh authorization flow
  runs on each startup.

### FR-5 — Live environment only
- The proxy targets the **live** ETrade environment with upstream base host
  `api.etrade.com`.
- There is **no sandbox toggle**. Safety rests entirely on the read-only proxy
  surface, not on environment selection.

### FR-6 — Local HTTPS server, loopback only
- The application starts an **HTTPS** server bound **only** to `127.0.0.1`
  (loopback) on the configured port.
- It must **never** bind a non-loopback address under any configuration or input.
- A **self-signed TLS certificate** is generated at startup using the `rcgen`
  crate (ephemeral, in memory, consistent with the no-persistence posture).
- The certificate **fingerprint** is printed to the console at startup so a
  client can be configured to trust it.
- **mTLS (client certificate authentication) is out of scope** for this first
  pass; loopback + HTTPS is the trust boundary.

### FR-7 — Reverse-proxy mapping under `/etrade-api`
- Local requests under the `/etrade-api` prefix map to the ETrade `/v1/accounts/*`
  path. Example: local `GET /etrade-api/v1/accounts/list` maps to upstream
  `GET https://api.etrade.com/v1/accounts/list`.
- Query strings on admitted requests are preserved through the mapping.
- Each proxied upstream request is **OAuth-signed with the access token** (and
  token secret) before being sent.
- The upstream response (status, relevant headers, body) is relayed back to the
  local client.
- The path-mapping/admission logic is a pure function in the core; the signing
  and network send live in the shell.

### FR-8 — Hard security rule: `GET`-only forwarding
- **Only HTTP `GET`** requests are proxied.
- Enforcement is at the **HTTP verb level**, not by URL globbing alone. The
  rationale: write operations such as order placement are a `POST` under
  `/v1/accounts/{accountIdKey}/orders/*` and share a path prefix with reads, so a
  path allow-list alone is insufficient.
- Any non-`GET` request to the proxy (`POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`,
  `OPTIONS`, etc.) under the proxy prefix is **rejected and never forwarded
  upstream**.
- The admission decision — "is this request forwarded?" — is a **total pure
  function** over (method, path): it admits exactly `GET` requests whose path is
  under `/etrade-api/v1/accounts`, and rejects everything else (non-`GET` methods
  and out-of-prefix paths). This is the central, well-tested invariant.

### FR-9 — `/internal/status` endpoint
- The server exposes `GET /internal/status`, which is **not** under `/etrade-api`
  and is **not** proxied upstream.
- It returns a JSON document: `{"authorized":true}` once the OAuth flow has
  completed and the access token is held, otherwise `{"authorized":false}`.
- The authorization lifecycle is modeled with the **typestate** approach from the
  steering doc: an unauthorized state transitions (by consuming it) into an
  authorized state that **owns** the access token, rather than a nullable token
  field guarded by a boolean. The status serialization is derived from which
  state is current.

## Non-Functional Requirements

### NFR-1 — Idiomatic functional style (steering compliance)
- Code adheres to `.kiro/steering/rust-functional-style.md`: errors as values,
  typed error enums, `?` propagation, combinators/iterators over manual loops
  where clearer, immutability by default with scoped `mut`, newtypes over bare
  primitives for domain values (e.g. consumer key/secret, tokens, nonce), and
  `#[non_exhaustive]` on public growable error enums.
- No `unwrap`/`expect` outside genuinely-unreachable, documented cases.

### NFR-2 — Security posture
- Credentials and token material are never persisted and are not emitted to logs
  or error messages. Error output referencing credentials uses key names, not
  values.
- The loopback-only bind and `GET`-only forwarding are treated as security
  invariants, not best-effort behaviors.

### NFR-3 — Deterministic core
- The pure core takes injected clock/nonce and performs no IO, enabling
  reproducible property tests.

## Acceptance Criteria

Each criterion is specific and testable. "Automated" means runnable under
`cargo test` with no network access to ETrade.

1. `cargo build` completes with no errors on a clean checkout.
2. `cargo clippy` (with `--all-targets`) produces **no warnings**.
3. `cargo test` passes, including unit, property, and integration tests.
4. **OAuth signing round-trip / determinism (proptest):** given injected nonce
   and timestamp held fixed, the pure signing function produces an identical
   signature base string and HMAC-SHA1 signature across repeated calls for the
   same inputs; varying the injected nonce/timestamp changes the output. The
   signature-base-string construction is property-tested over arbitrary
   parameter sets (correct percent-encoding and sorting).
5. **Admission invariant — non-GET always rejected (proptest):** for arbitrary
   non-`GET` methods and arbitrary paths (including paths under
   `/etrade-api/v1/accounts` and under `.../orders`), the admission function
   never admits the request.
6. **Admission invariant — out-of-prefix always rejected (proptest):** for
   arbitrary `GET` requests whose path is not under `/etrade-api/v1/accounts`
   (including `/internal/status` and arbitrary strings), the admission function
   never admits the request.
7. **Admission invariant — in-prefix GET admitted (proptest):** every `GET`
   request whose path is under `/etrade-api/v1/accounts` is admitted and maps to
   the corresponding upstream `/v1/accounts/...` path, with query string
   preserved.
8. **Admission totality:** the admission function returns a decision for all
   `(method, path)` inputs and never panics (checked by property test over
   arbitrary inputs).
9. **Loopback-only bind:** an automated test asserts the server's resolved bind
   address is `127.0.0.1` and that no configuration path yields a non-loopback
   address.
10. **`/internal/status` serialization:** a test asserts the unauthorized state
    serializes to `{"authorized":false}` and the authorized state serializes to
    `{"authorized":true}` (snapshot or exact-match).
11. **Config validation:** missing/empty `ETRADE_CONSUMER_KEY` or
    `ETRADE_CONSUMER_SECRET` yields a typed error naming the variable and a
    non-zero exit, with no socket bound (tested at the config-parsing layer).
12. **Authorize URL construction:** a test asserts the printed authorize URL
    equals
    `https://us.etrade.com/e/t/etws/authorize?key={consumer_key}&token={request_token}`
    for given inputs.
13. **No live end-to-end ETrade calls** occur in any automated test; the OAuth
    exchange and upstream forwarding shell paths are covered by example-based
    integration tests against local fakes/fixtures, not the real API.
14. **No credential persistence:** no test or code path writes token material to
    disk; the token exists only within the authorized typestate value in memory.

## Out of Scope

- mTLS / client-certificate authentication (deferred past the first pass).
- Proxying any method other than `GET`, or any path outside `/v1/accounts/*`.
- Any write/mutating ETrade operations (orders, transfers, etc.).
- Sandbox environment support or a live/sandbox toggle.
- Token persistence, caching, or refresh across runs.
- Launching a browser automatically for the authorize step.
- A CA-signed or externally trusted TLS certificate (self-signed only).
- Multi-user, remote, or non-loopback access.

## Assumptions

- The ETrade request-token, authorize, and access-token endpoints are those
  documented at the links in `CONCEPT.md`; exact endpoint hostnames/paths are an
  implementation detail resolved during design, but the live upstream base host
  for proxied account calls is `api.etrade.com`.
- "Configurable port" is satisfied by a CLI flag and/or environment variable;
  the default is `8443`. The precise mechanism is a design decision.
- Printing the TLS certificate fingerprint (rather than exporting the full cert)
  is sufficient for client trust bootstrapping in this first pass.
- Relayed response headers are limited to those safe and meaningful for a local
  client (e.g. content type); hop-by-hop headers are not blindly forwarded. The
  exact header policy is a design decision.
