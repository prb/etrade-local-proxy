# Implementation Plan: ETrade Local Read-Only Proxy

Build a from-scratch Rust CLI binary that runs a local HTTPS reverse proxy in
front of the live ETrade API, exposing only the `GET` read surface under
`/v1/accounts/*`. Follows `.kiro/steering/rust-functional-style.md`: pure
functional core behind a thin imperative shell, errors as values (`thiserror`
per module, `anyhow` only at `main`), typestate auth lifecycle, newtypes over
primitives, injected clock/nonce, `proptest` for the pure core.

Authoritative sources (do not re-decide): `.agents/tasks/design.md` (structure,
signatures, crate stack — LOCKED), `.agents/tasks/requirements.md` (acceptance
criteria AC-1..14), `CONCEPT.md` (product intent).

All commands run in `/Users/paulbrown/Code/etrade-local-proxy` (NO worktree).

Verification gate (every step must leave this green or make progress toward it):
- `cargo build`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
Do NOT add any automated test that makes a live ETrade network call (AC-13):
shell tests use `wiremock` local fakes only.

The plan is ordered PURE CORE FIRST (property-tested before the shell), then the
imperative shell, then integration tests and the final gate — matching the
design's `core` → `shell` dependency boundary.

---

- [ ] 1. Scaffold the Cargo binary crate with the locked dependency stack and the empty core/shell module tree.
      Create `Cargo.toml` (edition 2021) pinning exact versions per the design's locked stack: `tokio` (features `["rt","macros"]` for `current_thread`), `axum`, `axum-server` (feature `tls-rustls`), `hyper`, `reqwest` (`default-features = false`, features `["rustls-tls","json"]`), `rustls`, `rcgen = "0.14"` (default features), `hmac`, `sha1`, `base64 = "0.22"`, `percent-encoding`, `url`, `secrecy = "0.10"`, `rand`, `serde` (derive), `serde_json`, `thiserror`, `anyhow`, `clap` (derive); dev-deps `proptest`, `insta`, `wiremock`, `tokio` test features. Create `src/main.rs` (temporary `fn main() {}`), `src/lib.rs` declaring `pub mod core;` and `pub mod shell;`, and empty module files for the full tree in the design's Module Layout (`core/{mod,newtypes,config,admission,relay,status,authorize_url,tls_fingerprint,error}.rs`, `core/oauth/{mod,endpoints,base_string,sign,params}.rs`, `shell/{mod,env,clock_nonce,tls,server,handlers,upstream,oauth_flow,prompt,state,error}.rs`) with just module declarations/`//!` docs so the tree compiles.
      Files: `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/core/*.rs`, `src/core/oauth/*.rs`, `src/shell/*.rs`, `.gitignore` (ignore `/target`).
      Verify: `cargo build` succeeds and `cargo clippy --all-targets --all-features -- -D warnings` is clean on the empty tree.

- [ ] 2. Implement the domain newtypes and the ETrade endpoint constants (the pure core's foundation).
      In `core/newtypes.rs` define `ConsumerKey`, `ConsumerSecret(SecretString)`, `RequestToken`, `TokenSecret(SecretString)`, `AccessToken`, `Verifier`, `Nonce`, `Timestamp(u64)`, `ListenPort(u16)` per the design, with redacting/truncating hand-written `Debug` on non-secret token types and reliance on `secrecy`'s redacting `Debug`/no-`Display`/zeroize-on-drop for secret types; validate the pinned `secrecy = "0.10"` API (`SecretString = SecretBox<str>`, `SecretString::from(String)`, `expose_secret() -> &str`). In `core/oauth/endpoints.rs` define `UPSTREAM_HOST`, `REQUEST_TOKEN_PATH`, `ACCESS_TOKEN_PATH`, `AUTHORIZE_URL_BASE` and `oauth_endpoint_url(path)` so the host literal appears exactly once; include the documented first-run-verification comment.
      Files: `src/core/newtypes.rs`, `src/core/oauth/endpoints.rs`, `src/core/mod.rs`, `src/core/oauth/mod.rs`.
      Verify: `cargo test core::newtypes core::oauth::endpoints` — unit tests (constructors, `oauth_endpoint_url` builds `https://api.etrade.com{path}`, secret `Debug` redaction) pass; clippy clean.

- [ ] 3. Implement the pure OAuth signing pipeline: shared encoder, query split/serialize, the three-leg signing domain, base string, HMAC, and header builder.
      In `core/oauth/mod.rs` define the shared RFC-3986 `AsciiSet` and `oauth_encode`, plus `split_query` (decode-then-encode, non-UTF-8 raw passthrough, drop `oauth_*` names, preserve duplicates as an ordered multiset, total) and `wire_query` (re-serialize signed pairs in client order with `oauth_encode`). In `core/oauth/params.rs` define `SigningInput::{RequestToken,AccessToken,Resource}`, `OauthParams` (no `oauth_signature` field; `token: Option`; `extra` for callback/verifier), `oauth_params(&SigningInput,&Nonce,&Timestamp)`, and `OauthParams::as_pairs()`. In `core/oauth/base_string.rs` define `upstream_base_url(path)` and `signature_base_string(method,base_url,base_params)` (encode, sort a copy of encoded pairs by encoded name then value, join, assemble `METHOD&enc(url)&enc(params)`). In `core/oauth/sign.rs` define `signing_key` (the single source-level `expose_secret()` site), `sign_hmac_sha1` (base64 `0.22` Engine `STANDARD.encode`), `authorization_header(&OauthParams,&signature)` (renders exactly `as_pairs()` + signature, `oauth_encode`'d, double-quoted, name-sorted, no realm), and the single enforcing `sign_leg(&SigningInput,&ConsumerSecret,&[(String,String)],&Nonce,&Timestamp) -> SignedLeg`. Needs the core enum `HttpMethod` (add to `core/admission.rs` or `core/mod.rs`).
      Files: `src/core/oauth/mod.rs`, `src/core/oauth/params.rs`, `src/core/oauth/base_string.rs`, `src/core/oauth/sign.rs`.
      Verify: `cargo test core::oauth` passes, including proptests — determinism (fixed nonce/ts ⇒ identical base string + signature; varying them changes output), base-string/header param-multiset agreement across all three legs (RequestToken emits NO `oauth_token`; legs 2&3 emit exactly one), `split_query` totality + round-trip into base string, signed-multiset == wire-multiset (with a duplicate-key case), non-UTF-8 escape totality + signed==wire, header percent-encoding of `+`/`/`/`=` and no realm, and a table-driven RFC 5849 reference vector whose base string excludes `oauth_signature`.

- [ ] 4. Implement the total request-admission function and path mapping (the central security invariant).
      In `core/admission.rs` define `HttpMethod` (if not already in `core/mod.rs`), `Admission::{Forward(UpstreamPath),Status,Reject(RejectReason)}`, `RejectReason::{MethodNotGet,OutOfPrefix}` (`#[non_exhaustive]`), `UpstreamPath(String)`, and the total `admit(&HttpMethod,&str) -> Admission`: verb-first (non-GET ⇒ `Reject(MethodNotGet)`), then `GET /internal/status` ⇒ `Status`, `GET` under `/etrade-api/v1/accounts` (next char `/`,`?`, or end) ⇒ `Forward` mapping `/etrade-api`→`/v1/accounts` with query preserved verbatim, else `Reject(OutOfPrefix)`. Use only total string ops.
      Files: `src/core/admission.rs`.
      Verify: `cargo test core::admission` passes, including proptests for AC-5 (non-GET never `Forward`), AC-6 (out-of-prefix GET never `Forward`, with `/internal/status` excluded from that arm) plus a dedicated `GET /internal/status == Status` example, AC-7 (in-prefix GET admitted and correctly mapped, query preserved), AC-8 (totality over arbitrary strings, never panics); custom `Arbitrary` for `HttpMethod` and a mixed path strategy.

- [ ] 5. Implement the remaining pure-core pieces: status typestate, config validation, authorize-URL builder, TLS fingerprint, relay-header whitelist, and the core error enums.
      In `core/status.rs` define `Unauthorized`/`Authorized{access_token,token_secret}`, `Unauthorized::authorize(...)`, `StatusBody{authorized:bool}` and `status_body_unauthorized`/`status_body_authorized(&Authorized)`. In `core/config.rs` define `EnvSnapshot`, `Config`, `build_config(&EnvSnapshot,ListenPort) -> Result<Config,ConfigError>` (empty = missing). In `core/authorize_url.rs` define `authorize_url(&ConsumerKey,&RequestToken)` using ordinary form-urlencoding (NOT `oauth_encode`). In `core/tls_fingerprint.rs` define `fingerprint(&[u8]) -> String` (SHA-256, lowercase colon-hex). In `core/relay.rs` define `relay_header_allowed(name) -> bool` (whitelist Content-Type/Date/ETag/caching; reject Content-Length and hop-by-hop). In `core/error.rs` define `ConfigError`, `OauthParseError` (`#[non_exhaustive]`, `#[from]`, messages name variables not values) and the pure form-body parser used by the OAuth flow.
      Files: `src/core/status.rs`, `src/core/config.rs`, `src/core/authorize_url.rs`, `src/core/tls_fingerprint.rs`, `src/core/relay.rs`, `src/core/error.rs`.
      Verify: `cargo test` for these modules passes: `insta` snapshot of `{"authorized":false}`/`{"authorized":true}` (AC-10); config missing/empty each var (AC-11); authorize-URL encode-neutral literal (AC-12) plus a `+`/`/`/`=` form-encoding test proving `oauth_encode` is not reused; `tls_fingerprint` against a precomputed SHA-256 vector; relay whitelist table test. Clippy clean.

- [ ] 6. Implement the shell seams that feed the core: env snapshot, clock/nonce generators, config loading, loopback bind helper, and shell error enums.
      In `shell/env.rs` define `snapshot() -> EnvSnapshot` (the only `std::env` reads: the two credential vars). In `shell/clock_nonce.rs` define `Clock{fn now_unix(&self)->Timestamp}` and `NonceSource{fn next(&self)->Nonce}` traits with real impls (`SystemTime::now()` with the documented pre-1970 `expect`; CSPRNG via `rand`, fresh `Nonce` per call) and deterministic test fakes (fixed clock, counter nonce). In `shell/server.rs` define `bind_addr(ListenPort) -> SocketAddr` hard-coding `Ipv4Addr::LOCALHOST`. In `shell/error.rs` define `TlsError`, `OauthFlowError`, `ProxyError`, `ServerError` per the design (with `#[from]`, `#[non_exhaustive]`, and the leg-path diagnostic messages that name the endpoint constant and flag `oauth_callback=oob` as an unverified assumption on the request-token leg).
      Files: `src/shell/env.rs`, `src/shell/clock_nonce.rs`, `src/shell/server.rs` (bind_addr only for now), `src/shell/error.rs`, `src/shell/mod.rs`.
      Verify: `cargo test shell::server::bind_addr` passes AC-9 (loopback for all ports); unit test that two `NonceSource::next()` calls differ (real) / increment (fake). Clippy clean.

- [ ] 7. Implement TLS cert generation, the OAuth three-leg startup flow, and the stdin/stdout prompt shell.
      In `shell/tls.rs` generate an ephemeral rcgen `0.14` cert (`generate_simple_self_signed(["127.0.0.1".into()])`), hash `cert.der()` via `core::tls_fingerprint::fingerprint`, print the fingerprint, and build the rustls `ServerConfig` from `signing_key.serialize_der()` (`PrivateKeyDer::Pkcs8`) + `cert.der()`. In `shell/prompt.rs` implement printing the authorize URL/fingerprint and reading+trimming the stdin verifier (empty ⇒ `OauthFlowError::EmptyVerifier`, no re-prompt). In `shell/oauth_flow.rs` implement `run(&Config,&dyn Clock,&dyn NonceSource) -> Result<Authorized,OauthFlowError>`: for each leg draw a fresh `(nonce,ts)` immediately before signing via `sign_leg`, POST with reqwest, parse the form body with the core parser (leg 1 also parses-and-logs `oauth_callback_confirmed`), print the authorize URL from `core::authorize_url`, read the verifier, exchange for the access token, return `Authorized`.
      Files: `src/shell/tls.rs`, `src/shell/prompt.rs`, `src/shell/oauth_flow.rs`.
      Verify: `cargo test` compiles these; `cargo build` succeeds. A `wiremock` integration test (AC-13) drives the three-leg flow against a fake upstream and asserts an `Authorized` is produced, the request-token base string contains `oauth_callback=oob`, the access-token base string contains `oauth_verifier=<code>`, and the two legs carry distinct `oauth_nonce` values. Clippy clean.

- [ ] 8. Implement the shared auth state, the axum router/handlers, the signed upstream forward with bounded relay, and wire up `main`.
      In `shell/state.rs` define `AuthPhase::{Pending,Ready(Arc<Authorized>)}` behind `Arc<std::sync::RwLock<AuthPhase>>`, with the status-phase match (guard dropped before any `.await`). In `shell/handlers.rs` + `shell/upstream.rs` implement the axum fallback handler: convert axum `Method`/path into core types, call `admit`; on `Forward` clone the `Arc<Authorized>`, `split_query`, build `upstream_base_url`, draw a fresh `(nonce,ts)`, `sign_leg` the `Resource` leg, build the wire URL from `wire_query`, GET via reqwest, buffer the body with the `UPSTREAM_BODY_CAP = 8 MiB` cap (`UpstreamTooLarge → 502`), relay status + whitelisted headers (via `core::relay`, drop `Content-Length`/hop-by-hop) + buffered body; `Pending ⇒ 503`; on `Status` serialize from phase; on `Reject` map `MethodNotGet→405`, `OutOfPrefix→404` (never forward). In `shell/server.rs` finish `serve(port,tls,state,clock,nonces)` binding `bind_addr(port)` via axum-server TLS. In `main.rs` wire the startup sequence (clap `--port` default 8443 → env snapshot → `build_config` → tls → oauth_flow → store `Ready` → serve) with `anyhow` + `.context`, non-zero exit before any bind on config failure.
      Files: `src/shell/state.rs`, `src/shell/handlers.rs`, `src/shell/upstream.rs`, `src/shell/server.rs`, `src/main.rs`.
      Verify: `cargo build` and `cargo test` pass. Clippy clean.

- [ ] 9. Add the shell integration test suite (wiremock, local-fake only) and run the full verification gate.
      Add `tests/` integration tests (AC-13): proxy forward over `wiremock` — `GET /etrade-api/v1/accounts/list?x=1` reaches the fake as `GET /v1/accounts/list?x=1` with a signed header; a `POST` under the proxy prefix returns `405` and the mock records ZERO upstream hits; an out-of-prefix `GET` returns `404`. `/internal/status` over the real rustls stack in both phases, driving `Pending` by passing a `Pending` state into `serve` (also exercises the `503`/`NotReady` branch). Nonce freshness: counter-backed `NonceSource` injected via `serve`, two sequential proxied GETs carry distinct `oauth_nonce`. An integration test that rcgen produces a usable cert whose DER hashes to the fingerprint format.
      Files: `tests/proxy_forward.rs`, `tests/status.rs`, `tests/oauth_flow.rs`, `tests/tls.rs` (or a consolidated `tests/integration.rs`).
      Verify: the full gate green — `cargo build`, `cargo clippy --all-targets --all-features -- -D warnings` (zero warnings, AC-2), `cargo test` (all unit + proptest + integration pass, AC-1/AC-3). No test performs a live ETrade call (AC-13).

## Notes / assumptions

- The ETrade OAuth leg paths, authorize URL, and `oauth_callback=oob` value are
  documented assumptions per the design's feasibility note; they are isolated in
  `core::oauth::endpoints` and confirmed on the first live run. AC-13 forbids
  live calls, so the test suite passes regardless; the leg-path diagnostic error
  messages make a wrong value self-announcing on first run.
- Exact pinned crate versions are chosen at implementation time from the latest
  compatible releases of the locked crate set; validate the pinned `secrecy
  0.10`, `rcgen 0.14`, and `base64 0.22` APIs at build time as the design directs.
