## Verification evidence (iteration 1)

Ran from the repo root on branch `main` after implementing the probe.

- `cargo build` — clean (`Finished dev profile` in ~2.9s, no warnings).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean, zero
  warnings (`Finished dev profile`, exit 0).
- `cargo test` — all green. Per-binary summary:
  - lib unit tests (`src/lib.rs`): 113 passed (includes the 3 new
    `shell::probe` count-extraction unit tests).
  - `tests/oauth_flow.rs`: 2 passed.
  - `tests/probe.rs` (new): 3 passed — success/count, fail-fast on 401,
    2xx-unparseable → unknown count.
  - `tests/proxy_forward.rs`: 4 passed (unchanged — forward path byte-identical).
  - `tests/status.rs`: 2 passed. `tests/tls.rs`: 1 passed. Doc-tests: 0.
  - Totals: 113 lib + 12 integration = 125 tests, 0 failed.
- Core-purity grep still holds — `grep -rnE 'tokio|axum|reqwest|rustls|std::env|std::io' src/core/`
  returns only three doc-comment lines (`src/core/oauth/mod.rs:34` `///`,
  `src/core/mod.rs:4` and `:5` `//!`); no code matches, core untouched.

The change is entirely in the imperative shell: `src/shell/upstream.rs`
(extracted shared `signed_get`, `forward` now delegates), `src/shell/error.rs`
(new `ProbeError`), `src/shell/probe.rs` (new), `src/shell/mod.rs` (registered),
`src/main.rs` (wired between OAuth and serve), `tests/probe.rs` (new).

# Implementation Plan — Startup Authorization-Validation Probe

Additive, shell-only enhancement to the existing ETrade local proxy. After the
OAuth flow yields `Authorized` and before serving, make one signed
`GET /v1/accounts/list` to validate the token, log the account count on success,
and fail fast (exit non-zero, do not serve) on any non-2xx or transport error.

Working directly in `/Users/paulbrown/Code/etrade-local-proxy` on branch `main`.
No worktree. Core under `src/core/` stays untouched.

## Design decisions (grounded in the code read during exploration)

- **Share signing by extracting `signed_get` in `src/shell/upstream.rs`.**
  `forward(...)` today does: `split_query` → `ResourcePath::new` → read
  `config.environment().host()` → draw fresh `(ts, nonce)` → `sign_leg` with
  `SigningInput::Resource` → `build_url` (honoring `base_url_override`) →
  `client.get(url).header(AUTHORIZATION, ...)` → `read_bounded`. Extract that
  whole body verbatim into a new `pub async fn signed_get(...)` with the SAME
  parameter list as `forward`, and make `forward` a thin delegator
  (`signed_get(...).await`). This keeps the proxy handler's behavior
  byte-for-byte identical (same signing, same host threading, same fresh nonce,
  same 8 MiB bounded relay, same override seam) while giving the probe one
  shared entry point. Chosen over duplicating signing in the probe (would
  violate the "reuse this exact machinery" requirement and risk drift).
- **Probe lives in a new `src/shell/probe.rs`,** not in `upstream.rs`. The probe
  adds accounts-JSON counting, which is probe-specific concern; `upstream.rs`
  stays focused on signed relay. The probe calls `upstream::signed_get`.
- **New startup error type `ProbeError` in `src/shell/error.rs`** (its own
  `#[non_exhaustive]` `thiserror` enum), NOT a new `ProxyError` variant.
  `ProxyError` variants each map to a live HTTP status for the running server;
  the probe is a fatal *startup* concern like `OauthFlowError`/`ServerError`, so
  a dedicated startup error matches the per-module convention. It carries the
  non-2xx status code and wraps transport/relay failures.
- **Count via a focused serde struct with everything optional.** Model
  `AccountListResponse { accounts: Option<Accounts> }`,
  `Accounts { account: Option<Vec<serde_json::Value>> }` using serde `rename`
  for ETrade's `AccountListResponse` / `Accounts` / `Account` casing. A 2xx body
  that doesn't match yields `None` (count unknown) rather than an error — a 2xx
  means the token is accepted, so authorization is validated regardless of body
  shape. Parsing stays in the shell (serde_json already a dependency).
- **Count is `Option<usize>`:** `Some(n)` logs `— N accounts`; `None` logs
  `— account count unknown`. Both are SUCCESS for authorization.
- **main wiring:** the probe runs in `src/main.rs::run` between
  `oauth_flow::run(...)?` (producing `authorized`) and
  `state::ready(authorized)` + `server::serve(...)`. It reuses the already-built
  `clock`/`nonces` (drawing its own fresh `(ts, nonce)` inside `signed_get`) and
  passes `None` for the override (production). `main` adds `.context(...)` so
  `anyhow` renders it at the edge and returns `ExitCode::FAILURE`.
- **`/internal/status` semantics unchanged.** The probe does not touch the
  typestate; `authorized:true` still means the OAuth handshake completed. The
  probe gates *serving*, not the status flag.

## Plan

- [ ] 1. Extract the shared signed-GET helper in `src/shell/upstream.rs`.
      Add `pub async fn signed_get(...)` with the exact same parameter list and
      return type as the current `forward` (`client, config, authorized,
      mapped_path, base_url_override, clock, nonces` → `Result<RelayedResponse,
      ProxyError>`); move the current body of `forward` into it unchanged
      (split_query, SigningInput::Resource signing, build_url, send, read_bounded).
      Reduce `forward` to `signed_get(client, config, authorized, mapped_path,
      base_url_override, clock, nonces).await`. Keep `build_url`, `read_bounded`,
      `UPSTREAM_BODY_CAP`, and `RelayedResponse` as-is. Do not change any
      behavior; the handler path must be byte-for-byte identical.
      Files: src/shell/upstream.rs
      Verify: `cargo test --test proxy_forward` and `cargo test upstream` — all
      existing forward/signing tests still pass unchanged.

- [ ] 2. Add the `ProbeError` startup error enum in `src/shell/error.rs`.
      New `#[derive(Debug, Error)] #[non_exhaustive] pub enum ProbeError` with:
      a transport/relay variant `#[from] ProxyError` (so `signed_get`'s error
      propagates with `?`) rendered as a terse "authorization validation probe
      failed" message, and a `NonSuccessStatus { code: u16 }` variant whose
      `#[error(...)]` message includes the status code (e.g. "authorization
      validation probe GET /v1/accounts/list returned HTTP {code}"). No token
      material in any message. Mirror the style of the existing
      `OauthFlowError`/`ServerError` enums in this file.
      Files: src/shell/error.rs
      Verify: `cargo build` succeeds (unused-variant warnings are expected until
      the probe wires it in step 4).

- [ ] 3. Create the probe module `src/shell/probe.rs` and register it in
      `src/shell/mod.rs` (`pub mod probe;`).
      Add `pub async fn validate(client, config, authorized, base_url_override,
      clock, nonces) -> Result<usize_count, ProbeError>` — return
      `Result<Option<usize>, ProbeError>` where `Ok(Some(n))`/`Ok(None)` is a
      validated token (n = account count, None = 2xx but unknown shape) and
      `Err` is fail-fast. Internals: call
      `upstream::signed_get(client, config, authorized, "/v1/accounts/list",
      base_url_override, clock, nonces).await?`; if the relayed status is not
      2xx return `Err(ProbeError::NonSuccessStatus { code })`; on 2xx parse the
      body with the focused `AccountListResponse` serde struct (private to this
      module), returning `Ok(count)` where count is
      `resp.accounts.and_then(|a| a.account).map(|v| v.len())`. Keep the serde
      structs private; every field `Option` so an unexpected shape yields
      `Ok(None)` not an error. Add a `#[cfg(test)] mod tests` with a unit test
      that the count-extraction logic maps a known Accounts.Account array to the
      right length and an unparseable `serde_json` value to `None` (pure, no
      network).
      Files: src/shell/probe.rs, src/shell/mod.rs
      Verify: `cargo test --lib probe` — the new unit tests for count extraction
      pass; `cargo build` succeeds.

- [ ] 4. Wire the probe into startup in `src/main.rs::run`.
      After `let authorized = oauth_flow::run(...).await.context(...)?;` and
      BEFORE `state::ready(authorized)` / `server::serve(...)`, create a
      `reqwest::Client`, call
      `probe::validate(&client, &config, &authorized, None, clock.as_ref(),
      nonces.as_ref()).await.context("authorization validation failed")?`, then
      log to stderr: `Some(n)` → `eprintln!("info: authorization validated via
      GET /v1/accounts/list — {n} accounts");`, `None` →
      `eprintln!("info: authorization validated via GET /v1/accounts/list —
      account count unknown");`. On `Err`, the `?` + `.context` propagates to
      `main`, which prints `error: ...` and returns `ExitCode::FAILURE` without
      serving. Add the `use` for `probe` (and `reqwest::Client` if not present).
      Do not change the status typestate, the bind constant, or the serve call.
      Files: src/main.rs
      Verify: `cargo build` succeeds with no unused-variant/import warnings;
      `cargo clippy --all-targets -- -D warnings` is clean.

- [ ] 5. Add the wiremock integration tests in a new `tests/probe.rs`.
      Follow the `tests/proxy_forward.rs` / `tests/oauth_flow.rs` patterns:
      `mod common;` for `test_config`, drive `probe::validate` directly with
      `Some(server.uri())` as the override, `FixedClock::new(1_700_000_000)`, and
      `CounterNonceSource::new()`. Three tests:
      (1) SUCCESS — mock `GET /v1/accounts/list` → 200 with a small
      `AccountListResponse` JSON containing a known number (e.g. 2) of
      `Accounts.Account[]` entries; assert `Ok(Some(2))` and assert the recorded
      upstream request carries a signed `Authorization: OAuth ...` header at
      path `/v1/accounts/list`.
      (2) FAIL-FAST — mock the same path → 401; assert `validate` returns
      `Err(ProbeError::NonSuccessStatus { code: 401 })` (startup would abort).
      (3) 2xx-UNPARSEABLE — mock → 200 with a body that doesn't match the shape
      (e.g. `{"unexpected":true}` or `"not-json-object"`); assert `Ok(None)`
      (authorization validated, count unknown, no error).
      Files: tests/probe.rs
      Verify: `cargo test --test probe` — all three tests pass with no live
      calls.

- [ ] 6. Full verification sweep.
      Run the whole suite, clippy, and re-confirm core purity after all changes.
      Files: (none — verification only)
      Verify: `cargo test` passes (prior 110+ unit and all integration tests
      green, plus the 3 new probe tests); `cargo clippy --all-targets --
      -D warnings` clean; and the core-purity grep still shows only doc-comment
      matches:
      `grep -rnE 'tokio|axum|reqwest|rustls|std::env|std::io' src/core/`
      returns only `//`/`//!` doc-comment lines (the change is shell-only; no
      new `src/core/` edits).

## Notes / assumptions

- ETrade `accounts/list` JSON is `AccountListResponse.Accounts.Account[]`; serde
  `rename` handles the PascalCase keys. All-`Option` fields make the parse total,
  satisfying the "be defensive on unexpected 2xx shape" requirement.
- The probe uses the SAME override seam as the proxy (`base_url_override` passed
  straight into `signed_get`), so tests hit wiremock and production hits the
  selected `--sandbox`/live host — no divergence.
- `ProbeError` wrapping `ProxyError` via `#[from]` covers both the transport
  error case (reqwest `send`) and the over-cap case uniformly; both are
  fail-fast at startup, which matches the CONCEPT.md "network error" clause.
