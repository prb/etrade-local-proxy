# Implementation Plan: `--sandbox` CLI flag

## Verification note (first iteration — implemented)

Ran in the repo root:

- `cargo build` — success, zero warnings.
- `cargo clippy --all-targets --all-features -- -D warnings` — success, **0
  warnings**.
- `cargo test` — **119 passed, 0 failed** across lib, integration, and
  doc-tests. Every pre-existing live-default `api.etrade.com` assertion stayed
  green; new sandbox-path assertions added beside them.
- Core-purity litmus:
  `grep -rn "tokio\|axum\|reqwest\|rustls\|std::env\|std::io" src/core/` — the
  only 3 matches are doc comments (`src/core/oauth/mod.rs:34` and
  `src/core/mod.rs:4-5`); no code references. Host arrives as data.
- `cargo run -- --help` lists `--sandbox` (absent = live `api.etrade.com`,
  present = sandbox `apisb.etrade.com`).

New sandbox-path tests added: `env::{live_maps_to_live_host,
sandbox_maps_to_sandbox_host, default_environment_is_live}`;
`endpoints::endpoint_url_uses_sandbox_host`;
`base_string::upstream_base_url_sandbox_host`;
`sign::resource_leg_base_string_uses_sandbox_host` (signing-matches-sending:
base string computed against `apisb.etrade.com`, never `api.etrade.com`);
`config::sandbox_environment_is_carried`;
`shell::oauth_flow::endpoint_url_none_uses_sandbox_host`;
`shell::upstream::build_url_none_uses_sandbox_host`. All preserved invariants
(GET-only admission, loopback bind, in-memory creds, three-leg typed signing,
injected clock/nonce, 8 MiB cap, thiserror-per-module) untouched.

---

# Implementation Plan: `--sandbox` CLI flag

Incremental change to a mature, green codebase. The live host is currently
hardcoded via `core::oauth::endpoints::UPSTREAM_HOST = "api.etrade.com"` and read
directly by three base-URL construction sites. This plan threads the upstream
host as **data** from a new CLI flag through `Config` into the pure-core signing
path, so signing and sending always use the same host, while keeping the core
free of env/config globals and keeping every existing live-default assertion
green.

## Design decisions (made here, grounded in the code read)

- **Model the environment as a sum type with a host newtype, both in the pure
  core.** New module `src/core/env.rs`: `enum Environment { Live, Sandbox }`
  (derive `Clone, Copy, Debug, PartialEq, Eq`, `#[default] = Live`) and
  `struct UpstreamHost(&'static str)` (a newtype over the host literal, per the
  steering doc's "newtypes over bare primitives" and "illegal states
  unrepresentable"). `Environment::host(self) -> UpstreamHost` is the single
  mapping: `Live -> api.etrade.com`, `Sandbox -> apisb.etrade.com`. This
  encapsulates the apisb-vs-api distinction in one place so no caller handles it
  directly (CONCEPT.md requirement). Rationale: a sum type + newtype makes the
  two hosts the only representable options and keeps the literal in one spot,
  mirroring the existing `endpoints` "single source of truth" posture.
- **Keep `endpoints::UPSTREAM_HOST` as the Live literal, consumed by the
  mapping.** `Environment::Live.host()` returns `UpstreamHost(UPSTREAM_HOST)` and
  `Environment::Sandbox.host()` returns `UpstreamHost(SANDBOX_UPSTREAM_HOST)`
  (a new sibling constant in `endpoints.rs`). This preserves the existing
  "`api.etrade.com` appears once" invariant and adds the sandbox literal beside
  it with the same first-run-verification doc treatment. `env.rs` depends on
  `endpoints` for the literals; `endpoints` gains no dependency on `env`
  (no cycle).
- **Thread `&UpstreamHost` as a parameter into every base-URL construction
  site** rather than storing it in a core global. The three sites —
  `endpoints::oauth_endpoint_url`, `base_string::upstream_base_url`, and
  `sign::base_url_for` (hence `sign::sign_leg`) — gain a leading
  `host: &UpstreamHost` parameter. The core stays pure: the host is data passed
  in by the shell, never read from env/config inside core (grep-verifiable
  invariant preserved).
- **`Environment` lives in `Config`** (shell → core config boundary), set from
  the CLI flag at `build_config`. Shell signing call sites
  (`shell::oauth_flow::run`, `shell::upstream::forward`) obtain
  `config.environment().host()` and pass it into the core. This is the
  CLI-parse → config → core signing/base-URL data flow.
- **`AUTHORIZE_URL_BASE` is NOT touched.** `authorize_url::authorize_url` keeps
  reading `endpoints::AUTHORIZE_URL_BASE` directly; the flag never affects it
  (CONCEPT.md: authorize URL identical in both environments).
- **The test-only `base_url_override` seams are preserved and left orthogonal.**
  They continue to rewrite only the *sent* URL host (wiremock), while the
  *signed* host now comes from the injected `UpstreamHost`. Production host
  selection and the test override are layered cleanly and independently.
- **Signing-matches-sending for sandbox.** Because both `base_url_for` (signing)
  and `build_url`/`endpoint_url` (sending) derive their host from the same
  `UpstreamHost` value in production (`None` override), a sandbox run signs AND
  sends against `apisb.etrade.com`. This is the correctness crux and gets an
  explicit test.

## Preserved invariants (do not regress)

Verb-first GET-only admission in both environments; loopback-only `127.0.0.1`
bind constant; in-memory creds + fresh OAuth flow per startup; three-leg typed
`SigningInput` → one base-string builder → one header builder; injected
clock/nonce (fresh per leg/request); 8 MiB relay cap; multiset query handling;
`thiserror`-per-module with `anyhow` only at `main`; pure-core/thin-shell
boundary (core references no `tokio`/`axum`/`reqwest`/`rustls`/`std::env`/
`std::io` outside doc comments). mTLS stays out of scope.

Build command: `cargo build`. Test command: `cargo test`. (Verified green at
plan time; integration tests use the wiremock seams only — no live/sandbox
network calls.)

---

## Steps

- [ ] 1. Add the `Environment` sum type and `UpstreamHost` newtype in a new pure-core module, plus the sandbox host literal.
      Create `src/core/env.rs` with `enum Environment { Live, Sandbox }`
      (`Clone, Copy, Debug, PartialEq, Eq`, default `Live`), a
      `struct UpstreamHost(&'static str)` newtype with `as_str(&self) -> &str`,
      and `Environment::host(self) -> UpstreamHost`. Add
      `pub const SANDBOX_UPSTREAM_HOST: &str = "apisb.etrade.com";` to
      `src/core/oauth/endpoints.rs` beside `UPSTREAM_HOST`, with the same
      "documented assumption / confirm on first live run" doc comment style; map
      `Live -> UpstreamHost(endpoints::UPSTREAM_HOST)` and
      `Sandbox -> UpstreamHost(endpoints::SANDBOX_UPSTREAM_HOST)`. Register the
      module in `src/core/mod.rs` (`pub mod env;`). Add unit tests in `env.rs`:
      `Environment::Live.host().as_str() == "api.etrade.com"`,
      `Environment::Sandbox.host().as_str() == "apisb.etrade.com"`, and that
      `Environment::default() == Environment::Live`.
      Files: `src/core/env.rs` (new), `src/core/oauth/endpoints.rs`,
      `src/core/mod.rs`
      Verify: `cargo test --lib core::env` passes; `cargo build` succeeds.

- [ ] 2. Thread `&UpstreamHost` into the OAuth-leg URL builder in `endpoints.rs`.
      Change `oauth_endpoint_url(path: &str)` to
      `oauth_endpoint_url(host: &UpstreamHost, path: &str)` building
      `format!("https://{}{}", host.as_str(), path)`. Update the existing
      `endpoint_url_uses_single_host_constant` test to pass
      `&Environment::Live.host()` and keep asserting the `api.etrade.com` URLs;
      add a sibling assertion passing `&Environment::Sandbox.host()` and
      expecting `https://apisb.etrade.com/oauth/request_token` and
      `.../oauth/access_token`. (Import `Environment`/`UpstreamHost` from
      `crate::core::env`.)
      Files: `src/core/oauth/endpoints.rs`
      Verify: `cargo test --lib core::oauth::endpoints` passes (both live and
      sandbox leg-URL assertions green).

- [ ] 3. Thread `&UpstreamHost` into `upstream_base_url` in `base_string.rs`.
      Change `upstream_base_url(path: &str)` to
      `upstream_base_url(host: &UpstreamHost, path: &str)` building
      `format!("https://{}{}", host.as_str(), path)`. Update the module's
      existing tests that call `upstream_base_url` and the hardcoded
      `"https://api.etrade.com/..."` base-URL literals in `signature_base_string`
      tests to pass `&Environment::Live.host()` where the function is now called;
      keep every live assertion value unchanged. Add one unit test
      `upstream_base_url_sandbox_host` asserting
      `upstream_base_url(&Environment::Sandbox.host(), "/v1/accounts/list") ==
      "https://apisb.etrade.com/v1/accounts/list"`.
      Files: `src/core/oauth/base_string.rs`
      Verify: `cargo test --lib core::oauth::base_string` passes (live defaults
      green, new sandbox assertion green).

- [ ] 4. Thread `&UpstreamHost` through `sign::base_url_for` and `sign::sign_leg`.
      Change `base_url_for(input)` to `base_url_for(host, input)`, passing `host`
      into `oauth_endpoint_url(host, ...)` and `upstream_base_url(host, ...)` for
      all three legs. Change `sign_leg(input, consumer_secret, query_params,
      nonce, timestamp)` to take a leading `host: &UpstreamHost` and forward it
      to `base_url_for`. Update all in-module `sign.rs` tests and proptests that
      call `sign_leg`/`upstream_base_url` to pass `&Environment::Live.host()`,
      keeping the existing `api.etrade.com` expectations. Add a focused unit test
      `resource_leg_base_string_uses_sandbox_host`: sign a `Resource` leg with
      `&Environment::Sandbox.host()` for `/v1/accounts/list` and assert the base
      string contains `oauth_encode("https://apisb.etrade.com/v1/accounts/list")`
      and does NOT contain the encoded `api.etrade.com` URL — proving the
      signature base string for a sandbox request is computed against
      `apisb.etrade.com` (signing matches sending).
      Files: `src/core/oauth/sign.rs`
      Verify: `cargo test --lib core::oauth::sign` passes (all live/default
      proptests green, new sandbox base-string test green).

- [ ] 5. Add `Environment` to `Config` and set it from a new `build_config` parameter.
      In `src/core/config.rs`: add a private `environment: Environment` field to
      `Config`, a `pub fn environment(&self) -> Environment` accessor, and change
      `build_config(env: &EnvSnapshot, port: ListenPort)` to
      `build_config(env: &EnvSnapshot, port: ListenPort, environment: Environment)`,
      storing it. Update the in-module config tests to pass
      `Environment::Live` and add one assertion that
      `config.environment() == Environment::Live`; add a test that building with
      `Environment::Sandbox` yields `config.environment() == Environment::Sandbox`.
      (This is a buildable step on its own; callers are updated in the next
      steps.)
      Files: `src/core/config.rs`
      Verify: `cargo test --lib core::config` passes.

- [ ] 6. Update core unit-test and shell `build_config` call sites for the new signature (compile-fix sweep, same pattern across files).
      Pass the third `Environment` argument (`Environment::Live` to preserve
      current behavior) at every `build_config(...)` call site outside
      `config.rs`: `src/shell/oauth_flow.rs` (`test_config`),
      `src/shell/upstream.rs` (`config`), and the integration helper
      `tests/common/mod.rs` (`test_config`). Also update the `sign_leg(...)`
      call sites that live in shell production code to pass the host from config
      (handled in steps 7–8); this step is only the `build_config` arity fix.
      Files: `src/shell/oauth_flow.rs`, `src/shell/upstream.rs`,
      `tests/common/mod.rs`
      Verify: `cargo build --tests` compiles (these call sites no longer error);
      `cargo test --lib core` passes.

- [ ] 7. Pass the selected host from `Config` into the OAuth three-leg flow.
      In `src/shell/oauth_flow.rs`: compute `let host = config.environment().host();`
      once at the top of `run`, pass `&host` into both `sign_leg(&host, ...)`
      calls (legs 1 and 2), and change the private `endpoint_url` helper to
      `endpoint_url(host: &UpstreamHost, base_url_override, path)` so the
      non-override branch calls `oauth_endpoint_url(host, path)` while the
      override branch is unchanged (wiremock still rewrites the sent host). Update
      the in-module `endpoint_url_uses_override_host` test to pass
      `&Environment::Live.host()` and keep the `None`→`https://api.etrade.com/...`
      expectation; add a `None`→sandbox case asserting
      `https://apisb.etrade.com/oauth/request_token` when
      `&Environment::Sandbox.host()` is passed.
      Files: `src/shell/oauth_flow.rs`
      Verify: `cargo test --test oauth_flow` and
      `cargo test --lib shell::oauth_flow` pass (wiremock three-leg flow green;
      live + sandbox `endpoint_url` unit cases green).

- [ ] 8. Pass the selected host from `Config` into the proxy forward path.
      In `src/shell/upstream.rs`: compute `let host = config.environment().host();`
      in `forward`, pass `&host` into `sign_leg(&host, ...)`, and change
      `build_url(base_url_override, path, wire)` to
      `build_url(host: &UpstreamHost, base_url_override, path, wire)` so the
      non-override branch calls `upstream_base_url(host, path)` and the override
      branch is unchanged. Update the in-module `build_url_preserves_path_and_query`
      test to pass `&Environment::Live.host()` (keeping the
      `None`→`https://api.etrade.com/...` expectation) and add a
      `None`→sandbox assertion expecting
      `https://apisb.etrade.com/v1/accounts/list`.
      Files: `src/shell/upstream.rs`
      Verify: `cargo test --test proxy_forward` and
      `cargo test --lib shell::upstream` pass (wiremock forward path green; live
      + sandbox `build_url` unit cases green).

- [ ] 9. Add the `--sandbox` CLI flag and wire it through `main`.
      In `src/main.rs`: add `#[arg(long, default_value_t = false)] sandbox: bool`
      to the `Cli` struct beside `port` (clap derive, no env var — the flag is
      the only interface). In `run`, map it to the core type:
      `let environment = if cli.sandbox { Environment::Sandbox } else { Environment::Live };`
      and pass `environment` as the new third argument to `build_config(...)`.
      Import `Environment` from `etrade_local_proxy::core::env`. The flow,
      forward, and server wiring already read the host from `config`, so no
      further `main` changes are needed. (Absent flag = live; present = sandbox.)
      Files: `src/main.rs`
      Verify: `cargo build` succeeds; `cargo run -- --help` lists `--sandbox`;
      run `cargo run -- --sandbox --help`-style parse is not needed, but
      `cargo build` plus the full suite below covers wiring.

- [ ] 10. Full-suite regression + core-purity confirmation.
      Run the entire build and test suite and confirm the core-purity grep
      invariant still holds (host arrives as data; core references no shell deps
      outside doc comments).
      Files: none (verification only)
      Verify: `cargo build` and `cargo test` both succeed with every existing
      live-default assertion green and the new sandbox assertions green; and
      `grep -rn "std::env\|std::io\|tokio\|axum\|reqwest\|rustls" src/core/`
      returns only doc-comment (`///`/`//!`) matches — no code references.

## Notes / assumptions

- `apisb.etrade.com` is the ETrade sandbox API host per CONCEPT.md and the
  ETrade authorization docs; like the existing live constants it is a documented
  assumption confirmed on first live run, not an automated-test target (AC-13 /
  no live calls).
- The `#[allow(clippy::too_many_arguments)]` already present on
  `server::app_state` is unaffected; the host is read from `Config` inside the
  shell, so no new argument is threaded through `server::serve`/`app_state`.
- If a reviewer prefers the environment to be carried explicitly through
  `AppState` rather than re-derived from `config.environment()` in `forward`,
  that is a cosmetic refactor with identical behavior; this plan keeps it in
  `Config` to minimize the change surface and avoid touching the loopback-bind
  server seam.
