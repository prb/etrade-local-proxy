# Technical Design: ETrade Local Read-Only Proxy

## Overview

This is a from-scratch Rust CLI binary that runs a local HTTPS reverse proxy in
front of the live ETrade API, structurally exposing only the `GET` read surface
under `/v1/accounts/*`. The design follows the workspace steering doc
(`.kiro/steering/rust-functional-style.md`): a **pure functional core** of
plain-value transformations (OAuth signature construction, the GET-only
admission decision, path mapping, status serialization, config validation,
authorize-URL building) sits behind a **thin imperative shell** (the Tokio async
runtime, the TLS listener, the outbound HTTP client, stdin/stdout prompts,
environment reads, the system clock and RNG). The core is unit- and
property-testable with plain values — no network, no async runtime, no mocks —
and every source of non-determinism (clock, nonce) is injected into core
functions by the shell. Errors are values: each library-style module exposes a
`#[non_exhaustive]` `thiserror` enum, `?` propagates with `#[from]`-generated
conversions, and `anyhow` appears only in `main`. The unauthorized → authorized
lifecycle is a consuming typestate, not a boolean-plus-`Option` pair.

The sections below lock the technology stack, the module layout, each core
function's signature and behavior, the shared-state model, error hierarchy,
error-handling and validation rules per fallible operation, the security
invariants and their enforcing layer, and the test strategy. Once approved, the
stack is fixed.

## Technology Stack (locked)

- **Edition / toolchain:** Rust 2021, stable toolchain.
- **Async runtime:** `tokio`, **`current_thread` flavor** via
  `#[tokio::main(flavor = "current_thread")]`. The shell is inherently
  effectful and Tokio is the de-facto standard, but this is a loopback-only,
  single-user read proxy with no concurrency pressure, so a single-threaded
  runtime is the closer fit to the "thin shell" ethos and is marginally leaner.
  axum and reqwest both run fine on `current_thread`. (Resolves review NIT #10:
  the multi-thread flavor is unjustified for this workload, so we constrain to
  `current_thread` deliberately.)
- **HTTP server + client:** `axum` (server) over `hyper`, and `reqwest`
  (outbound client). **Chosen over** hand-rolling on bare `hyper` for both
  sides: axum gives a clean handler/router model that keeps the shell thin and
  delegates every decision to pure core functions, and reqwest gives a batteries
  included client (connection pooling, redirect control, TLS) so the shell holds
  almost no transport logic. Rejected alternative: `hyper`-only on both sides
  would add boilerplate (manual request/response plumbing) with no benefit here;
  the requirements need an ordinary request/response proxy, not low-level control.
- **TLS:** `rustls` everywhere — **chosen over OpenSSL** for a pure-Rust build
  with no system OpenSSL dependency. Server-side: `axum-server` with its
  `tls-rustls` feature terminates TLS from an in-memory cert/key. Client-side:
  `reqwest` with `rustls-tls` (and *not* the default native-TLS feature) so the
  outbound leg is also pure-Rust. Pin reqwest to `default-features = false` plus
  `["rustls-tls", "json"]`.
- **Self-signed certificate:** `rcgen` (pinned to `0.14`) generates an ephemeral
  in-memory cert+key at startup (no file written), consistent with the
  no-persistence posture. **Feature pin (resolves review NIT #2):**
  `generate_simple_self_signed`, `CertifiedKey`, `KeyPair`, and
  `Certificate::der()` all live behind `rcgen 0.14`'s **`crypto` feature, which
  is a default feature in 0.14**, so no non-default feature is required and the
  default `rcgen = "0.14"` dependency compiles as specified — stated explicitly
  here to mirror the explicit `reqwest` (`default-features = false,
  ["rustls-tls","json"]`) and `secrecy` pins. The pinned `0.14` accessor
  contract (resolves NIT #4),
  matching the rigor applied to `secrecy`: `rcgen::generate_simple_self_signed(["127.0.0.1".into()])`
  returns a `CertifiedKey { cert, signing_key }`; the **fingerprint input** is
  `cert.der()` which yields a `&CertificateDer<'_>` (deref to `&[u8]`) hashed by
  `core::tls_fingerprint::fingerprint`; the **rustls private key** is
  `signing_key.serialize_der()` wrapped as
  `rustls::pki_types::PrivateKeyDer::Pkcs8(... .into())`, and the rustls
  certificate chain is built from the same `cert.der().clone()`. The implementer
  validates these exact `0.14` signatures at build time.
- **OAuth 1.0a signing:** **hand-rolled pure functions** in the core, using
  `hmac` + `sha1` for the MAC and `base64` (pinned to `0.22`) for the digest
  encoding, plus a small
  percent-encoding helper (`percent-encoding` crate with a custom
  OAuth/RFC-3986 `AsciiSet`). **Chosen over** an OAuth client crate because the
  steering doc requires the signing logic to be pure and property-testable with
  an **injected** timestamp and nonce; most OAuth crates reach for the system
  clock and an internal RNG, which would push non-determinism into the core and
  defeat the central property tests (AC-4). The surface we need (HMAC-SHA1
  signature base string + `Authorization: OAuth ...` header) is small and
  well-specified, so hand-rolling is lower-risk than fighting a crate's
  effectful API. `hmac`/`sha1` are themselves pure (bytes in, bytes out) and
  stay in the core.
- **Secret material:** `secrecy = "0.10"` (`SecretString`) wraps the consumer
  secret and token secret (NFR-2). The single pinned contract (resolves review
  #4): `SecretString = SecretBox<str>`; construct with
  `SecretString::from(String)`; read the bytes with
  `secrecy::ExposeSecret::expose_secret()` returning `&str`; it derives a
  **redacting `Debug`** and **does not implement `Display`**; and the bytes are
  **zeroized on drop**. The design's `signing_key` folds the exposed `&str` into
  a `String` and is the one and only **source-level** `expose_secret()` call
  site (invoked per leg/request); the exposed value never escapes it. The implementer validates these exact signatures at
  build time against the pinned `0.10` version.
- **Nonce RNG:** `rand` (CSPRNG) backs the shell's `NonceSource`, which produces
  a fresh `Nonce` per call (one per OAuth leg and per proxied request). The RNG
  lives only in the shell; the pure core receives the resulting `Nonce` as an
  injected value (AC-4), so determinism and testability are preserved.
- **Serialization:** `serde` + `serde_json` for the `/internal/status` body.
- **CLI / config:** `clap` (derive) for the `--port` flag; environment reads via
  `std::env`. Rationale: a single optional flag plus two env vars is trivial, and
  clap derive keeps parsing declarative and testable at the pure layer. The
  **listen port is configured solely via the `--port` flag (default `8443`)**;
  no `ETRADE_PORT` (or other) env var is provided. FR-2's "and/or" is satisfied
  by the flag alone (resolves NIT #5), and this keeps all environment reads to
  the single `EnvSnapshot` seam (only the two credential vars).
- **Errors:** `thiserror` (per-module typed enums), `anyhow` (only in `main`).
- **Testing:** `proptest` (pure-core properties), `insta` (snapshot of the
  status JSON and other serialized output), `wiremock` (local fake upstream for
  shell integration tests), `tokio::test` for async shell tests. **wiremock
  chosen** for the fake ETrade endpoints so that AC-13 ("no live ETrade calls")
  holds: the OAuth exchange and the proxy forward are pointed at a local mock
  server in tests.

Dependency versions are pinned to exact minor versions in `Cargo.toml` at
implementation time (per the dependency-safety rule); all are well-known,
actively maintained crates.

## Module Layout (core vs shell)

```
src/
  main.rs            # imperative shell entrypoint; anyhow; wires everything
  lib.rs             # declares modules; re-exports core API for tests

  core/              # PURE. no IO, no async, no tokio, no reqwest/axum types.
    mod.rs
    newtypes.rs      # ConsumerKey, ConsumerSecret, RequestToken, TokenSecret,
                     #   AccessToken, Verifier, Nonce, Timestamp, ListenPort
    config.rs        # Config + pure validation from a captured env snapshot
    admission.rs     # GET-only admission decision + path mapping (central)
    relay.rs         # pure response-header whitelist predicate (relay policy)
    oauth/
      mod.rs         # re-exports; shared oauth_encode (AsciiSet) + split_query
                     #   + wire_query
      endpoints.rs   # the single source of truth for ETrade hosts/paths
      base_string.rs # signature base string construction (pure)
      sign.rs        # HMAC-SHA1 signing + Authorization header build (pure)
      params.rs      # oauth_* parameter assembly from injected nonce/timestamp
    status.rs        # AuthState typestate + status serialization
    authorize_url.rs # authorize URL construction (pure)
    tls_fingerprint.rs # SHA-256(DER) -> lowercase colon-hex (pure)
    error.rs         # core error enums (thiserror)

  shell/             # IMPERATIVE. owns all effects.
    mod.rs
    env.rs           # read env vars -> EnvSnapshot (the only std::env reads)
    clock_nonce.rs   # Clock + NonceSource generator traits + real impls
                     #   (SystemTime -> Timestamp; CSPRNG -> fresh Nonce per call)
    tls.rs           # rcgen cert generation + fingerprint; rustls config
    server.rs        # axum router, loopback bind, handler wiring
    handlers.rs      # /etrade-api/* and /internal/status handlers
    upstream.rs      # reqwest client; signs via core; relays response
    oauth_flow.rs    # 3-leg flow: request token, prompt, access token (IO)
    prompt.rs        # stdin verifier prompt, stdout URL/fingerprint printing
    state.rs         # shared runtime auth state (Arc<RwLock<...>>) wrapper
    error.rs         # shell error enums (thiserror)
```

The `core` tree depends only on `std` plus pure crates (`serde`, `hmac`,
`sha1`, `base64`, `percent-encoding`, `url` for parsing in tests). It must not
reference `tokio`, `axum`, `reqwest`, `rustls`, or `std::env`/`std::io`
directly. This boundary is the litmus test from the steering doc and is enforced
by code review plus the fact that `core` modules compile and test without any
async runtime.

## Pure Core: Function Signatures and Behavior

### Newtypes (`core::newtypes`)

Domain values are newtypes over their primitives so they cannot be transposed:

```rust
pub struct ConsumerKey(String);
pub struct ConsumerSecret(secrecy::SecretString); // see note below
pub struct RequestToken(String);
pub struct TokenSecret(SecretString);
pub struct AccessToken(String);
pub struct Verifier(String);
pub struct Nonce(String);           // injected
pub struct Timestamp(u64);          // injected, unix seconds
pub struct ListenPort(u16);
```

**Clock injection and the `Timestamp` conversion (resolves review #7).** The
pure core only ever receives a `Timestamp(u64)` as a parameter (the inject-the-
clock rule). The shell's `shell::clock_nonce` produces it with
`SystemTime::now().duration_since(UNIX_EPOCH)` and takes `.as_secs()`. That
`duration_since` returns `Err` only if the system clock is before 1970-01-01,
which is an unrecoverable, nonsensical startup condition; this is therefore one
of the **documented `expect()` sites** sanctioned by the steering doc
(`.expect("system clock is before UNIX_EPOCH")`), not a `Result` threaded
through the core. The `Nonce` comes from the shell RNG and is likewise injected.

**Freshness contract: the shell injects generators, not values (resolves
review #1).** The pure core keeps taking plain `&Nonce`/`&Timestamp` values (so
property tests can pin them), but the *shell seam* that feeds them is a pair of
**generator traits**, not pre-computed values, so a fresh `(nonce, timestamp)`
is drawn immediately before signing **each OAuth leg and each proxied request** —
no nonce or timestamp is ever reused across legs or across requests. OAuth 1.0a
requires `oauth_nonce` to be unique per request for a given timestamp/token, and
ETrade rejects a replayed `(timestamp, nonce)` pair with a `401`; because the
AC-13 wiremock upstream does not enforce nonce uniqueness, this contract is made
explicit in the types rather than left to the implementer so a value-reuse
implementation cannot slip through the test suite and fail only on the first
live run. The seam:

```rust
// shell::clock_nonce
pub trait Clock       { fn now_unix(&self) -> Timestamp; }   // current wall-clock seconds
pub trait NonceSource { fn next(&self) -> Nonce; }           // FRESH per call (RNG-backed)
```

The real implementations wrap `SystemTime::now()` (the documented pre-1970
`expect()` above) and a CSPRNG (`rand`), one fresh `Nonce` per `next()` call.
Every signing call site in the shell draws its own `(clock.now_unix(),
nonces.next())` pair *immediately before* calling `sign_leg`; the pure core
never holds or re-emits a prior value. Tests substitute deterministic fakes (a
fixed-time `Clock`, a counter-backed `NonceSource`) to pin inputs where a
property needs reproducibility, and a shell integration assertion checks that
two sequential proxied requests carry **distinct `oauth_nonce` values** in their
recorded upstream headers, pinning the freshness contract at the shell even
though wiremock does not validate nonces upstream (see Testability).

Secret-bearing newtypes (`ConsumerSecret`, `TokenSecret`) wrap
`secrecy::SecretString`. `SecretString` provides a **redacting `Debug`** (it
prints `[REDACTED ...]` rather than the value) and **does not implement
`Display`**, so a secret cannot be formatted into a log line or error message by
accident — this enforces NFR-2 ("never emitted to logs or error messages") at
the type level rather than by discipline. It also **zeroizes the bytes on drop**,
a further NFR-2 benefit. The raw secret is obtainable only through
`secrecy::ExposeSecret::expose_secret()` (returning `&str` at the pinned
`secrecy = "0.10"` contract); the design has exactly one **source-level call
site** — `core::oauth::sign::signing_key`, invoked per leg/request (leg 1 with
an empty token secret, legs 2/3 with a real token secret) — from which the
exposed `&str` never escapes (it is folded into the HMAC key and dropped). `secrecy` is listed and
version-pinned in the locked technology stack above. Non-secret tokens (`RequestToken`,
`AccessToken`, `Verifier`) keep a plain `String`, with a hand-written `Debug`
that truncates/redacts to avoid leaking token material. (Resolves review #4.)

### Admission decision + path mapping (`core::admission`) — central invariant

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Forward(UpstreamPath),   // GET under /etrade-api/v1/accounts
    Status,                  // GET /internal/status
    Reject(RejectReason),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason { MethodNotGet, OutOfPrefix }

/// The upstream path+query produced by mapping an admitted local request,
/// e.g. "/v1/accounts/list?x=1". Still carries the query verbatim; the shell
/// splits it with `core::oauth::split_query` (see "OAuth signing") immediately
/// before signing, so this value and the no-query `base_url` passed to
/// `signature_base_string` are consistent.
pub struct UpstreamPath(String);

/// TOTAL pure function over (method, path+query). Never panics.
pub fn admit(method: &HttpMethod, path_and_query: &str) -> Admission;
```

Design points:

- `method` is a small core enum `HttpMethod` (not axum's `Method`); the shell
  maps axum's method into it. This keeps the core free of framework types and
  makes `HttpMethod` trivially `Arbitrary` for proptest.
- The function is **total**: it returns an `Admission` for every input and never
  panics (AC-8). Parsing the path uses only total string operations
  (`strip_prefix`, split on `?`), never indexing that can panic.
- `admit` is the single source of truth for both the GET-only rule (FR-8) and
  the prefix rule (FR-7). Enforcement is verb-level first: any method other than
  `GET` yields `Reject(MethodNotGet)` regardless of path — so a `POST` to
  `/etrade-api/v1/accounts/{id}/orders` is rejected by the method check before
  the path is even considered. Then:
  - `GET /internal/status` → `Status`.
  - `GET` whose path (before `?`) starts with `/etrade-api/v1/accounts` →
    `Forward`, mapping `/etrade-api` + rest → `/v1/accounts/...` and
    **preserving the query string** verbatim.
  - Every other `GET` → `Reject(OutOfPrefix)`. There is no separate `NotFound`
    reason: a GET that is neither `/internal/status` nor under the proxy prefix
    is uniformly `OutOfPrefix`. Collapsing to a single reason keeps the
    `#[non_exhaustive]` enum minimal and gives AC-6 one deterministic code to
    assert against. (Resolves review #6.)
- Prefix match guards against partial-segment false positives (e.g.
  `/etrade-api/v1/accountsX`): the match requires the next char after the prefix
  to be `/`, `?`, or end-of-string.

**Reject → HTTP status code (one code per reason).** The shell maps each reason
to exactly one status so AC-5/AC-6 have unambiguous assertion targets:

| `RejectReason` | HTTP status | Meaning |
| --- | --- | --- |
| `MethodNotGet` | `405 Method Not Allowed` | any non-`GET` under any path |
| `OutOfPrefix`  | `404 Not Found`          | a `GET` not under `/etrade-api/v1/accounts` and not `/internal/status` |

Nothing is forwarded upstream on either reject (FR-8). (Resolves review #6.)

### OAuth signing (`core::oauth`) — pure, injected nonce/timestamp

This is the most correctness-sensitive part of the design, so the whole pipeline
is specified end to end. Every step is a pure function with injected
nonce/timestamp, independently property-testable. The pipeline is:

The signing domain is modeled around the **three OAuth legs as distinct typed
inputs** (`SigningInput`, below), each carrying exactly the fields its leg
admits. All three feed **one** base-string builder and **one** header builder,
which both derive their output from the *same* `OauthParams.as_pairs()` so the
base string and the `Authorization` header can never diverge (resolves HIGH #1).

```
split_query(upstream_path)                 → (path, query_params)   (decoded, oauth_* dropped; leg 3 only)
oauth_params(&SigningInput, nonce, ts)     → OauthParams   (NO oauth_signature; oauth_token absent on leg 1)
base_params = OauthParams.as_pairs() ++ query_params        (still no signature; query only on leg 3)
signature_base_string(method, base_url, base_params)        → String   (ONE builder, all three legs)
sign_hmac_sha1(base_string, signing_key)                    → base64 signature
authorization_header(&OauthParams, &signature)              → "OAuth ..." header   (ONE builder; renders exactly as_pairs() + signature)
wire_query(query_params)                   → wire query string (same encoder; == signed set)
```

The `split_query`/`wire_query` lines apply to the proxy-forward (resource) leg
only: the outbound URL's query is re-serialized from the *same* `query_params`
that were signed, so the signed and sent query sets are byte-identical (resolves
review #1; see the proxy handler). The two OAuth token legs carry no client
query. Because `signature_base_string` and `authorization_header` are each the
single builder for all three legs and both read `OauthParams.as_pairs()`, the
base-string and header parameter sets are identical on every leg by construction.

#### ETrade endpoint constants (`core::oauth::endpoints`) — single source of truth (resolves review #3)

Every ETrade host and path literal lives here and nowhere else, so the proxied
host cannot drift between `upstream_base_url` and the OAuth flow:

```rust
/// Host for proxied read calls AND the two OAuth token legs. Fixed by FR-5.
/// Live ETrade API host (CONCEPT.md; https://developer.etrade.com/documentation).
pub const UPSTREAM_HOST: &str = "api.etrade.com";

/// OAuth 1.0a leg endpoints. Paths cited from the ETrade authorization docs:
///   request token:  https://apisb.etrade.com/docs/api/authorization/request_token.html
///   access token:   https://apisb.etrade.com/docs/api/authorization/get_access_token.html
/// (the live host is UPSTREAM_HOST; the doc pages use the sandbox host for
/// illustration). These two PATHS are the design's assertion and MUST be
/// confirmed against the live docs before first run — see the feasibility note.
pub const REQUEST_TOKEN_PATH: &str = "/oauth/request_token";
pub const ACCESS_TOKEN_PATH:  &str = "/oauth/access_token";

/// Authorize URL host+path (browser-facing). Fixed by AC-12.
///   https://apisb.etrade.com/docs/api/authorization/authorize.html
pub const AUTHORIZE_URL_BASE: &str = "https://us.etrade.com/e/t/etws/authorize";

/// Convenience: full https URL for an OAuth leg on UPSTREAM_HOST. Builds the
/// string as `format!("https://{UPSTREAM_HOST}{path}")`, so UPSTREAM_HOST is the
/// ONLY source of the host — no literal is duplicated (resolves NIT #5).
pub fn oauth_endpoint_url(path: &str) -> String;
```

`core::oauth::upstream_base_url` (below) builds its host from `UPSTREAM_HOST`;
`shell::oauth_flow` builds its two leg URLs from `oauth_endpoint_url(REQUEST_TOKEN_PATH)`
and `oauth_endpoint_url(ACCESS_TOKEN_PATH)`; `core::authorize_url` builds from
`AUTHORIZE_URL_BASE`. The host literal `api.etrade.com` therefore appears exactly
once.

**Feasibility note / documented assumption (resolves review #3, NIT #3, and
NIT #4).** Three ETrade-API behaviors are the design's assertion, drawn from the
ETrade authorization docs linked in `CONCEPT.md`, and could not be byte-verified
against the live service in this environment:

1. the two OAuth leg *paths* (`/oauth/request_token`, `/oauth/access_token`);
2. the authorize URL host+path (`AUTHORIZE_URL_BASE`);
3. the **`oauth_callback=oob`** value sent on the request-token leg — `oob`
   (out-of-band) is the standard OAuth 1.0a token for a no-redirect flow and
   matches the CONCEPT console-display + stdin-verifier flow, but ETrade could
   require a different callback token (resolves review NIT #3).

None are pinned by the requirements. AC-13 forbids live calls, so the wiremock
tests pass regardless of whether these values match the real API. They are
recorded as **explicit, documented assumptions** — not perpetual blockers: each
is confirmed during manual testing with real credentials on the first live run.

**First-run manual-verification checklist (resolves NIT #3).** On the first live
run with real credentials, confirm: (1) the two leg paths resolve (leg 1 and leg
2 return 2xx, not 404); (2) the authorize URL opens ETrade's authorization page;
(3) `oauth_callback=oob` is accepted — specifically, the request-token response
body contains **`oauth_callback_confirmed=true`**. The leg-1 parser
parses-and-logs `oauth_callback_confirmed` (see `shell::oauth_flow` leg-1
parsing) so this item is *actively* confirmed from the response rather than
merely inferred from the leg not 401-ing; record the confirmation date beside
the endpoint constants once verified.
Because the paths and the callback value are isolated as named constants/a
single call site, a correction is a one-line change in one file. To make a wrong
value *diagnosable* rather than opaque, the OAuth flow maps a non-2xx or
unparseable response from either leg to
`OauthFlowError::UnexpectedStatus`/`Parse`, which name the endpoint constant;
the **request-token leg's** `UnexpectedStatus` message additionally hints that
`oauth_callback=oob` is an unverified assumption to check if leg 1 `401`s on
first run (see the error hierarchy; resolves NIT #3 and NIT #4). Record the
confirmation date in a comment beside the constants once verified against the
live service.

#### Shared percent-encoding (`core::oauth`)

One `AsciiSet` constant encodes everything per RFC 3986 §2.1 / RFC 5849 (only
the unreserved set `A-Z a-z 0-9 - . _ ~` is left unencoded; everything else,
including `+ / =` from base64, is percent-encoded). The **same encoder is used
for the base string and for the `Authorization` header** so there is a single
source of truth and no risk of the two diverging.

```rust
pub fn oauth_encode(s: &str) -> String; // percent-encode via the shared AsciiSet
```

#### Splitting the query off the path (`core::oauth::split_query`) — resolves review #1

```rust
/// Splits "/v1/accounts/list?a=1&b=2" into
///   ("/v1/accounts/list", [("a","1"), ("b","2")]).
/// Returns an ORDERED Vec that PRESERVES DUPLICATES as a multiset — it never
/// collects into a map and never de-duplicates, so `?symbol=A&symbol=B` yields
/// [("symbol","A"), ("symbol","B")] in client order (resolves MEDIUM #3). Each
/// name and value is percent-DECODED (RFC 5849 §3.4.1.3.1) so the base string
/// can re-encode them uniformly with `oauth_encode` — decode-then-encode, never
/// double-encode. A bare "/path" (no '?') yields (path, []). A trailing '?' or a
/// pair with no '=' is handled totally (value = ""). Incoming query parameters
/// whose (decoded) name begins with `oauth_` are DROPPED here so client input
/// can neither inject nor shadow a protocol parameter in the signed set. Total;
/// never panics.
pub fn split_query(path_and_query: &str) -> (String, Vec<(String, String)>);
```

**Non-UTF-8 percent-escape handling (resolves review #2).** Arbitrary client
input can contain percent escapes that do not decode to valid UTF-8 (`%FF`,
`%C0%80`). `split_query` must stay total and return `String`/`Vec<(String,
String)>`, so the decode behavior is pinned explicitly: **decode via
`percent_encoding::percent_decode(bytes).decode_utf8()`, and on `Err`
(non-UTF-8) fall back to passing the raw, still-encoded token through
unchanged** rather than substituting U+FFFD. The rule, per token (each name and
each value independently):

- Decode succeeds (valid UTF-8) → use the decoded string; the base string and
  `wire_query` re-encode it with `oauth_encode` (decode-then-encode).
- Decode fails (non-UTF-8) → keep the original raw substring verbatim; it is
  then re-encoded by `oauth_encode` as-is.

**Consequence of raw passthrough (resolves NIT #2).** Because the raw substring
still contains a literal `%` (not in the unreserved set), `oauth_encode`
re-encodes it: a non-UTF-8 escape such as `%FF` becomes `%25FF` on **both** the
base string and the wire query, so the value forwarded upstream is a
*double-encoded* form of what the client sent. This is accepted deliberately: it
is pathological, read-only-API input; the signed side and the wire side stay
byte-identical (no 401); and it is strictly preferable to lossy U+FFFD
substitution, which would sign bytes the client never sent. The behavior is a
known, chosen trade-off rather than a surprise.

This keeps the function total (no error channel bolted onto the signature
pipeline), never panics, and — crucially — makes the signed set and the
`wire_query` set *identical by construction* even for non-UTF-8 input, because
both are built from the same per-token result. Lossy U+FFFD substitution is
explicitly **rejected**: it would sign bytes the client never sent. A proptest
input class injects non-UTF-8 percent escapes and asserts (a) totality and (b)
that the signed pair set equals the wire pair set for such input (see
Testability).

**Reserved-name handling (resolves review #3a).** A client (or an attacker)
can put any string in the query, including a literal `oauth_token` or
`oauth_signature`. `split_query` filters out every incoming parameter whose
decoded name starts with `oauth_` before returning, so the merged base-string
set `OauthParams.as_pairs() ∪ query_params` can never contain a duplicate or
shadowed protocol name. The protocol `oauth_*` parameters come exclusively from
`OauthParams`. (The encoded-sort tie-break rule — review #3b — is specified in
the base-string section's step 2 below.)

The query parameters this returns are merged into the base-string parameter set
(below), satisfying RFC 5849 §3.4.1.3.1, which requires **every** query
parameter to participate in the signature. FR-7 keeps query strings on the happy
path, so this is not an edge case — an admitted `GET /etrade-api/v1/accounts/list?x=1`
must be signed over `x=1` or ETrade returns 401. The `UpstreamPath` returned by
`admit` carries the query verbatim; the shell calls `split_query` on it to get
the no-query path, then `upstream_base_url(path)` for the normalized `base_url`,
plus the query pairs. (This ties the `UpstreamPath` and `base_url` comments
together — resolves NIT #9.)

#### Protocol parameters (`core::oauth::params`) — three signing domains, one builder (resolves review HIGH #1)

The OAuth signing domain is modeled around the **work performed**, not the URL.
There are three distinct OAuth legs, each with a *different* set of inputs it is
allowed to carry; collapsing them into one function over an *optional* token is
exactly what produced the HIGH finding (a request-token leg that emits
`oauth_token=""` and so diverges from its own base string). Instead, each leg is
its own typed domain, so the illegal states — a request-token leg carrying a
token, a proxy-forward leg carrying a callback — are **unrepresentable** per the
steering doc:

```rust
/// The three OAuth 1.0a legs as DISTINCT signing inputs. Each variant carries
/// EXACTLY the fields its leg requires — no optional token, no empty-string
/// placeholder. RequestToken and AccessToken are distinct newtypes and can
/// never be interchanged (NFR-1).
pub enum SigningInput<'a> {
    /// Leg 1 — get request token. Consumer key only, carries oauth_callback.
    /// There is NO token field and NO token secret, so oauth_token can never be
    /// emitted (empty or otherwise) on this leg — this is what makes the HIGH
    /// finding unrepresentable rather than merely avoided. The leg signs with
    /// the consumer secret and an EMPTY token secret (supplied by sign_leg).
    RequestToken {
        consumer_key: &'a ConsumerKey,
        callback: &'a str,                 // e.g. "oob"
    },
    /// Leg 2 — exchange verifier for access token. Consumer key + the REQUEST
    /// token (public value, goes in the base string/header) + the REQUEST
    /// token's secret (signs this leg) + oauth_verifier. The secret TRAVELS
    /// WITH the leg, so signing leg 2 with anything other than the request
    /// token's secret is unrepresentable (resolves MEDIUM #2 / NIT #3).
    AccessToken {
        consumer_key: &'a ConsumerKey,
        request_token: &'a RequestToken,
        request_token_secret: &'a TokenSecret,
        verifier: &'a Verifier,
    },
    /// Leg 3 — sign a proxied read. Consumer key + the ACCESS token (public
    /// value) + the ACCESS token's secret (signs this leg); no
    /// callback/verifier. The secret TRAVELS WITH the leg, so signing a
    /// resource call with no access-token secret, or with the request token's
    /// secret, is unrepresentable (resolves MEDIUM #2).
    Resource {
        consumer_key: &'a ConsumerKey,
        access_token: &'a AccessToken,
        access_token_secret: &'a TokenSecret,
    },
}

/// The protocol parameters for ONE leg, assembled from a SigningInput plus the
/// injected nonce/timestamp. There is NO oauth_signature field by construction,
/// so the signature can never leak into the base string. oauth_token is present
/// as a field ONLY for the AccessToken and Resource legs — the RequestToken leg
/// produces an OauthParams with no token at all, so a literal oauth_token="" is
/// structurally impossible.
pub struct OauthParams { /* consumer_key, nonce, timestamp,
                            signature_method = "HMAC-SHA1", version = "1.0",
                            token: Option<String> — Some ONLY for AccessToken
                              (= request token) and Resource (= access token)
                              legs; None for the RequestToken leg,
                            extra: Vec<(String,String)> holding oauth_callback
                              (RequestToken leg) or oauth_verifier (AccessToken
                              leg) or empty (Resource leg).
                            NO oauth_signature field. */ }

/// The ONE builder. It is total over the three domains: each `SigningInput`
/// variant maps to exactly the fields that leg admits. The nonce and timestamp
/// are INJECTED so the core stays deterministic (AC-4).
pub fn oauth_params(
    input: &SigningInput<'_>,
    nonce: &Nonce,                    // INJECTED
    timestamp: &Timestamp,            // INJECTED
) -> OauthParams;

/// The protocol params rendered as (name, value) pairs, EXCLUDING
/// oauth_signature (which does not exist on this type). This is the SINGLE
/// source for both the base-string parameter set and the rendered header, so
/// the two cannot diverge (resolves HIGH #1). Emits oauth_token ONLY when the
/// leg carried a token (AccessToken/Resource), and emits every `extra` entry
/// (oauth_callback on leg 1, oauth_verifier on leg 2), so those protocol
/// parameters enter BOTH the base string and the Authorization header.
impl OauthParams { pub fn as_pairs(&self) -> Vec<(String, String)>; }
```

**The token secret travels with the leg (resolves MEDIUM #2).** The *key
material* that signs each leg is carried by the `SigningInput` variant itself,
not passed independently: leg 1 (`RequestToken`) has no secret field and signs
with the consumer secret plus an **empty** token secret; leg 2 (`AccessToken`)
carries `request_token_secret: &TokenSecret` and signs with the consumer secret
**plus that request token secret**; leg 3 (`Resource`) carries
`access_token_secret: &TokenSecret` and signs with the consumer secret **plus
that access token secret**. Because the public token value and its matching
secret live in the *same* variant, "sign the access-token leg with the request
token's secret" is the only expressible pairing and "sign a resource call with
no access-token secret, or with the wrong secret" is impossible to write — the
pairing is now a **type invariant, not a prose convention**.

**One function derives both the params and the signing key (resolves MEDIUM
#2).** To make the pairing unavoidable in practice, a single `sign_leg` function
owns the whole per-leg signing step: it derives the `OauthParams` *and* the HMAC
signing key from the one `SigningInput` value (plus the consumer secret and the
injected nonce/timestamp), builds the base string, signs it, and renders the
header. There is exactly one place that chooses which token secret signs which
leg — inside `sign_leg`, driven by matching the `SigningInput` variant — so an
implementer cannot spread the pairing or get it wrong at a call site:

```rust
/// The one and only per-leg signing entry point. Matches on `input` to pull
/// the leg's token secret (empty for RequestToken, the request-token secret
/// for AccessToken, the access-token secret for Resource) and pairs it with
/// the leg's public token in `oauth_params` — so the token/secret pairing is
/// the single expressible option. Nonce and timestamp are INJECTED (AC-4).
/// For the Resource leg the caller passes the already-split query_params so
/// they enter the base string; the two OAuth token legs pass an empty slice.
pub fn sign_leg(
    input: &SigningInput<'_>,
    consumer_secret: &ConsumerSecret,
    query_params: &[(String, String)],   // Resource leg only; empty otherwise
    nonce: &Nonce,                        // INJECTED
    timestamp: &Timestamp,                // INJECTED
) -> SignedLeg;

/// The output of signing one leg: the ready-to-send Authorization header value
/// and the OauthParams it was built from (exposed for test assertions that the
/// header multiset == as_pairs()). No secret escapes in either field.
pub struct SignedLeg { pub authorization_header: String, pub oauth_params: OauthParams }
```

`sign_leg` internally calls `oauth_params(input, nonce, timestamp)` for the
protocol parameters, derives the signing key by matching the same `input`
variant to its secret (via the lower-level `signing_key` helper below), builds
`base_params = oauth_params.as_pairs() ++ query_params`, computes
`signature_base_string` → `sign_hmac_sha1` → `authorization_header`, and returns
both. The lower-level `oauth_params`, `signature_base_string`, `signing_key`,
`sign_hmac_sha1`, and `authorization_header` remain public pure functions so the
property tests can still exercise each stage in isolation, but the shell always
goes through `sign_leg`, which is the single enforcing call site for the
token/secret pairing.

**Distinct token newtypes never collapse (NFR-1).** `RequestToken` and
`AccessToken` are distinct newtypes and appear in distinct variants, so no leg
can accidentally sign with the wrong token: the access-token leg can only hold a
`&RequestToken`, the resource leg only a `&AccessToken`. There is no shared
`OauthToken` carrier and no `Option<token>` to misuse.

**`extra` folds into the signed set (preserved from prior rounds).**
`OauthParams` stores the per-leg `extra` entries, and `as_pairs()` emits them
alongside the other protocol parameters. Because the base-string parameter set
is `OauthParams.as_pairs() ∪ query_params`, `oauth_callback=oob` (leg 1) and
`oauth_verifier=<code>` (leg 2) participate in **both** the signature base
string and the rendered header — as RFC 5849 requires for protocol parameters.
If they appeared only in the header the request-token and access-token
signatures would be wrong and every startup would 401; folding them through
`as_pairs()` prevents that by construction. The AC-13 wiremock test asserts the
recorded request-token call's base string contains `oauth_callback=oob` (see
Testability).

Making `OauthParams` structurally incapable of holding `oauth_signature` is the
type-level guarantee against the single most common OAuth-signing bug:
`oauth_signature` is **computed last and only ever appears in the rendered
`Authorization` header**, never in the base string. Making `oauth_token` a field
that is simply *absent* on the request-token leg (rather than an empty string)
is the type-level guarantee against the HIGH finding: there is no code path that
can emit `oauth_token=""`, and because both the base string and the header are
derived from the same `as_pairs()`, they are identical by construction on every
leg.

#### Base string (`core::oauth::base_string`) — RFC 5849 §3.4.1

```rust
/// Builds the normalized base URI per RFC 5849 §3.4.1.2 for a mapped upstream
/// path: lowercase scheme `https`, lowercase host `endpoints::UPSTREAM_HOST`
/// (= api.etrade.com), default port 443 omitted, path only, NO query, NO
/// fragment. This is the single construction site for the signed base URI, so
/// it is unit-testable and the normalization rule cannot drift.
pub fn upstream_base_url(path: &str) -> String;
// -> "https://" + endpoints::UPSTREAM_HOST + path (host from the single constant)

pub fn signature_base_string(
    method: &HttpMethod,
    base_url: &str,                    // the NORMALIZED base URI (from upstream_base_url); no query
    base_params: &[(String, String)],  // OauthParams.as_pairs() ++ query_params; NO oauth_signature
) -> String;
```

**Base URI contract (resolves review #1).** `base_url` MUST be the normalized
request URI per RFC 5849 §3.4.1.2: lowercase scheme `https`, lowercase host
`api.etrade.com`, the default `https` port 443 omitted, and no query or
fragment. `signature_base_string` **assumes its `base_url` argument is already
normalized and does not re-normalize it** — it percent-encodes the string
whole. The design produces a normalized URI only through the pure
`upstream_base_url(path)` helper above (the host comes from the single
`endpoints::UPSTREAM_HOST` constant, is already lowercase, and carries no port),
so an implementer must route all base-URI construction through that helper
rather than concatenating a host inline; parameterizing the
host or appending a port there would silently break signing. The query having
been stripped by `split_query` satisfies the "no query, no fragment" clause.

Exact normalization of the parameter string, in order:
1. Percent-encode every parameter name and value with `oauth_encode`.
2. Sort a **copy** of the **already-encoded** pairs by **encoded name**, then (as
   a tie-break) by **encoded value**. The sort operates on the percent-encoded
   forms produced in step 1, per RFC 5849 §3.4.1.3.2 — never on the raw forms —
   and is a **stable sort over the full multiset**, so duplicate-name parameters
   (e.g. `symbol=A`, `symbol=B`) are both retained and ordered by value. Sorting
   a copy is deliberate: the base string sorts for signing while the wire query
   (`wire_query`) preserves the client's original order (resolves MEDIUM #3). The
   signed multiset and the wire multiset are the same `(name, value)` pairs; only
   their order differs, which is exactly what RFC 5849 permits.
3. Join as `name=value` with `&`.
4. Return `METHOD + "&" + oauth_encode(base_url) + "&" + oauth_encode(joined)`.

The parameter set is explicitly `OauthParams.as_pairs()` (which excludes
`oauth_signature`) **unioned with** the query params from `split_query`. The
`oauth_signature` is absent here by construction. Because nonce and timestamp
arrive as parameters, identical inputs always yield an identical base string and
signature — the determinism AC-4 checks. (Resolves review #1 and #2.)

#### Signing + header (`core::oauth::sign`)

```rust
/// HMAC key = oauth_encode(consumer_secret) + "&" + oauth_encode(token_secret_or_empty).
/// This is a LOWER-LEVEL helper: `sign_leg` is the only production caller and it
/// supplies the token secret by matching the SigningInput variant (None → empty
/// for the RequestToken leg, the REQUEST token secret for the AccessToken leg,
/// the ACCESS token secret for the Resource leg), so the per-leg pairing is
/// chosen in exactly one place. This is the ONLY source-level expose_secret()
/// call site (invoked per leg/request); the exposed &str is folded into the key
/// string and does not escape this function.
pub fn signing_key(consumer_secret: &ConsumerSecret,
                   token_secret: Option<&TokenSecret>) -> String;

/// HMAC-SHA1 over the base string, base64-encoded with the STANDARD alphabet.
/// Pinned API (resolves review NIT #4): base64 `0.22`'s Engine-based call
/// `base64::engine::general_purpose::STANDARD.encode(mac_bytes)` (standard
/// alphabet, WITH padding) — not the older free `base64::encode`. The resulting
/// `+`/`/`/`=` are then percent-encoded by `oauth_encode` wherever the digest
/// is emitted (base string input and Authorization header). The implementer
/// validates this exact `0.22` call at build time.
pub fn sign_hmac_sha1(base_string: &str, signing_key: &str) -> String;

/// Renders the full `Authorization` header value. Renders EXACTLY the pairs in
/// `params.as_pairs()` (the same set that built the base string) with the
/// injected `oauth_signature` inserted — nothing more, nothing less. See
/// grammar below.
pub fn authorization_header(params: &OauthParams, signature: &str) -> String;
```

**`Authorization` header grammar (resolves HIGH #1).** `authorization_header`
renders **exactly the pairs present in `OauthParams.as_pairs()`, plus the
injected `oauth_signature`** — each pair sorted by name, percent-encoded with
the shared `oauth_encode`, and double-quoted. Because the base string is built
from the same `as_pairs()`, the header and base-string parameter sets are
**identical by construction**; there is no second, independent template that
could list a field the base string omits. This is the fix for the HIGH finding:
`oauth_token` is emitted **only when `as_pairs()` contains it** — i.e. only on
the access-token and resource legs, where the leg actually carried a token.
Illustrative shape (fields in `[...]` appear only when present in `as_pairs()`
for that leg):

```
OAuth oauth_consumer_key="<enc>",
      [oauth_callback="<enc>",]        // present only on the request-token leg
      oauth_nonce="<enc>",
      oauth_signature="<enc>",         // inserted by this fn; not in OauthParams
      oauth_signature_method="HMAC-SHA1",
      oauth_timestamp="<enc>",
      [oauth_token="<enc>",]           // present ONLY on legs 2 & 3; OMITTED on the request-token leg (never emitted empty)
      [oauth_verifier="<enc>",]        // present only on the access-token leg
      oauth_version="1.0"
```

Rules:
- Scheme literal `OAuth ` (no `realm` — ETrade does not require one, so it is
  **omitted** to keep the header minimal).
- The field list is **derived from `as_pairs()`**, not from a fixed template, so
  on the request-token leg there is simply no `oauth_token` pair to render and a
  literal `oauth_token=""` is impossible to produce.
- Every value — **including the base64 `oauth_signature`**, whose `+`, `/`, `=`
  must be percent-encoded — is run through the **same `oauth_encode`** used for
  the base string, then wrapped in double quotes.
- Pairs are comma-space separated and ordered by name. `oauth_signature` is the
  only value not present in `OauthParams`; it is passed in separately and
  inserted here, which is the one and only place the params and the signature
  combine.

`authorization_header` taking `(&OauthParams, &signature)` — with `OauthParams`
having no signature field and no empty-string token placeholder — makes both the
"sign, then render" ordering and the empty-`oauth_token` divergence
unrepresentable. The shell's `clock_nonce.rs` supplies real nonce/timestamp
values to `oauth_params`; tests pin them.

### Status typestate (`core::status`)

```rust
pub struct Unauthorized;                 // zero-size start state
pub struct Authorized { access_token: AccessToken, token_secret: TokenSecret }

impl Unauthorized {
    /// Consumes self; the only way to reach Authorized is to supply a token.
    pub fn authorize(self, access_token: AccessToken,
                     token_secret: TokenSecret) -> Authorized;
}

#[derive(serde::Serialize)]
struct StatusBody { authorized: bool }

pub fn status_body_unauthorized() -> StatusBody; // { authorized: false }
pub fn status_body_authorized(_: &Authorized) -> StatusBody; // { authorized: true }
```

There is no nullable token field and no boolean flag; "authorized" is derived
from *which type the runtime currently holds*. `/internal/status` is **GET-only
like everything else**: a non-GET to it is rejected `405` by the verb-first
`admit` check (which returns `Reject(MethodNotGet)` before the path is even
examined), so only `GET /internal/status` reaches the `Status` arm and this
serialization (resolves NIT #6). The access token exists **only**
inside an `Authorized` value (FR-4, AC-14). Operations that require a token
(signing an upstream request) take `&Authorized`, so an unauthorized proxy
cannot even express an upstream call.

### Authorize URL + config (`core::authorize_url`, `core::config`)

```rust
pub fn authorize_url(key: &ConsumerKey, token: &RequestToken) -> String;
// -> endpoints::AUTHORIZE_URL_BASE + "?key={key}&token={token}"
//    = https://us.etrade.com/e/t/etws/authorize?key={key}&token={token}
// Encoding: key and token are encoded with ordinary query-string
// (application/x-www-form-urlencoded) encoding, NOT oauth_encode (see below).

pub struct EnvSnapshot { consumer_key: Option<String>,
                         consumer_secret: Option<String> }
pub struct Config { consumer_key: ConsumerKey, consumer_secret: ConsumerSecret,
                    port: ListenPort }
pub fn build_config(env: &EnvSnapshot, port: ListenPort)
    -> Result<Config, ConfigError>;
```

`build_config` is pure over a *snapshot* of the environment captured by the
shell (`shell::env`), so config validation (AC-11) is unit-testable without
touching real env vars. Empty strings are treated as missing.

**Authorize-URL encoding (resolves MEDIUM #1).** The authorize URL is a
**browser-facing** URL handed to the user to open, not an OAuth signature base
string, so it does **not** reuse `oauth_encode` (the RFC-3986 unreserved-only
`AsciiSet`). `authorize_url` encodes the `key` and `token` query values with
ordinary `application/x-www-form-urlencoded` query encoding — the same encoding
a browser and ETrade's authorize endpoint expect for query parameters. Reusing
the OAuth signing encoder here would be wrong: an ETrade request token typically
contains base64-ish characters (`+`, `/`, `=`), which `oauth_encode` would turn
into `%2B`, `%2F`, `%3D`, producing a URL that does not match what ETrade's
authorize endpoint and AC-12 expect.

The encoder choice and AC-12 are pinned to agree. AC-12 asserts the printed URL
equals
`https://us.etrade.com/e/t/etws/authorize?key={consumer_key}&token={request_token}`
with the given values substituted. To keep the acceptance test unambiguous,
**AC-12's fixture uses encode-neutral values** for `key` and `token` (characters
drawn from the unreserved set `A-Z a-z 0-9 - . _ ~`, which both encoders leave
byte-for-byte identical), so the literal expected string is exactly the
substitution with no `%`-escapes, and the test does not accidentally pin a
particular encoder's escaping. A second, separate unit test over a token
containing `+`/`/`/`=` asserts the query encoding produces `%2B`/`%2F`/`%3D`
(standard form-urlencoding), documenting the real-token behavior without
conflating it with AC-12's encode-neutral literal.

## Imperative Shell

### Shared runtime auth state (`shell::state`)

**Chosen representation: `Arc<std::sync::RwLock<AuthPhase>>`** where

```rust
enum AuthPhase { Pending, Ready(Arc<Authorized>) }
```

**`RwLock` kind (resolves review #6):** this is `std::sync::RwLock`, **not**
`tokio::sync::RwLock`. The write happens exactly once at startup and all reads
are synchronous (`.read()` with no `.await`); a guard is **never held across an
`.await`** — handlers clone the `Arc<Authorized>` out and drop the guard before
any async call. On the `current_thread` runtime this is correct and avoids the
`!Send` std-guard-across-await hazard. (`parking_lot::RwLock` would be an
acceptable drop-in with the same discipline, but std keeps the dependency set
smaller and is sufficient for write-once/read-many; it is not added to the
stack.)

The OAuth flow runs once at startup and flips the phase from `Pending` to
`Ready` exactly once; thereafter it is read-only on the hot path (`/internal/status`
and every proxied request read it). An `RwLock` fits a write-once / read-many
pattern and is the simplest correct option. **Rejected alternative:** an
actor/channel task owning the state — justified for high-write-contention or
complex coordination, neither of which exists here; it would add a task, a
channel protocol, and latency for no benefit. The steering doc explicitly
sanctions `Arc<RwLock<...>>` for shared runtime state as long as mutability is
*isolated* and not threaded through the core — and here the core never sees the
lock. The typestate `Authorized` lives inside the `Ready` variant; the lock
guards the *phase transition*, while the typestate guards *what operations are
possible* once ready. The two mechanisms are complementary: the lock answers
"has auth happened yet?" and the typestate answers "what can I do with the
token?".

Actually storing `Arc<Authorized>` inside lets a handler clone the `Arc` out
under a short read-lock and then sign without holding the lock across any
`.await`, avoiding holding a std `RwLock` guard across await points.

**Phase → status body mapping (resolves review #5).** The `/internal/status`
handler is the one seam where the lock and the typestate meet. It performs this
exact match under a read guard that is dropped before serialization (nothing is
`.await`-ed while held):

```rust
let body = {
    // std::sync::RwLock::read() returns a Result; a poisoned lock at startup is
    // unrecoverable, so this is one of the documented expect() sites.
    let guard = state.read().expect("auth-state lock poisoned");
    match &*guard {
        AuthPhase::Pending  => core::status::status_body_unauthorized(),
        AuthPhase::Ready(a) => core::status::status_body_authorized(a),
    }
};                                                 // guard dropped here (no .await held)
// serialize `body` to JSON after the guard is released
```

The status value is thus derived from *which phase the runtime currently holds*
(FR-9/AC-10), not from a boolean. `status_body_authorized` takes `&Authorized`
and never reads the token's bytes, so no secret is touched to answer status.

### Startup sequence (`main.rs` + shell)

1. Parse `--port` (clap), default `ListenPort(8443)`. The port is sourced only
   from this flag — there is no env-var fallback (resolves NIT #5).
2. `shell::env::snapshot()` reads the two env vars once → `EnvSnapshot`.
3. `core::config::build_config(&snapshot, port)` → `Config` or exit non-zero
   with a message naming the missing variable (no socket bound yet — AC-11).
4. `shell::tls::generate()` → rcgen ephemeral cert+key via
   `generate_simple_self_signed`, yielding `CertifiedKey { cert, signing_key }`.
   The shell takes the certificate **DER bytes** from `cert.der()` (an
   `rcgen 0.14` `&CertificateDer<'_>`, dereferenced to `&[u8]`) and passes them
   to the pure core function
   `core::tls_fingerprint::fingerprint(der: &[u8]) -> String`, which computes
   **SHA-256 over the DER bytes** and renders them as **lowercase hex with
   colon separators** (e.g. `ab:cd:ef:…`, 32 bytes → 32 colon-separated hex
   octets). The shell prints that string to stdout (FR-6). Pinning the exact DER
   source (`cert.der()`), the hashed input (DER), and the rendering (lowercase
   colon-hex) makes the fingerprint reproducible by a client bootstrapping
   trust, and makes the renderer a pure, unit-testable function (resolves NIT
   #4 and prior review #5). Then build the rustls `ServerConfig` from
   `signing_key.serialize_der()` (→ `PrivateKeyDer::Pkcs8`) and the same
   `cert.der()` as the certificate chain.
5. `shell::oauth_flow::run(&config, &clock, &nonces)` performs the three-leg
   flow (below), returning `Authorized`. Store `Ready(Arc::new(authorized))`
   in the shared state. `clock: &dyn Clock` and `nonces: &dyn NonceSource` are
   the **generator** seams from `shell::clock_nonce` (not pre-computed values):
   `oauth_flow` draws a fresh `(nonce, timestamp)` immediately before signing
   each leg, so the request-token and access-token legs never share a nonce
   (resolves review #1). The same `clock`/`nonces` handles are passed to the
   server so each proxied request can likewise draw its own fresh pair.
6. `shell::server::serve(config.port, tls, state, clock, nonces)` binds
   **`127.0.0.1`** only and runs the axum app. The `clock`/`nonces` generators
   are placed in the axum app state alongside the auth state so the proxy
   handler can draw a fresh `(nonce, timestamp)` per request (step 3 of the
   handler).

Ordering note: the proxy authorizes *before* it accepts connections, so in
normal operation `/internal/status` reports `true` as soon as it is reachable.
The `Pending` phase and `{"authorized":false}` serialization still exist and are
exercised by tests, and guard against any future reordering.

### OAuth three-leg flow (`shell::oauth_flow`)

`shell::oauth_flow::run(config: &Config, clock: &dyn Clock, nonces: &dyn
NonceSource) -> Result<Authorized, OauthFlowError>`. Each leg draws a **fresh**
`(nonce, timestamp)` from the injected generators *immediately before signing* —
`let ts = clock.now_unix(); let nonce = nonces.next();` once per leg — so the
request-token and access-token legs never sign with the same `oauth_nonce`
(resolves review #1). It then calls the pure signer to get the `Authorization`
header, uses `reqwest` to POST to the ETrade endpoint, and parses the
`oauth_token` / `oauth_token_secret` (and `oauth_verifier` echo) from the
`application/x-www-form-urlencoded` response body with a pure parser in the
core. The leg-1 parser additionally reads **`oauth_callback_confirmed`** when
present and logs it (at info level, no token material) so the
`oauth_callback=oob` assumption is actively confirmed on the first live run
(resolves NIT #3); it is informational only — a missing or `false` value is not
treated as fatal, since the leg already fails loudly via `UnexpectedStatus` if
ETrade rejects the callback. Endpoints:

- Request token: `oauth_endpoint_url(endpoints::REQUEST_TOKEN_PATH)`
  (= `https://api.etrade.com/oauth/request_token`), signed with
  `sign_leg(&SigningInput::RequestToken { consumer_key, callback: "oob" },
  consumer_secret, &[], &nonce, &ts)` where `nonce`/`ts` were just drawn fresh
  for this leg — the leg carries no secret, so `sign_leg` uses an empty token
  secret. The `oauth_callback=oob` entry is folded into the base string via
  `as_pairs()`, so it is signed, not merely a transport detail; `oob` matches
  the console-display/stdin-verifier flow (no redirect URI) and is recorded as a
  confirm-on-first-run assumption beside the leg paths (see the feasibility note;
  resolves review #3). This leg carries no token, so `oauth_token` is absent
  from both its base string and header by construction.
- Authorize URL printed: built by `core::authorize_url` from
  `endpoints::AUTHORIZE_URL_BASE`
  (= `https://us.etrade.com/e/t/etws/authorize?key=...&token=...`).
- Verifier read from stdin once (`shell::prompt`); an empty verifier (after
  trimming) aborts the flow with `OauthFlowError`, no re-prompt (see Validation
  Rules).
- Access token: `oauth_endpoint_url(endpoints::ACCESS_TOKEN_PATH)`
  (= `https://api.etrade.com/oauth/access_token`), signed with a **freshly
  drawn** `(nonce, ts)` for this leg and
  `sign_leg(&SigningInput::AccessToken { consumer_key, request_token:
  &request_token, request_token_secret: &request_token_secret, verifier:
  &verifier }, consumer_secret, &[], &nonce, &ts)` — the REQUEST token secret
  travels inside the leg, so it is paired with the request token by
  construction, and the fresh nonce guarantees this leg's `oauth_nonce` differs
  from the request-token leg's.

The decision logic (what to sign, how to build the base string, how to parse the
form body) is pure; only the socket writes/reads and the stdin read are in the
shell.

### Proxy handler (`shell::handlers`, `shell::upstream`)

The axum fallback handler receives any method/path. It converts axum's `Method`
and the request's path+query into core types and calls `core::admission::admit`.
On `Admission::Forward(upstream_path)`:

1. Read the shared state; if `Pending`, return `503 Service Unavailable`
   (`ProxyError::NotReady` — cannot sign without a token; the typestate makes an
   upstream call unrepresentable, so the handler returns early). In normal
   operation this is unreachable because startup authorizes before binding, but
   it is a real, tested path — see the test seam note below.
2. Clone the `Arc<Authorized>` out of the read guard, drop the guard.
3. Split the mapped `UpstreamPath` with `core::oauth::split_query` into
   `(path, query_params)`. Build `base_url = core::oauth::upstream_base_url(&path)`
   (the normalized, no-query base URI). **Draw a fresh `(nonce, timestamp)` for
   this request** from the injected generators — `let ts = clock.now_unix();
   let nonce = nonces.next();` — so every proxied request signs with a distinct
   `oauth_nonce` and no nonce/timestamp is reused across requests (resolves
   review #1). Sign the resource leg with the single
   `sign_leg(&SigningInput::Resource { consumer_key, access_token:
   &access_token, access_token_secret: &access_token_secret }, consumer_secret,
   &query_params, &nonce, &ts)` — the ACCESS token secret travels inside the leg,
   so it is paired with the access token by construction, and `sign_leg` folds
   `query_params` into `base_params = oauth_params.as_pairs() ++ query_params`
   before computing the base string, HMAC-SHA1 signature, and `Authorization`
   header (injected nonce/timestamp from the shell). `sign_leg` returns the
   ready `authorization_header`.

   **The wire query is derived from the signed pairs, never from the raw client
   query (resolves review #1).** `query_params` is the decoded, `oauth_*`-filtered
   pair set that was actually signed. The outbound URL's query string is built by
   re-serializing *those same pairs* with the shared `oauth_encode`, so the signed
   set and the sent set are byte-identical. The pure helper that does this lives
   in the core so it is unit-testable:

   ```rust
   /// Re-serialize the signed query pairs into a wire query string using the
   /// SAME oauth_encode as the base string. Operates on the ordered
   /// Vec<(String,String)> AS GIVEN — it PRESERVES CLIENT ORDER and PRESERVES
   /// DUPLICATES as a multiset (no map, no de-dup, no sort), so
   /// [("symbol","A"),("symbol","B")] serializes to "symbol=A&symbol=B" in that
   /// order. The signed set (a SORTED copy of these same pairs) and the wire set
   /// (these pairs in client order) are therefore the SAME MULTISET, differing
   /// only in order (resolves MEDIUM #3). Pure; total. Empty pairs -> "".
   pub fn wire_query(pairs: &[(String, String)]) -> String; // "a=1&b=2"
   ```

   The shell then forms the upstream URL as
   `base_url` when `wire_query(&query_params)` is empty, else
   `format!("{base_url}?{}", wire_query(&query_params))`, and sends it with
   `reqwest` (`GET` only). Because both the base-string parameter set and the wire
   query are produced from the same filtered, `oauth_encode`-canonicalized pairs,
   the two cannot diverge: a client's differently-but-equivalently encoded query
   (`%7E` vs `~`, `+` vs `%20`, upper vs lower hex) is normalized identically on
   both sides, and a client-supplied `oauth_token=...` query param is dropped from
   both the signed set and the wire query (so ETrade never sees an unsigned
   `oauth_*` parameter). This avoids the 401/protocol-violation failure modes of
   signing one query and sending another. A property test asserts
   `signed param set == wire param set` (see Testability).
4. Relay the response: the upstream body is **fully buffered (bounded) and
   relayed without interpretation** (resolves review #6 and MEDIUM #2), then copy
   the upstream status, copy a **whitelist** of response headers (`Content-Type`,
   `Date`, `ETag`, caching headers), drop all hop-by-hop headers (`Connection`,
   `Transfer-Encoding`, `Keep-Alive`, `Upgrade`, etc.), and send the buffered
   body. Buffering (rather than streaming) is chosen because the account-JSON
   payloads are small and it keeps the `ProxyError::Upstream → 502` mapping
   **honest**: an upstream read error is caught *before* any status/headers are
   written to the local client, so it can still be mapped to `502`. Streaming
   would make a post-headers upstream failure unmappable to `502`; buffering
   avoids that undefined mid-stream behavior at no meaningful cost for these
   payloads. A read error on the (completed) upstream fetch therefore maps
   cleanly to `502 Bad Gateway`.

   **Bounded buffer (resolves MEDIUM #2).** The upstream is explicitly treated as
   untrusted, so the body is read with a hard cap of **`UPSTREAM_BODY_CAP = 8
   MiB`** (a named `const`), not with an unbounded `reqwest::Response::bytes()`.
   The body is accumulated via a size-limited read (stream the response chunks and
   stop once the accumulated length would exceed `UPSTREAM_BODY_CAP`); exceeding
   the cap is treated as an upstream fault and maps to
   `ProxyError::UpstreamTooLarge → 502 Bad Gateway` (logged at warn level, no body
   written to the client). This closes the unbounded-memory path: a misbehaving
   or compromised upstream cannot drive unbounded allocation, and because the cap
   is checked before any status/headers are written, the `502` mapping stays
   honest. 8 MiB is far above any legitimate `/v1/accounts/*` JSON payload while
   bounding worst-case memory per in-flight request. **`Content-Length` is not
   copied** (resolves prior review #8): the framework sets
   `Content-Length`/transfer-encoding for the relayed body, so copying the
   upstream value would be redundant and can conflict. The whitelist is a pure
   function `core::relay::relay_header_allowed(name) -> bool` so it is
   unit-testable in isolation; it lives in its own `core::relay` module rather
   than `core::admission`, keeping `admission` strictly the central
   GET-only/prefix invariant (resolves review #7).

On `Admission::Status` → serialize the status body from the current phase using
the exact phase match in `shell::state` above. The `Status` arm is only ever
reached by `GET /internal/status`; a non-GET to that path never reaches the
handler's status branch because `admit` rejects it `405` verb-first, so
`/internal/status` is GET-only like every other route (resolves NIT #6). On
`Admission::Reject(reason)` →
map per the reject table: `MethodNotGet → 405 Method Not Allowed`,
`OutOfPrefix → 404 Not Found` (one code per reason). Nothing is forwarded
upstream on a reject (FR-8).

**Test seam for the `Pending` / 503 path (resolves review #7).** Because
`shell::server::serve(port, tls, state, clock, nonces)` takes the
`Arc<RwLock<AuthPhase>>` and the generator seams as parameters, an integration
test constructs a server with the state initialized to `Pending` and drives it
directly, exercising both the `/internal/status` unauthorized case (AC-10) and
the proxy handler's `503`/`ProxyError::NotReady` branch. The same parameterized
seam lets a test inject a counter-backed `NonceSource` and assert that two
sequential proxied requests emit distinct `oauth_nonce` values (the freshness
contract from review #1). This is the only way the `Pending` branch is reached, and the seam makes
it a defined, covered path rather than production-dead code.

### Loopback-only bind (`shell::server`)

The bind address is **constructed as a constant** `Ipv4Addr::LOCALHOST`
(`127.0.0.1`) in code — it is never derived from user input, config, or env.
Only the port is configurable. A small pure helper

```rust
pub fn bind_addr(port: ListenPort) -> SocketAddr
    // SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.0)
```

returns the address so AC-9 can assert in a unit test that *for every* port the
resulting IP is loopback and there is no code path to any other address. The
server passes this `SocketAddr` to `axum-server`'s TLS binder.

## Error Hierarchy

Per-module `thiserror` enums, `#[non_exhaustive]` where public and growable,
`#[from]` for clean `?` conversion. `anyhow` only in `main`.

- `core::error::ConfigError` — `MissingConsumerKey`, `MissingConsumerSecret`,
  `EmptyConsumerKey`, `EmptyConsumerSecret`. Messages name the variable, never
  the value. Fatal at startup → surfaces through `main` as a non-zero exit
  before any bind (AC-11). Recoverable: no.
- `core::error::OauthParseError` — `MissingField { field }`, `MalformedForm`.
  Returned by the pure form-body parser. Recoverable by the caller only insofar
  as it aborts the flow; fatal to startup.
- `core::error::AdmissionError` — not needed; `admit` is total and returns
  `Admission`, so admission has no error channel (rejection is a value, not an
  error). Documented explicitly: rejection is a normal outcome, not a failure.
- `shell::error::TlsError` — `CertGeneration(#[from] rcgen::Error)`,
  `RustlsConfig(...)`. Fatal at startup.
- `shell::error::OauthFlowError` — `Http(#[from] reqwest::Error)`,
  `UnexpectedStatus { endpoint: &'static str, code: u16 }`,
  `Parse { endpoint: &'static str, source: OauthParseError }`,
  `Prompt(#[from] std::io::Error)`, `EmptyVerifier`. Fatal at startup; the user
  sees a clear message and re-runs. Logged at error level (no token material).
  `EmptyVerifier` is returned when the stdin verifier is empty after trimming
  (single prompt, no retry — see Validation Rules).

  **Leg-path diagnostic guard (resolves NIT #4).** `UnexpectedStatus` and
  `Parse` both carry the **endpoint constant name** (`endpoint`, e.g.
  `"REQUEST_TOKEN_PATH (/oauth/request_token)"`). Their `thiserror` `#[error]`
  messages name that constant and append a reminder: *"verify this path against
  the current ETrade authorization docs — it is an unverified assumption (see
  core::oauth::endpoints)."* On the **request-token leg** specifically, the
  message additionally notes that `oauth_callback=oob` is an unverified
  assumption to confirm if that leg `401`s (resolves review NIT #3). The shell
  maps a non-2xx response from either OAuth leg to `UnexpectedStatus { endpoint,
  code }` and an unparseable form body to `Parse { endpoint, .. }`, so a wrong
  leg path or callback value (the known residual risks) surfaces as a
  **diagnosable** startup failure pointing straight at the constant/value to
  check, rather than an opaque 404/parse abort. This turns the manual pre-run
  confirmation into a self-announcing failure mode.
- `shell::error::ProxyError` — `Upstream(#[from] reqwest::Error)` → `502 Bad
  Gateway`; `UpstreamTooLarge { cap: usize }` (body exceeded
  `UPSTREAM_BODY_CAP = 8 MiB`) → `502 Bad Gateway`; `NotReady` (phase still
  `Pending`) → `503 Service Unavailable`. Per-request, recoverable: mapped to
  the stated HTTP response, logged at warn level, process keeps running. Because
  the handler buffers the upstream body (bounded) before writing any response
  (handler step 4), an upstream send/read error or an over-cap body is always
  observed before status/headers go out, so `Upstream`/`UpstreamTooLarge → 502`
  is unconditional and honest — there is no mid-stream window.
- `shell::error::ServerError` — `Bind(#[from] std::io::Error)`,
  `Tls(#[from] TlsError)`. Fatal at startup.

`main` aggregates with `anyhow::Result<()>`, adding `.context(...)` at the few
boundaries that aid diagnosis (config load, TLS setup, OAuth flow, bind), and
maps any error to a non-zero exit. No `unwrap`/`expect` outside documented
unreachable cases (e.g. a `const` IP parse that cannot fail, commented as such).

## Validation Rules Per External Input

- **`ETRADE_CONSUMER_KEY` / `ETRADE_CONSUMER_SECRET`** (required, string):
  missing or empty → `ConfigError`, non-zero exit, no socket (AC-11). No length
  cap imposed (ETrade controls format); only non-empty is required.
- **`--port`** (optional, `u16`): defaults to `8443`. clap rejects
  non-numeric / out-of-range `u16` with its standard usage error and non-zero
  exit. Port `0` is accepted by the type but discouraged; since bind is loopback
  only, `0` (OS-assigned) is harmless and may actually help tests — allowed.
- **Verifier from stdin** (required, string): trimmed of surrounding
  whitespace; empty after trim → fail immediately with a clear
  `OauthFlowError` (no re-prompt). FR-3/CONCEPT specify a single prompt, so the
  earlier "re-prompt once" behavior is dropped for scope discipline; the user
  re-runs the proxy on a mistyped verifier, consistent with the fresh-flow
  per-startup posture. Treated as opaque otherwise; passed to the access-token
  leg as `oauth_verifier`. (Resolves review #8.)
- **Incoming HTTP method + path** (every request): validated by the total
  `admit` function; no input can panic it (AC-8). Oversized paths are bounded by
  axum/hyper's own limits; `admit` itself imposes no additional length rule but
  is total over any string.
- **Upstream response** (external, untrusted): status copied through; headers
  filtered by the whitelist; body **fully buffered (bounded, see below) and
  relayed without interpretation** (the proxy does not parse account JSON). The
  body is read with a hard cap of `UPSTREAM_BODY_CAP = 8 MiB`; a response whose
  body would exceed the cap is treated as an upstream fault and mapped to
  `ProxyError::UpstreamTooLarge → 502` (no partial body relayed). A non-2xx upstream
  status within the cap is relayed as-is so the client sees ETrade's own error.

## Security Invariants and Enforcing Layer

- **Loopback-only bind (FR-6/AC-9).** Owned by `shell::server::bind_addr`,
  which hard-codes `Ipv4Addr::LOCALHOST`. No other layer may construct the bind
  address. Enforced because the address is a code constant, not data; proven by
  the unit test over all ports.
- **GET-only forwarding (FR-8/AC-5,6,7,8).** Owned by `core::admission::admit`,
  a total pure function checked verb-first. The shell has exactly one place that
  issues an upstream request, and it is reachable only from the `Forward` arm;
  there is no other code path to `reqwest`. Proven by the proptest suite.
- **No credential persistence (FR-4/AC-14).** Owned by the type system: tokens
  live only inside `Authorized`/`SecretString`, there is no serialization impl
  and no filesystem write for them. Enforced by review plus the absence of any
  `fs`/`serde` path touching token types.
- **No credential leakage (NFR-2).** Owned by the secret newtypes' redacting
  `Debug`/`Display` and by error messages that reference variable *names*.

## Testability

Pure core (unit + property under `cargo test`, no runtime):

- `admit` — proptest AC-5 (non-GET always rejected over arbitrary method+path),
  AC-6, AC-7 (in-prefix GET admitted and correctly mapped with query preserved),
  AC-8 (totality: never panics over arbitrary strings). Custom `Arbitrary` for
  `HttpMethod` and a path strategy that mixes valid prefixes, `/orders` paths,
  and random strings.
  - **AC-6 stated as the real invariant (resolves MEDIUM #1).** The `Admission`
    outcome is tri-state (`Forward`/`Status`/`Reject`), while AC-6 is framed as
    "never admits," and FR-8 defines "admit" as "forwarded upstream." The
    property is therefore pinned on the *forwarding* invariant, not on a blanket
    "always `Reject`": **for every `GET` whose path is not under
    `/etrade-api/v1/accounts`, `admit` returns a non-`Forward` outcome** —
    `prop_assert!(!matches!(admit(&HttpMethod::Get, p), Admission::Forward(_)))`
    over the random-string / `/orders` path strategy. The single carve-out path
    `/internal/status` is covered by a **dedicated example** asserting
    `admit(&HttpMethod::Get, "/internal/status") == Admission::Status`; every
    other out-of-prefix `GET` is covered by a second property asserting
    `Reject(OutOfPrefix)` with the literal `/internal/status` excluded from that
    arm's strategy. This matches requirements AC-6 (which names `/internal/status`
    as a path the function "never admits," i.e. never forwards) without asserting
    the stronger-but-wrong `Reject` for the one path that correctly returns
    `Status`.
- OAuth signing — proptest AC-4: fixed injected nonce/timestamp ⇒ identical base
  string and signature across repeated calls; varying nonce/timestamp changes
  output; base-string construction verified over arbitrary parameter sets for
  correct percent-encoding and lexicographic sort. Additional targeted tests
  covering the review findings:
  - **Base-string / header agreement across all three legs (proptest, resolves
    HIGH #1):** a strategy generates an arbitrary `SigningInput` of each variant
    (`RequestToken`, `AccessToken`, `Resource`) with arbitrary key/token/callback/
    verifier values and injected nonce/timestamp, builds `OauthParams`, and
    asserts that the `(name, value)` pair multiset embedded in the rendered
    `authorization_header` (parsed back out, excluding `oauth_signature`) is
    **exactly** `OauthParams.as_pairs()` — i.e. the header and base string are
    built from the identical parameter set for every leg. The property explicitly
    asserts that the **`RequestToken` leg emits NO `oauth_token`** (neither in
    `as_pairs()` nor in the header) and that the `AccessToken`/`Resource` legs do
    emit exactly one `oauth_token`. This pins the HIGH-finding fix at the type/
    value level: no leg can produce `oauth_token=""` and header/base-string
    divergence is impossible. The strategy drives this through `sign_leg` (the
    single enforcing call site), supplying the per-variant token secret the
    variant now carries, so the test also exercises the token/secret pairing
    (resolves MEDIUM #2): the `AccessToken` leg's secret is a `request_token_secret`
    and the `Resource` leg's is an `access_token_secret`, which is the only
    expressible pairing.
  - **`split_query` round-trip (proptest):** for an arbitrary path
    and arbitrary `(name, value)` pairs, encoding the pairs into a query string,
    running `split_query`, and feeding the result into `signature_base_string`
    yields a base string that contains every query parameter; `split_query` is
    total over arbitrary strings (never panics). Confirms query params reach the
    signature.
  - **Signed multiset == wire multiset (proptest, resolves #1 and MEDIUM #3):**
    for arbitrary query pairs, the pair **multiset** signed into the base string
    equals the pair multiset produced by `wire_query` — i.e.
    `wire_query(&query_params)` parsed back yields exactly the pairs that went
    into `base_params`, with duplicates preserved. The assertion compares
    **sorted vectors of `(name, value)` pairs** (multiset equality), not set
    membership, so a dropped or de-duplicated duplicate key fails the test. The
    strategy includes a **dedicated duplicate-key case** (e.g.
    `?symbol=A&symbol=B&symbol=A`) to pin that both the signed and wire sides
    keep all three pairs. This pins the invariant that the outbound query is
    derived from the signed pairs (never the raw client query) and that the
    base-string sort operates on a copy while `wire_query` preserves client
    order.
  - **Non-UTF-8 percent escapes (proptest, resolves #2):** an input class of
    query strings containing non-UTF-8 escapes (`%FF`, `%C0%80`) asserts (a)
    `split_query` is total (never panics), and (b) for such input the signed
    pair set still equals the `wire_query` pair set — confirming the
    raw-passthrough-on-decode-failure rule keeps the two sides identical rather
    than diverging via lossy substitution.
  - **Base string excludes `oauth_signature` (RFC 5849 reference vector,
    resolves #2):** a table-driven example test pins one input against a
    known-good RFC 5849 / ETrade reference signature **and** asserts the computed
    base string does not contain the substring `oauth_signature`.
  - **Header percent-encoding (resolves #3):** given a signature whose base64
    contains `+`, `/`, `=`, assert `authorization_header` emits
    `oauth_signature="%2B..."` etc. — i.e. the signature value is percent-encoded
    with the shared `oauth_encode` and double-quoted, and no bare `+`/`/`/`=`
    appears in the rendered value. Assert no `realm` is present.
- `build_config` — example tests for AC-11 (missing/empty each variable).
- `authorize_url` — example test for AC-12 using an **encode-neutral** fixture
  (unreserved-set `key`/`token`) asserting the exact literal
  `https://us.etrade.com/e/t/etws/authorize?key={key}&token={token}` with no
  `%`-escapes; plus a second test over a token containing `+`/`/`/`=` asserting
  ordinary query (`application/x-www-form-urlencoded`) encoding yields
  `%2B`/`%2F`/`%3D` and confirming `oauth_encode` is **not** reused here
  (resolves MEDIUM #1).
- status serialization — `insta` snapshot for AC-10 (`{"authorized":false}` and
  `{"authorized":true}`), plus a compile-time guarantee that `Authorized` is the
  only producer of `true`.
- `bind_addr` — property/example test for AC-9 (loopback for all ports).
- `core::relay::relay_header_allowed` — table test for the whitelist, asserting
  `Content-Type`/`ETag`/caching headers pass and `Content-Length` plus all
  hop-by-hop headers are rejected.

Imperative shell (integration tests, local fakes — AC-13):

- OAuth three-leg flow against a `wiremock` server standing in for
  `api.etrade.com`: assert the signed `Authorization` header shape, the request
  sequence, and that an `Authorized` is produced; no live calls. Explicitly
  assert the recorded **request-token** call's signature inputs include
  `oauth_callback=oob` in the base string (resolves review #4) and the
  **access-token** call's include `oauth_verifier=<code>`, confirming `extra`
  entries are signed, not header-only.
- Proxy forward against `wiremock`: a
  `GET /etrade-api/v1/accounts/list?x=1` reaches the fake upstream as
  `GET /v1/accounts/list?x=1` with the query preserved and a signed header; a
  `POST` to the same prefix returns `405` and the mock records **zero** upstream
  hits (the structural GET-only guarantee, end-to-end). A `GET` to an
  out-of-prefix path returns `404`.
- **Nonce/timestamp freshness (resolves review #1):** with a counter-backed
  `NonceSource` injected via the `serve` seam, two sequential proxied `GET`
  requests are driven against `wiremock` and the two recorded upstream
  `Authorization` headers are parsed; the test asserts their `oauth_nonce`
  values are **distinct**. This pins the freshness contract at the shell even
  though wiremock does not validate nonces upstream, catching a value-reuse
  implementation that would otherwise pass every other test and fail only on the
  first live run. The three-leg flow test likewise asserts the request-token and
  access-token legs carry distinct `oauth_nonce` values.
- `/internal/status` served over the real rustls stack returns the expected JSON
  in both phases. The `Pending` case is driven by passing a `Pending` state into
  `shell::server::serve` directly (the test seam from the handler section), which
  also exercises the proxy handler's `503`/`ProxyError::NotReady` branch.
- TLS/cert: a pure unit test for `core::tls_fingerprint::fingerprint` feeds
  known DER bytes and asserts the exact SHA-256 lowercase colon-hex string
  (e.g. against a precomputed vector); an integration test asserts `rcgen`
  produces a usable cert whose DER the shell can hash into that same format.

Build/lint gates (AC-1,2,3): `cargo build`, `cargo test` green, and the clippy
zero-warning gate is enforced by the exact command
**`cargo clippy --all-targets --all-features -- -D warnings`** (which turns
warnings into errors at invocation time rather than via a crate-level
`#![deny(warnings)]`, avoiding brittle builds while making AC-2 mechanically
checkable). (Resolves review NIT #11.)

## Open Decisions — Resolved

- **Server/client crates:** axum+hyper (server), reqwest (client). Justified
  above over bare hyper.
- **TLS:** rustls on both legs (axum-server `tls-rustls`, reqwest `rustls-tls`),
  chosen over OpenSSL for a pure-Rust build.
- **Shared auth state:** `Arc<RwLock<AuthPhase>>` holding `Arc<Authorized>`,
  chosen over an actor/channel for this write-once/read-many case; the pure core
  never sees the lock.
- **OAuth signing:** hand-rolled pure functions (`hmac`+`sha1`+`base64`+
  `percent-encoding`) with injected nonce/timestamp, chosen over an OAuth crate
  to keep signing pure and property-testable. The signing domain is modeled
  around the **work performed, not the URL**: the three OAuth legs are three
  distinct typed inputs (`SigningInput::{RequestToken, AccessToken, Resource}`),
  each carrying exactly the fields its leg admits (request-token carries a
  callback and NO token/secret; access-token carries the request token + its
  secret + verifier; resource carries the access token + its secret), with
  `RequestToken` and `AccessToken` as distinct newtypes. The token secret
  travels inside the leg and a single `sign_leg` function derives both the
  params and the signing key from the one `SigningInput`, so the per-leg
  token/secret pairing is a type invariant, not a convention (resolves MEDIUM
  #2). All three feed **one** `signature_base_string` builder and **one**
  `authorization_header` builder, both derived from the same
  `OauthParams.as_pairs()`, so the base string and header are identical by
  construction and no leg can emit `oauth_token=""` (resolves HIGH #1). The full
  pipeline — `split_query` (decode-then-encode, non-UTF-8 raw-passthrough,
  `oauth_*` dropped, duplicates preserved as a multiset) → `oauth_params` (no
  signature field; token absent on leg 1) → `signature_base_string` over
  oauth∪query params (sorts a copy) → `sign_hmac_sha1` → `authorization_header`
  (shared encoder, double-quoted values, no realm, renders exactly `as_pairs()`
  + signature), with the resource leg's wire query re-serialized by `wire_query`
  from the *same* signed pairs in client order — is specified end to end so
  query params reach the signature, the signed and sent query multisets are
  identical, and `oauth_signature` lives only in the header. ETrade host and
  OAuth leg paths are centralized in `core::oauth::endpoints`.
- **Error hierarchy:** per-module `#[non_exhaustive]` `thiserror` enums with
  `#[from]`; `anyhow` only in `main`.
- **Property testing the GET-only invariant and base string:** proptest with a
  custom `HttpMethod` strategy and a mixed path strategy for admission (AC-5–8).
  AC-6 is pinned on the *forwarding* invariant — every out-of-prefix `GET`
  returns a **non-`Forward`** outcome — with `/internal/status` carved out as a
  dedicated `Status` example (reconciling the tri-state `Admission` with the
  "never admits" wording; resolves MEDIUM #1). Arbitrary OAuth parameter sets
  cover base-string encoding/sorting, plus a `split_query` round-trip into the
  base string (AC-4).

## Responses to Design Review

### Revision 8 — responses to the current review (`design-review.json`, verdict `CHANGES_REQUESTED`; 1 MEDIUM, 3 NIT)

This revision resolves every finding in the latest review. None of them touched
the three-leg signing model (three distinct typed legs feeding one base-string
builder and one header builder, request/access tokens as distinct newtypes,
`oauth_token` never emitted empty), the GET-only verb-first invariant, the
loopback-only `127.0.0.1` bind as a code constant, in-memory/typestate
credential handling with a fresh flow at every startup, the bounded relay, the
multiset query handling, the locked crate stack, or the documented-assumption
treatment of the ETrade leg paths — all preserved unchanged. mTLS remains out of
scope.

- **#1 (MEDIUM) — AC-6 property ("out-of-prefix GET always rejected, including
  `/internal/status`") contradicted `admit` returning `Admission::Status`.**
  Resolved by restating AC-6 as the real invariant in the Testability `admit`
  bullet and the Open-Decisions entry. The tri-state `Admission`
  (`Forward`/`Status`/`Reject`) is reconciled with the "never admits" wording
  (FR-8 defines "admit" as "forwarded upstream") by pinning the property on the
  *forwarding* invariant: for every out-of-prefix `GET`, `admit` returns a
  **non-`Forward`** outcome (`!matches!(result, Admission::Forward(_))`). The one
  carve-out path `/internal/status` is covered by a dedicated example asserting
  `Admission::Status`, and the literal `/internal/status` is excluded from the
  `Reject(OutOfPrefix)`-asserting arm. No more "always `Reject`" claim that would
  fail on the `Status` path.
- **#2 (NIT) — non-UTF-8 raw-passthrough double-encodes `%` on the wire.**
  Resolved by adding a sentence to the `split_query` non-UTF-8 rule noting that
  raw passthrough re-encodes a non-UTF-8 escape (`%FF` → `%25FF`) so the upstream
  receives a double-encoded form, accepted because the signed and wire sides stay
  byte-identical and the inputs are pathological, and preferable to lossy U+FFFD.
  No code change.
- **#3 (NIT) — `oauth_callback_confirmed` from the request-token response was not
  checked.** Resolved. The leg-1 parser now parses-and-logs
  `oauth_callback_confirmed` (informational, non-fatal), and a first-run
  manual-verification checklist was added beside the feasibility note listing
  `oauth_callback_confirmed=true` as the active confirmation of the
  `oauth_callback=oob` assumption. No structural change.
- **#4 (NIT) — `expose_secret()` "exactly one place" wording invited a misread.**
  Resolved by rewording all three spots (the secret-newtype note, the `secrecy`
  stack bullet, and the `signing_key` doc comment) to "exactly one **source-level**
  call site (`signing_key`), invoked per leg/request, from which the exposed
  `&str` never escapes." No design change.

### Revision 7 — responses to the current review (`design-review.json`, verdict `CHANGES_REQUESTED`; 1 MEDIUM, 3 NIT)

This revision resolves every finding in the latest review. None of them touched
the three-leg signing model, the GET-only verb-first invariant, the
loopback-only `127.0.0.1` bind as a code constant, in-memory/typestate
credential handling with a fresh flow at every startup, the bounded relay, the
multiset query handling, the locked crate stack, or the documented-assumption
treatment of the ETrade leg paths — all of those are preserved unchanged. The
one MEDIUM finding was a correctness gap (nonce freshness) that no test in the
plan would catch because it is live-only; it is now an explicit, type-pinned
contract plus a shell assertion.

- **#1 (MEDIUM) — OAuth nonce/timestamp freshness per leg/request unspecified;
  signatures read as a single reused value.** Resolved by making freshness an
  explicit design contract reflected in the shell signatures. `shell::clock_nonce`
  now exposes **generator traits** — `Clock { fn now_unix(&self) -> Timestamp }`
  and `NonceSource { fn next(&self) -> Nonce }` (fresh per call, CSPRNG-backed) —
  and the shell draws a fresh `(nonce, timestamp)` **immediately before signing
  each OAuth leg and each proxied request**; no value is reused across legs or
  requests. `oauth_flow::run(&config, clock, nonces)` and
  `server::serve(port, tls, state, clock, nonces)` take the generators (not
  values); the three-leg flow and proxy handler step 3 now show the per-call
  `clock.now_unix()`/`nonces.next()` draw. The pure core still takes plain
  `&Nonce`/`&Timestamp` so property tests pin them. Added a shell integration
  assertion that two sequential proxied requests carry **distinct `oauth_nonce`
  values**, and that the request-token and access-token legs do too — pinning the
  contract at the shell even though wiremock does not validate nonces upstream.
- **#2 (NIT) — `rcgen` feature set not pinned in the locked stack.** Resolved.
  The self-signed-certificate stack bullet now states that
  `generate_simple_self_signed`/`CertifiedKey`/`KeyPair`/`Certificate::der()`
  live behind `rcgen 0.14`'s **`crypto` feature, which is a default feature in
  0.14**, so the default `rcgen = "0.14"` dependency compiles with no non-default
  feature — mirroring the explicit `reqwest` and `secrecy` feature pins.
- **#3 (NIT) — `oauth_callback=oob` rides the unverifiable-ETrade-API assumption
  but was not recorded as one.** Resolved. `oauth_callback=oob` is added to the
  documented-assumption note beside `core::oauth::endpoints` (now listing the leg
  paths, the authorize URL, and `oob` as the three confirm-on-first-run items),
  and the request-token leg's `OauthFlowError::UnexpectedStatus` message now hints
  that `oob` is an unverified assumption to check if leg 1 `401`s. No structural
  change.
- **#4 (NIT) — base64 engine/alphabet for the HMAC-SHA1 signature not pinned.**
  Resolved. `base64` is pinned to `0.22` in the stack and `sign_hmac_sha1` now
  pins the exact Engine-based call
  `base64::engine::general_purpose::STANDARD.encode(mac_bytes)` (standard
  alphabet, with padding), with the digest then percent-encoded by `oauth_encode`.

### Revision 6 — responses to the prior review (`design-review.json`, verdict `CHANGES_REQUESTED`; 2 MEDIUM, 3 NIT)

This revision resolves every finding in the latest review. None of the findings
touched the signing-leg model, the GET-only verb-first invariant, the
loopback-only bind, in-memory/typestate credential handling, bounded relay,
multiset query handling, the locked crate stack, or the documented-assumption
treatment of the ETrade leg paths, and all of those are preserved unchanged.

- **#1 (MEDIUM) — `authorize_url` percent-encoding conflicts with AC-12's
  exact-match assertion.** Resolved by pinning the encoder. The authorize URL is
  browser-facing, not a signature base string, so it does **not** reuse
  `oauth_encode`; `authorize_url` encodes `key`/`token` with ordinary
  `application/x-www-form-urlencoded` query encoding. AC-12's fixture is pinned
  to **encode-neutral** values (unreserved set only), so its literal expected
  string has no `%`-escapes and does not pin a particular encoder; a separate
  unit test over a `+`/`/`/`=` token asserts the query encoding yields
  `%2B`/`%2F`/`%3D`. The `authorize_url` section and the AC-12 Testability entry
  now both state this and agree. (See `core::authorize_url` / config section and
  the Testability `authorize_url` bullet.)
- **#2 (MEDIUM) — per-leg token-secret pairing was prose, not enforced by
  types.** Resolved by making the secret travel with the leg. `SigningInput::AccessToken`
  now carries `request_token_secret: &TokenSecret` and `SigningInput::Resource`
  carries `access_token_secret: &TokenSecret`, and a single new function
  `sign_leg(input, consumer_secret, query_params, nonce, timestamp) -> SignedLeg`
  derives **both** the `OauthParams` and the signing key from the one
  `SigningInput`, matching the variant to its secret. So "sign the access-token
  leg with the request token's secret" is the only expressible pairing and
  "sign a resource call with no/the-wrong secret" is unrepresentable. The
  lower-level `signing_key` is now documented as a helper whose only production
  caller is `sign_leg` (the single enforcing call site); the shell's two OAuth
  legs and the proxy handler all call `sign_leg`.
- **#3 (NIT) — `SigningInput::AccessToken` comment named a token-secret field
  the variant lacked.** Resolved together with #2: the variant now actually
  carries `request_token_secret: &TokenSecret`, and the comment is rewritten to
  match (and the `Resource` comment notes its `access_token_secret`).
- **#4 (NIT) — `rcgen 0.14` DER-extraction and key accessors unpinned.**
  Resolved. The stack and startup step 4 now pin the `0.14` contract:
  `generate_simple_self_signed` → `CertifiedKey { cert, signing_key }`;
  `cert.der()` (a `&CertificateDer`) is the fingerprint input and the rustls
  cert chain; `signing_key.serialize_der()` → `PrivateKeyDer::Pkcs8` is the
  rustls private key — matching the rigor applied to `secrecy`.
- **#5 (NIT) — `oauth_endpoint_url` comment duplicated the `UPSTREAM_HOST`
  literal.** Resolved. The comment now states the function builds from
  `format!("https://{UPSTREAM_HOST}{path}")`, so `UPSTREAM_HOST` is the only
  source of the host and no literal is duplicated; the comment is illustrative
  only.

### Revision 5 — responses to the prior review (`design-review.json`, verdict `CHANGES_REQUESTED`; 1 HIGH, 2 MEDIUM, 3 NIT)

This revision resolves every finding in the latest review. The headline change
restructures the OAuth signing domain around the **work performed, not the URL**,
which resolves the HIGH finding by construction.

- **#1 (HIGH) — header grammar lists `oauth_token` unconditionally, but the
  request-token leg has no token.** Resolved by remodeling. The single
  `oauth_params(key, Option<OauthToken>, …)` function (signing one *optional*
  token) is replaced with three distinct typed domains — `SigningInput::{
  RequestToken, AccessToken, Resource }` — each carrying exactly the fields its
  leg admits: the request-token leg has **no token field at all** (so
  `oauth_token=""` is unrepresentable, not merely avoided), the access-token leg
  carries the request token + verifier, and the resource leg carries the access
  token. `RequestToken` and `AccessToken` remain distinct newtypes. All three
  feed **one** `signature_base_string` builder and **one** `authorization_header`
  builder, both deriving their parameters from the same `OauthParams.as_pairs()`,
  so the base string and header are identical by construction and `oauth_token`
  is emitted only when the leg actually carried a token. The header grammar is
  rewritten as "exactly the pairs in `as_pairs()` plus the inserted
  `oauth_signature`," with `oauth_token`/`oauth_callback`/`oauth_verifier`
  annotated as present only on the legs that carry them. Added a proptest
  asserting base-string/header parameter-multiset agreement across all three leg
  variants and that the request-token leg emits no `oauth_token`.
- **#2 (MEDIUM) — relay buffer-vs-stream wording conflict and no size bound.**
  Resolved. The validation rule now reads "fully buffered (bounded, see below)
  and relayed without interpretation," matching the handler. Pinned a concrete
  `UPSTREAM_BODY_CAP = 8 MiB` named `const` with a size-limited read; exceeding
  it maps to `ProxyError::UpstreamTooLarge → 502` (checked before any
  status/headers are written, so the mapping stays honest). Added the
  `UpstreamTooLarge { cap }` arm to `ProxyError`.
- **#3 (MEDIUM) — duplicate query-key handling (multiset vs set).** Resolved.
  Specified that `split_query` and `wire_query` operate on an ordered
  `Vec<(String, String)>` that preserves duplicates as a **multiset** (no map, no
  de-dup); the base string sorts a **copy** for signing per §3.4.1.3.2 while
  `wire_query` preserves client order; and the proptest asserts **multiset**
  (sorted-vector) equality and includes a dedicated duplicate-key case
  (`?symbol=A&symbol=B&symbol=A`).
- **#4 (NIT) — OAuth leg paths unverifiable with no runtime guard.** Resolved.
  `OauthFlowError::UnexpectedStatus` and `Parse` now carry the endpoint constant
  name and their messages remind the operator to verify the path against current
  ETrade docs on a non-2xx/unparseable OAuth-leg response. Recorded the leg paths
  as an explicit, documented assumption to confirm during manual testing with
  real credentials (not a perpetual blocker), with the confirmation date to be
  noted beside the constants.
- **#5 (NIT) — configurable port only via `--port`.** Resolved. Stated that the
  listen port is configured solely via the `--port` flag (default `8443`), no
  `ETRADE_PORT` env var is provided, and FR-2's "and/or" is satisfied by the flag
  alone — in both the stack's CLI/config entry and startup step 1.
- **#6 (NIT) — `/internal/status` GET-only not restated.** Resolved. The status
  typestate section and the handler's `Status` arm now both restate that
  `/internal/status` is GET-only and a non-GET to it is rejected `405` by the
  verb-first `admit` check.

Everything the review confirmed sound is preserved unchanged: GET-only enforced
verb-first (never path-glob) and never forwarding a non-GET upstream;
loopback-only `127.0.0.1` bind as a code constant; access token in memory only,
never persisted, fresh OAuth flow at every startup and only at startup; the
`Unauthorized → Authorized` typestate backing `/internal/status`; env-var
credentials `ETRADE_CONSUMER_KEY`/`ETRADE_CONSUMER_SECRET`; live
`api.etrade.com` with no sandbox toggle; the locked `axum`+`hyper`/`reqwest` +
`rustls` (not OpenSSL) stack, `rcgen` self-signed cert with printed SHA-256
fingerprint, `secrecy 0.10`; the `/etrade-api` → `/v1/accounts/*` mapping; and
mTLS out of scope.

### Revision 4 — responses to the prior review (`design-review.json`, verdict `CHANGES_REQUESTED`; 3 MEDIUM, 4 NIT)

This revision resolves every finding in the latest review. Each response is
consistent with the requirements and the steering doc.

- **#1 (MEDIUM) — signed query params and wire query params can diverge.**
  Addressed. The proxy handler no longer builds the outbound URL from the raw
  client query. A new pure helper `core::oauth::wire_query(pairs) -> String`
  re-serializes the *same* filtered, `oauth_encode`-canonicalized pairs that
  were signed, so the signed set and the sent set are byte-identical;
  client-supplied `oauth_*` params are dropped from both sides and
  equivalent-but-different encodings normalize identically. Added a proptest
  asserting `signed set == wire set`.
- **#2 (MEDIUM) — `split_query` percent-decoding of non-UTF-8 input
  unspecified.** Addressed. Pinned the behavior: decode each name/value with
  `decode_utf8()` and on failure **pass the raw (still-encoded) token through
  unchanged** (never lossy U+FFFD), keeping `split_query` total and keeping the
  signed and wire sets identical even for non-UTF-8 input. Added a non-UTF-8
  proptest input class asserting totality and signed-set == wire-set.
- **#3 (MEDIUM) — ETrade OAuth endpoint paths asserted/unverified and
  duplicated.** Addressed. Added `core::oauth::endpoints` as the single source
  of truth for `UPSTREAM_HOST`, `REQUEST_TOKEN_PATH`, `ACCESS_TOKEN_PATH`, and
  `AUTHORIZE_URL_BASE`, with the ETrade doc URL cited beside each; `upstream_base_url`,
  `shell::oauth_flow`, and `authorize_url` all build from these constants so the
  host appears once. Added an explicit feasibility note that the two leg paths
  are the design's assertion, must be confirmed against the live docs before
  first run, and are not caught by AC-13 (no-live-calls) tests.
- **#4 (NIT) — `secrecy` 0.10 API contract hedges between versions.** Addressed.
  Dropped the 0.8/0.9 comparison; the locked stack now states the single pinned
  0.10 contract (`SecretString::from(String)`, `expose_secret() -> &str`,
  redacting `Debug`, no `Display`, zeroize on drop).
- **#5 (NIT) — TLS fingerprint hashing input and rendering unspecified.**
  Addressed. Specified SHA-256 over the certificate **DER bytes**, rendered as
  **lowercase colon-separated hex**, as a pure core function
  `core::tls_fingerprint::fingerprint(der) -> String` fed DER by the shell;
  added a pure unit test for it.
- **#6 (NIT) — mid-stream upstream failure vs 502 mapping undefined.**
  Addressed. The proxy handler now **buffers** the small account-JSON body
  before responding, so an upstream error is caught before any status/headers
  are written and `ProxyError::Upstream → 502` stays honest with no mid-stream
  window.
- **#7 (NIT) — `SystemTime`→unix-seconds conversion failure not documented.**
  Addressed. Noted that `shell::clock_nonce` uses
  `SystemTime::now().duration_since(UNIX_EPOCH)` and that the pre-1970 error arm
  is one of the documented `expect()` sites (an unrecoverable startup
  invariant), consistent with the steering rule on documented unreachable
  panics.

### Revision 3 — responses to the prior review (`design-review.json`, revision 2)

This revision resolves every HIGH/MEDIUM finding (there are no HIGH) and all
NITs in the latest `.agents/tasks/design-review.json` (verdict
`CHANGES_REQUESTED`; 4 MEDIUM, 4 NIT). Each response is consistent with the
requirements and the steering doc.

- **#1 (MEDIUM) — `signature_base_string` base-URI normalization unspecified.**
  Addressed. Added the pure helper `core::oauth::upstream_base_url(path) ->
  String` as the single base-URI construction site and stated the explicit RFC
  5849 §3.4.1.2 contract: `base_url` is the normalized URI (lowercase scheme
  `https`, lowercase host `api.etrade.com`, default port 443 omitted, no query,
  no fragment), and `signature_base_string` assumes a pre-normalized argument
  and does not re-normalize. The handler now calls `upstream_base_url`.
- **#2 (MEDIUM) — `oauth_params` token typing cannot serve the access-token
  legs.** Addressed. Introduced `pub enum OauthToken<'a> { Request(&'a
  RequestToken), Access(&'a AccessToken) }` and changed `oauth_params` to take
  `Option<OauthToken<'_>>`, so the request-token leg (`None`), access-token leg
  (`Request`), and proxy-forward leg (`Access`) all pass the correct newtype
  without collapsing `RequestToken` and `AccessToken` (preserves NFR-1).
- **#3 (MEDIUM) — query merge can inject/shadow `oauth_*`; encoded-sort
  tie-break ambiguous.** Addressed. `split_query` now drops incoming parameters
  whose decoded name begins with `oauth_` before merging, so client input cannot
  inject or shadow a protocol parameter; and base-string step 2 is reworded to
  sort the **already-encoded** pairs by encoded name then encoded value (RFC
  5849 §3.4.1.3.2).
- **#4 (MEDIUM) — `oauth_callback`/`oauth_verifier` not clearly folded into the
  signed base string.** Addressed. Stated that `OauthParams` stores the `extra`
  entries and that `as_pairs()` emits them, so callback/verifier enter **both**
  the base string and the header. Added the wiremock assertion that the
  request-token base string contains `oauth_callback=oob` (and the access-token
  call `oauth_verifier`).
- **#5 (NIT) — `secrecy` version unpinned.** Addressed. Pinned
  `secrecy = "0.10"` in the locked stack and documented the version-sensitive
  contract (`SecretString::from(String)`, `expose_secret() -> &str`).
- **#6 (NIT) — `RwLock` kind unstated.** Addressed. Stated `std::sync::RwLock`
  (not `tokio::sync::RwLock`), that reads are synchronous and guards are never
  held across `.await`, and noted `parking_lot` as an acceptable drop-in not
  added to the stack.
- **#7 (NIT) — `relay_header_allowed` in `core::admission` muddies its
  responsibility.** Addressed. Moved the predicate to its own pure module
  `core::relay`, leaving `core::admission` as the central-invariant module only.
- **#8 (NIT) — `Content-Length` in the relay whitelist is self-contradictory.**
  Addressed. Dropped `Content-Length` from the copied whitelist; the framework
  sets `Content-Length`/transfer-encoding for the relayed body.

### Revision 2 — responses to the prior review

The following resolved the earlier review round and remain in force.

- **#1 (HIGH) — query params missing from the signature base string.**
  Addressed. Added the pure `core::oauth::split_query(path_and_query) ->
  (String, Vec<(String,String)>)` (decode-then-encode, total), specified that
  the handler builds `base_params = OauthParams.as_pairs() ++ query_params` and
  passes the no-query `base_url` to `signature_base_string`, and added a
  `split_query`-into-base-string proptest. Satisfies RFC 5849 §3.4.1.3.1 and
  FR-7's query preservation.
- **#2 (HIGH) — base-string vs header parameter separation.** Addressed.
  `OauthParams` has **no `oauth_signature` field** by construction; the base
  string is built from `OauthParams.as_pairs()` ∪ query params (signature
  excluded), and `oauth_signature` is computed last and inserted only by
  `authorization_header`. Added the RFC 5849 reference-vector test asserting the
  base string omits `oauth_signature`.
- **#3 (HIGH) — header grammar / signature percent-encoding.** Addressed.
  Specified the exact `OAuth key="val", ...` grammar, every value (including the
  base64 signature's `+`/`/`/`=`) percent-encoded via the shared `oauth_encode`
  and double-quoted, `realm` omitted. Added a test that the signature is
  percent-encoded in the header.
- **#4 (MEDIUM) — `secrecy` absent from locked stack; no `Display`.**
  Addressed. Added pinned `secrecy` to the locked stack; corrected the claim to
  "redacting `Debug` only, no `Display`"; specified `signing_key` is the sole
  `expose_secret()` call site and the exposed value never escapes it; noted
  zeroize-on-drop as an NFR-2 benefit.
- **#5 (MEDIUM) — Pending/Ready → status body mapping.** Addressed. Added the
  explicit handler match (`Pending → status_body_unauthorized()`,
  `Ready(a) → status_body_authorized(a)`) with the read guard dropped before
  serialization and no `.await` held.
- **#6 (MEDIUM) — contradictory reject codes / `NotFound`.** Addressed.
  Tabulated one code per reason (`MethodNotGet → 405`, `OutOfPrefix → 404`) and
  dropped `NotFound` from `RejectReason`.
- **#7 (MEDIUM) — Pending/503 test seam.** Addressed. Documented that
  `shell::server::serve` accepts the `Arc<RwLock<AuthPhase>>` so a test injects
  `Pending` to exercise the 503 / `NotReady` path and the AC-10 unauthorized
  case.
- **#8 (MEDIUM) — unrequested verifier re-prompt.** Addressed by dropping it
  (option a): a single prompt, fail on first empty verifier with
  `OauthFlowError::EmptyVerifier`, matching FR-3/CONCEPT.
- **#9 (NIT) — `UpstreamPath` (with query) vs no-query `base_url`.** Addressed.
  The `UpstreamPath` doc comment now ties to `split_query`, making the two
  consistent.
- **#10 (NIT) — multi-thread tokio flavor.** Addressed by switching to
  `flavor = "current_thread"` for this single-user loopback proxy.
- **#11 (NIT) — clippy gate naming.** Addressed. Named the enforced gate
  `cargo clippy --all-targets --all-features -- -D warnings`.
```