# Design Review: ETrade Local Read-Only Proxy

Reviewed document: `.agents/tasks/design.md` (revision 8)
Grounding: `CONCEPT.md`, `.agents/tasks/requirements.md`,
`.kiro/steering/rust-functional-style.md`
Reviewer posture: fresh read, no prior-round context assumed. Security-sensitive
local proxy holding live brokerage credentials in memory.

## Verdict

**APPROVED.** No HIGH or MEDIUM findings. Two NITs are recorded below for the
implementer's attention; neither blocks implementation.

The design stands on its own: the technology stack is locked with exact version
and feature pins, every pure-core function has a signature and a stated
behavior, the three security invariants (loopback bind, GET-only forwarding,
no-persistence) each name an owning layer and an enforcing mechanism, and the
test plan maps each acceptance criterion to a concrete test. I was able to
verify every dependency-API claim the design pins (see Verified Assumptions).

## Scrutiny of the mandated review points

Each item below is the specific thing the review was asked to block on. All
pass.

1. **Three-leg OAuth signing domain — PASS.** The signing domain is modeled as
   three distinct typed inputs: `SigningInput::{RequestToken, AccessToken,
   Resource}` (`core::oauth::params`). The `RequestToken` leg carries **no token
   field and no token secret** — only `consumer_key` and `callback` — so
   `oauth_token` cannot be emitted at all on that leg, empty or otherwise. The
   resulting `OauthParams` has `token: Option<String>` that is `None` for the
   request-token leg. `RequestToken` and `AccessToken` are **distinct newtypes**
   in distinct variants, so no leg can hold the wrong token type. All three legs
   feed **one** base-string builder (`signature_base_string`) and **one** header
   builder (`authorization_header`), and both derive their parameter set from the
   same `OauthParams.as_pairs()`, so the base string and the Authorization header
   cannot diverge by construction. `OauthParams` structurally has no
   `oauth_signature` field; the signature is computed last and inserted only by
   `authorization_header`. This is NOT "one function over an optional token"; it
   is the required three-domain model. The HIGH condition is satisfied.

2. **GET-only enforced verb-first — PASS.** `core::admission::admit` checks the
   method first and returns `Reject(MethodNotGet)` for any non-GET **before the
   path is examined** (so a `POST` to `.../orders` is rejected on the verb, not
   by path globbing). The shell has exactly one upstream-issuing site, reachable
   only from the `Admission::Forward` arm; non-GET is never forwarded upstream.
   `admit` is a total pure function over `(method, path)` using only total string
   operations.

3. **Loopback-only bind — PASS.** `shell::server::bind_addr(port)` constructs
   `SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.0)` from a code
   constant. Only the port is configurable; the IP is never derived from config,
   env, or input. AC-9 asserts loopback for every port.

4. **Token in memory, fresh per startup, typestate — PASS.** `Unauthorized →
   Authorized` consuming typestate (`core::status`); the access token/secret live
   only inside `Authorized`, which is held in `AuthPhase::Ready(Arc<Authorized>)`.
   No serialization impl and no filesystem write touches token types. The OAuth
   flow runs once at startup only; there is no caching or reuse across runs.
   `/internal/status` derives its body from which phase/type is current, not a
   boolean.

5. **Bounded body relay / consistent buffer-vs-stream wording — PASS.** The
   handler and the validation-rules section both say "fully buffered (bounded)
   and relayed without interpretation." `UPSTREAM_BODY_CAP = 8 MiB` is a named
   const; over-cap maps to `ProxyError::UpstreamTooLarge → 502`, checked before
   any status/headers are written so the 502 mapping is honest. Buffering (not
   streaming) is justified for small account JSON. Wording is consistent across
   the handler, validation rules, and error hierarchy.

6. **Multiset query handling — PASS.** `split_query` and `wire_query` both
   operate on an ordered `Vec<(String, String)>` that preserves duplicates (no
   map, no de-dup, no sort). The base string sorts a **copy** of the
   already-encoded pairs; `wire_query` preserves client order. The signed
   multiset and the wire multiset are the same `(name, value)` pairs differing
   only in order, pinned by a proptest that compares sorted vectors (multiset
   equality) and includes a dedicated `?symbol=A&symbol=B&symbol=A` case.

7. **Unverifiable ETrade endpoints recorded as a documented assumption — PASS.**
   `core::oauth::endpoints` centralizes `UPSTREAM_HOST`, `REQUEST_TOKEN_PATH`,
   `ACCESS_TOKEN_PATH`, `AUTHORIZE_URL_BASE`. The feasibility note records the two
   leg paths, the authorize URL, and `oauth_callback=oob` as explicit
   confirm-on-first-run assumptions with a manual-verification checklist, not
   perpetual blockers. The flow adds a self-announcing diagnostic
   (`OauthFlowError::UnexpectedStatus`/`Parse` carry the endpoint-constant name
   and a reminder) and parses-and-logs `oauth_callback_confirmed`. This is the
   correct treatment per the mandate.

8. **Functional-Rust steering conformance — PASS.** Errors as values with
   per-module `#[non_exhaustive]` `thiserror` enums and `#[from]`, `anyhow` only
   in `main`; typestate for the auth lifecycle; newtypes for all domain values;
   clock and nonce injected via `Clock`/`NonceSource` generator traits so the
   pure core takes plain `&Nonce`/`&Timestamp`; proptest for the pure core;
   `insta` for serialized output; integration tests + `wiremock` for the shell.
   The core/shell boundary is explicit and the core forbids `tokio`/`axum`/
   `reqwest`/`rustls`/`std::env`. Documented `expect()` sites (pre-1970 clock,
   poisoned startup lock, const IP) match the steering rule.

## Findings

### NIT-1 — Query string on `/internal/status` not specified

Location: `core::admission::admit` design points; `shell::handlers` `Status`
arm. The design states `GET /internal/status → Status` and that path parsing
splits on `?`, but it does not state whether `GET /internal/status?x=1` (status
path with a trailing query) still maps to `Status`. A client or health-checker
could append a cache-buster.

Concrete fix: state the rule explicitly — compare the path **before `?`** for
the status route, so `GET /internal/status?anything` still yields `Status`:

```
// in admit, after the verb check:
let path = path_and_query.split('?').next().unwrap_or(path_and_query);
match path { "/internal/status" => Admission::Status, ... }
```

and add a one-line proptest/example asserting `admit(Get, "/internal/status?x=1")
== Status`.

### NIT-2 — Authorization-header parameter ordering basis not pinned

Location: `core::oauth::sign::authorization_header` grammar ("Pairs are
comma-space separated and ordered by name"). The base string pins sorting on the
**encoded** name/value (RFC 5849 §3.4.1.3.2), but the header section says only
"ordered by name" without stating encoded-vs-raw. OAuth 1.0a does not require any
particular ordering in the `Authorization` header, so this is cosmetic and the
HIGH-fix test only asserts multiset equality (order-independent) — but pinning it
avoids an implementer guessing and avoids churn in any snapshot of the header.

Concrete fix: add one sentence — "header pairs are ordered by **encoded** name
(same basis as the base string) purely for determinism; ordering is not
protocol-significant." Or explicitly state the header order is unspecified and
tests must not assert on it.

## Verified Assumptions

Checked against docs.rs for the exact pinned versions:

- **secrecy 0.10** — `SecretString = SecretBox<str>` (type alias confirmed);
  `From<String>` impl exists (`SecretString::from(String)`); `ExposeSecret`
  trait method `expose_secret(&self) -> &S` yields `&str` for `SecretBox<str>`;
  serde `Serialize` is **not** derived by default (only `Deserialize` behind the
  `serde` feature), so a secret cannot be serialized to disk by accident —
  supports the no-persistence/no-leak posture (NFR-2). The design's
  "redacting Debug, no Display, zeroize on drop" claims are consistent with the
  SecretBox wrapper design.
- **rcgen 0.14** — `generate_simple_self_signed(...) -> Result<CertifiedKey<
  KeyPair>, Error>`; `CertifiedKey { pub cert: Certificate, pub signing_key: S }`
  destructures as the design shows; `Certificate::der(&self) -> &CertificateDer<
  'static>` (derefs to `[u8]`), usable as the fingerprint input and (cloned) as
  the rustls cert chain; `KeyPair::serialize_der(&self) -> Vec<u8>` (PKCS#8 DER)
  for the rustls private key wrapped as `PrivateKeyDer::Pkcs8`. The **`crypto`
  feature is a default feature** in 0.14 (confirmed on the features page:
  default = crypto, pem, ring), so the plain `rcgen = "0.14"` dependency compiles
  the used API — exactly as the design states. `generate_simple_self_signed`
  returns a `Result`, matching the `TlsError::CertGeneration(#[from] rcgen::Error)`
  mapping.
- **base64 0.22** — `base64::engine::general_purpose::STANDARD` is a
  `GeneralPurpose` engine with the standard alphabet and PAD config; the
  Engine-based `.encode(...)` call the design pins is the correct 0.22 API (the
  old free `base64::encode` is removed). Standard-alphabet-with-padding matches
  OAuth 1.0a HMAC-SHA1 signature encoding.
- **Internal consistency** — the Resource-leg query params are signed into the
  base string (`base_params = as_pairs() ++ query_params`) but correctly
  **excluded from the Authorization header** (which renders only
  `OauthParams.as_pairs()` + signature) and placed in the wire query via
  `wire_query` — this is correct per RFC 5849 (query params live in the URL, only
  `oauth_*` protocol params go in the header). The HIGH-fix multiset test
  compares the header against `as_pairs()`, not against `base_params`, so it is
  consistent with this split.
- **Config validation** — `ConfigError` enumerates missing and empty variants
  for both env vars; `EnvSnapshot` captures `Option<String>` and empty strings
  are treated as missing (FR-2/AC-11), with no socket bound before validation.

## Unverified / Wrong Assumptions

- **ETrade live OAuth endpoint paths and callback token** (`REQUEST_TOKEN_PATH`
  = `/oauth/request_token`, `ACCESS_TOKEN_PATH` = `/oauth/access_token`,
  `AUTHORIZE_URL_BASE` = `https://us.etrade.com/e/t/etws/authorize`,
  `oauth_callback=oob`, and `UPSTREAM_HOST = api.etrade.com` for the OAuth legs):
  **not byte-verified against the live ETrade service.** This environment has no
  authenticated access to ETrade, and AC-13 forbids live calls in tests. The
  design does exactly the right thing — isolates these as named constants in one
  module, records them as explicit confirm-on-first-run assumptions with a
  manual checklist, and makes a wrong value a self-announcing, diagnosable
  startup failure. This is a documented assumption, not a blocker, per the review
  mandate. No action required beyond the first-run verification the design
  already prescribes.

## Notes on completeness

Every acceptance criterion (AC-1 through AC-14) has a named test in the
Testability section. The one place requirements wording and the implementation
model needed reconciliation — AC-6's "never admits `/internal/status`" vs the
tri-state `Admission` that returns `Status` for that path — is explicitly
reconciled by pinning the property on the *forwarding* invariant
(`!matches!(result, Admission::Forward(_))`) with `/internal/status` carved out
as a `Status` example. That reconciliation is sound: FR-8 defines "admit" as
"forwarded upstream," and `/internal/status` is never forwarded upstream.
