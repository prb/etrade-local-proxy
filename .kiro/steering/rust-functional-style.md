---
inclusion: always
---

# Idiomatic Functional Rust

This document defines what "idiomatic functional approaches" means for Rust
code in this workspace. The goal is pragmatic functional Rust: lean on the type
system, errors as values, and a pure core behind a thin IO shell — without
fighting the language where `async` IO or mutation is the honest choice.

## Guiding principle: functional core, imperative shell

Keep the decision-making logic pure and push side effects (network calls,
stdin/stdout, the clock, the filesystem, sockets) to the outer edges.

- **Pure core**: data transformation, validation, encoding/decoding, business
  rules, serialization. These take data in and return data out with no IO.
- **Imperative shell**: servers, clients, CLI prompts, config loading, anything
  that touches the OS or the network. These call into the pure core and perform
  the actual effects.

A good litmus test: the core should be unit-testable with plain values and no
mocks, network, or async runtime.

## Errors as values

- Return `Result<T, E>` for anything fallible. Reserve `panic!`, `unwrap`, and
  `expect` for genuinely unreachable states and startup invariants that make
  continuing meaningless — and document why at each such call site.
- Use a typed error enum per module (via `thiserror`) rather than stringly-typed
  errors. The top-level CLI/`main` boundary may use `anyhow` to aggregate, but
  library-style modules should expose precise error types.
- Propagate with `?`. Convert between error types with `From` impls (which
  `thiserror`'s `#[from]` generates) so `?` stays clean.
- Add context at boundaries where it helps diagnosis, not at every frame.

## Model state in the type system

Make illegal states unrepresentable.

- Represent lifecycles and modes as distinct types rather than a boolean plus
  optional fields. Prefer consuming one state value to produce the next (a
  typestate) so operations only valid in a given state exist as methods on that
  state's type, and a nullable/flag field can never drift out of sync with
  reality.
- Prefer enums with data over flag booleans. Prefer newtypes
  (`struct UserId(u64)`) over bare primitives for domain values that shouldn't
  be interchangeable.
- Use `#[non_exhaustive]` on public error enums that may grow.

## Prefer expressions and combinators

- Favor `Option`/`Result` combinators — `map`, `and_then`, `ok_or`,
  `unwrap_or_else`, `map_err` — over manual `match`/`if let` ladders when the
  combinator chain is at least as readable. Use `match` when it reads more
  clearly; readability wins over dogma.
- Use iterator chains (`iter`, `map`, `filter`, `collect`, `fold`) over
  index-based or accumulator mutation loops where the chain is clear.
- `let ... else` and `if let` are fine for early exits; don't nest deeply when a
  combinator flattens it.
- Treat values as immutable by default. Introduce `mut` only when it is the
  clearer or necessary choice (e.g. building a response, a hot loop), and keep
  its scope tight.

## Purity and determinism

- Inject non-determinism rather than reaching for it. A function that needs the
  current time, a nonce, randomness, or a generated id should take those as
  parameters so the core stays deterministic and testable. The shell supplies
  the real clock/RNG.
- Keep transformations total where possible: handle every case the type admits,
  rather than assuming a shape and panicking when it differs.

## Testing

The functional core / imperative shell split is what makes this style testable;
test each half with the technique that fits it.

- **Property-based testing for the pure core.** Where logic has properties that
  should hold for all inputs, prefer property tests (`proptest`) over only
  hand-picked examples. The pure core is the natural target: plain values in,
  plain values out, no runtime needed. Use it where it earns its keep, not
  everywhere for its own sake. Good shapes to look for:
  - **Round-trips** — `decode(encode(x)) == x` for serialization, encoding, and
    similar reversible transforms.
  - **Invariants** — a validator never admits a disallowed input; a parser
    never panics on arbitrary input (this is the totality rule, checked).
  - **Equivalence** — a fast or refactored implementation agrees with a simple
    reference one.
- **Determinism makes properties reproducible.** The inject-the-clock/nonce/RNG
  rule above is what lets a property test pin inputs and get repeatable results;
  the two rules reinforce each other. When a property fails, persist the failing
  case as a concrete regression test (`proptest` saves failing seeds for this).
- **Example-based tests still matter.** Table-driven unit tests remain the right
  tool for known edge cases and regressions, alongside — not replaced by —
  property tests.
- **The shell gets integration tests.** IO-heavy code doesn't suit properties;
  cover it with example-based integration tests, and keep the shell thin so
  there is little logic sitting outside the property-tested core. Snapshot
  testing (`insta`) is a reasonable fit for asserting on serialized output.

## Where functional purity yields

Be honest about the boundaries. This is Rust, not Haskell.

- `async` IO (servers, outbound clients) is inherently effectful; that's
  expected and fine. Keep the effectful surface thin and delegate decisions back
  to pure functions.
- Shared mutable runtime state (e.g. behind an `Arc<RwLock<...>>` or an
  actor/channel) is acceptable where a long-running process needs it. Isolate
  it; don't thread mutability through the core.
- Performance-sensitive code may use mutation and allocation deliberately.
  Comment the intent when it departs from the functional default.

## Conventions summary

- `Result` + `?` + `thiserror` for errors; `anyhow` only at the `main` edge.
- Typed states over boolean flags; newtypes over bare primitives.
- Pure core, thin IO shell; inject clock/nonce/RNG.
- Combinators and iterators over manual loops when clearer.
- Immutable by default; scoped, intentional `mut`.
- No `unwrap`/`expect` outside documented, truly-unreachable cases.
- Property tests (`proptest`) for the pure core where properties hold;
  example-based and integration tests for edge cases and the shell.
