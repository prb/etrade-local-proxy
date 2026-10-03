// Each integration-test binary compiles this module independently, so helpers
// unused by a given binary would warn; allow dead_code for the shared util.
#![allow(dead_code)]

//! Shared helpers for the shell integration suite.
//!
//! These tests drive the imperative shell against a **local** `wiremock`
//! upstream — there is no live ETrade call anywhere (AC-13). The helpers below
//! build a `Config` from plain values and parse the OAuth parameters back out
//! of a recorded `Authorization` header so a test can assert on the signed
//! parameter set.

use etrade_local_proxy::core::config::{build_config, Config, EnvSnapshot};
use etrade_local_proxy::core::env::Environment;
use etrade_local_proxy::core::newtypes::ListenPort;

/// A `Config` built from fixed, non-secret test credentials, targeting the live
/// environment (the default).
pub fn test_config() -> Config {
    let env = EnvSnapshot {
        consumer_key: Some("ckey".into()),
        consumer_secret: Some("csec".into()),
    };
    build_config(&env, ListenPort::new(8443), Environment::Live).expect("valid test config")
}

/// Parse the `(name, value)` pairs out of a rendered `OAuth ...` header,
/// decoding the percent-encoded, double-quoted values.
///
/// Because the pure core builds the `Authorization` header and the signature
/// base string from the **same** `OauthParams::as_pairs()`, the parameter set
/// recovered here is byte-for-byte the set that entered the base string. A test
/// asserting the header carries `oauth_callback=oob` is therefore asserting the
/// same about the signed base string.
pub fn parse_oauth_header(header: &str) -> Vec<(String, String)> {
    let body = header
        .strip_prefix("OAuth ")
        .expect("Authorization header uses the OAuth scheme");
    body.split(", ")
        .map(|kv| {
            let (name, quoted) = kv.split_once('=').expect("name=value pair");
            let value = quoted.trim_matches('"');
            let decoded = percent_encoding::percent_decode(value.as_bytes())
                .decode_utf8()
                .expect("header values are valid utf8")
                .into_owned();
            (name.to_string(), decoded)
        })
        .collect()
}

/// The value of a single OAuth parameter from a rendered header, if present.
pub fn oauth_param(header: &str, name: &str) -> Option<String> {
    parse_oauth_header(header)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
}
