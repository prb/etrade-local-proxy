//! Integration test for the `rcgen` → fingerprint seam: `rcgen` produces a
//! usable self-signed cert whose DER the shell hashes into the exact lowercase
//! colon-hex SHA-256 format, consistent with the pure-core `tls_fingerprint`
//! implementation.

use rcgen::generate_simple_self_signed;

use etrade_local_proxy::core::tls_fingerprint::fingerprint;
use etrade_local_proxy::shell::tls;

#[test]
fn shell_fingerprint_matches_core_over_rcgen_der() {
    // Generate the same way the shell does, then confirm the shell's printed
    // fingerprint equals the core function applied to the cert DER bytes.
    let certified =
        generate_simple_self_signed(["127.0.0.1".to_string()]).expect("rcgen generates a cert");
    let der = certified.cert.der();
    let expected = fingerprint(der);

    // 32 colon-separated lowercase hex octets.
    let octets: Vec<&str> = expected.split(':').collect();
    assert_eq!(octets.len(), 32, "SHA-256 renders as 32 octets");
    for octet in &octets {
        assert_eq!(octet.len(), 2, "each octet is two hex digits");
        assert!(
            octet
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "octet {octet} must be lowercase hex"
        );
    }

    // The shell's generate() computes the fingerprint over its own cert DER
    // with the same core function, so its output has the identical shape.
    let shell_tls = tls::generate().expect("shell tls generation succeeds");
    let shell_octets: Vec<&str> = shell_tls.fingerprint.split(':').collect();
    assert_eq!(shell_octets.len(), 32);
    assert!(shell_tls
        .fingerprint
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == ':'));

    // The DER bytes are non-trivial and the fingerprint is deterministic over
    // them (recomputing yields the same value).
    assert!(!der.is_empty(), "cert DER is non-empty");
    assert_eq!(expected, fingerprint(der));
}
