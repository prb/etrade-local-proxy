//! Certificate fingerprint rendering (pure).
//!
//! Computes SHA-256 over the certificate DER bytes and renders it as lowercase
//! hex with colon separators (32 colon-separated octets), so a client
//! bootstrapping trust can reproduce it. The shell supplies the DER bytes from
//! `rcgen`'s `cert.der()`.

use sha2::{Digest, Sha256};

/// SHA-256 over `der`, rendered as lowercase colon-separated hex
/// (`ab:cd:…`, 32 octets). Pure; total.
pub fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_known_vector() {
        // SHA-256 of the empty string.
        let fp = fingerprint(b"");
        assert_eq!(
            fp,
            "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:\
27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55"
                .replace('\n', "")
        );
    }

    #[test]
    fn renders_thirty_two_octets() {
        let fp = fingerprint(b"some der bytes");
        let octets: Vec<&str> = fp.split(':').collect();
        assert_eq!(octets.len(), 32);
        for octet in octets {
            assert_eq!(octet.len(), 2);
            assert!(octet.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn known_vector_abc() {
        // SHA-256("abc").
        let fp = fingerprint(b"abc");
        assert_eq!(
            fp,
            "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:\
b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad"
                .replace('\n', "")
        );
    }
}
