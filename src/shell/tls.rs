//! Ephemeral self-signed TLS: generate an in-memory cert/key with `rcgen`,
//! print the SHA-256 fingerprint (computed by the pure core), and build the
//! `rustls` server config. No file is ever written, consistent with the
//! no-persistence posture.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use crate::core::tls_fingerprint::fingerprint;
use crate::shell::error::TlsError;

/// The subject alternative name for the loopback-only certificate.
const SAN: &str = "127.0.0.1";

/// The result of TLS setup: the ready `rustls` server config plus the printed
/// fingerprint (returned for tests; also written to stdout by [`generate`]).
pub struct Tls {
    pub server_config: Arc<ServerConfig>,
    pub fingerprint: String,
}

/// Generate an ephemeral self-signed cert/key for `127.0.0.1`, print its
/// SHA-256 fingerprint to stdout, and build the `rustls` server config.
pub fn generate() -> Result<Tls, TlsError> {
    let certified = generate_simple_self_signed([SAN.to_string()])?;

    // Fingerprint is computed by the pure core over the DER bytes.
    let der = certified.cert.der();
    let fp = fingerprint(der);
    println!("TLS certificate SHA-256 fingerprint: {fp}");

    let server_config = build_server_config(der, &certified.signing_key.serialize_der())?;

    Ok(Tls {
        server_config: Arc::new(server_config),
        fingerprint: fp,
    })
}

/// Build the `rustls` server config from the cert DER chain and the PKCS#8
/// private key DER. The crypto provider is chosen explicitly (`aws_lc_rs`, the
/// rustls default) so that the presence of a second provider pulled in by
/// `reqwest` cannot make the process-default ambiguous.
fn build_server_config(
    cert_der: &CertificateDer<'static>,
    key_pkcs8_der: &[u8],
) -> Result<ServerConfig, TlsError> {
    let cert_chain = vec![cert_der.clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8_der.to_vec()));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::RustlsConfig)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(TlsError::RustlsConfig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_config_and_fingerprint() {
        let tls = generate().expect("tls generation succeeds");
        // Fingerprint is 32 colon-separated lowercase hex octets.
        let octets: Vec<&str> = tls.fingerprint.split(':').collect();
        assert_eq!(octets.len(), 32);
        assert!(tls
            .fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':'));
        // The server config is usable (Arc holds a built config).
        assert!(Arc::strong_count(&tls.server_config) >= 1);
    }
}
