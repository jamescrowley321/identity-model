//! The HTTP client the harness hands every library client.
//!
//! reqwest with rustls ignores `SSL_CERT_FILE`, and the local suite's
//! certificate cannot simply be added as a root: `cert-init` mints it with
//! `openssl req -x509`, which marks it `CA:TRUE`, and webpki refuses a CA
//! certificate presented as the server's own (`CaUsedAsEndEntity`). So the
//! harness pins that exact certificate on top of the bundled webpki roots
//! (never instead of them). A hosted run starts the harness without the local
//! suite, so a missing certificate file is tolerated and the client is the
//! library's own hardened default.

use std::path::Path;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Where the local suite's `cert-init` writes the nginx certificate.
pub const SUITE_CERT_PATH: &str = "/certs/nginx-selfsigned.crt";

/// Whether the suite certificate was found and pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteRoot {
    Pinned,
    Absent,
}

/// Accepts exactly one pinned server certificate, and anything the bundled
/// webpki roots accept. Handshake signatures are always verified, so the peer
/// must hold the pinned certificate's private key.
#[derive(Debug)]
struct PinnedOrWebPki {
    pinned: CertificateDer<'static>,
    roots: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedOrWebPki {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            return Ok(ServerCertVerified::assertion());
        }
        self.roots
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.roots.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.roots.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.roots.supported_verify_schemes()
    }
}

fn verifier(pinned: CertificateDer<'static>) -> Result<PinnedOrWebPki, String> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| format!("build webpki verifier: {e}"))?;
    Ok(PinnedOrWebPki { pinned, roots })
}

/// Builds the harness HTTP client from the library's hardened builder,
/// pinning the PEM certificate at `cert_path` too when it exists.
pub fn build_http_client(cert_path: &Path) -> Result<(reqwest::Client, SuiteRoot), String> {
    let builder = rs_identity_model::secure_client_builder();
    let (builder, root) = match std::fs::read(cert_path) {
        Ok(pem) => {
            let pinned = CertificateDer::from_pem_slice(&pem)
                .map_err(|e| format!("parse {}: {e}", cert_path.display()))?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("TLS protocol versions: {e}"))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier(pinned)?))
                .with_no_client_auth();
            (builder.use_preconfigured_tls(config), SuiteRoot::Pinned)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (builder, SuiteRoot::Absent),
        Err(e) => return Err(format!("read {}: {e}", cert_path.display())),
    };
    let client = builder
        .build()
        .map_err(|e| format!("build HTTP client: {e}"))?;
    Ok((client, root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_name() -> ServerName<'static> {
        ServerName::try_from("localhost.emobix.co.uk").expect("name")
    }

    #[test]
    fn missing_certificate_is_tolerated() {
        let (_, root) = build_http_client(Path::new("/nonexistent/suite.crt")).expect("client");
        assert_eq!(root, SuiteRoot::Absent);
    }

    #[test]
    fn unparseable_certificate_is_an_error() {
        let path = std::env::temp_dir().join(format!("bad-cert-{}.crt", std::process::id()));
        std::fs::write(&path, b"no certificate here\n").expect("write");
        let result = build_http_client(&path);
        std::fs::remove_file(&path).expect("cleanup");
        assert!(
            result.is_err(),
            "a file without a PEM certificate must not build a client"
        );
    }

    #[test]
    fn only_the_pinned_certificate_bypasses_the_roots() {
        let pinned = CertificateDer::from(b"pinned-der".to_vec());
        let verifier = verifier(pinned.clone()).expect("verifier");
        let accepted =
            verifier.verify_server_cert(&pinned, &[], &server_name(), &[], UnixTime::now());
        assert!(accepted.is_ok(), "{accepted:?}");

        // Anything else goes to webpki, which rejects this non-certificate.
        let other = CertificateDer::from(b"other-der".to_vec());
        let rejected =
            verifier.verify_server_cert(&other, &[], &server_name(), &[], UnixTime::now());
        assert!(
            rejected.is_err(),
            "an unpinned certificate must be verified by the roots"
        );
    }
}
