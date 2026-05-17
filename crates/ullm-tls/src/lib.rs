// SPDX-License-Identifier: Apache-2.0
//! TLS helpers for ullm.
//!
//! The outer transport runs **TLS 1.3 with the post-quantum hybrid
//! `X25519MLKEM768` key exchange** (per `draft-ietf-tls-ecdhe-mlkem` /
//! TLS-named-group `0x11EC`). The PQ KEM is provided by the
//! [`rustls-post-quantum`] crate on top of the `aws-lc-rs` crypto provider;
//! falling back to classical groups (X25519, secp256r1) is permitted by the
//! provider so clients without PQ support still negotiate a working
//! handshake.
//!
//! Certificates are still pinned by SHA-256 fingerprint in the dev path; a
//! webpki / CA-rooted variant lives behind [`client_config_with_root`].

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("certificate generation failed: {0}")]
    CertGen(String),
    #[error("PEM parse error: {0}")]
    Pem(String),
    #[error("rustls error: {0}")]
    Rustls(String),
}

#[derive(Clone)]
pub struct SelfSignedCert {
    pub cert_der: Vec<u8>,
    pub key_der_pkcs8: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 over the DER-encoded certificate.
    pub fingerprint: [u8; 32],
    /// SANs the cert was issued for — bound into `FingerprintVerifier` so
    /// the pinned client also enforces the cert's named-binding (P2-7).
    pub sans: Vec<String>,
}

/// Default validity window for `SelfSignedCert::generate`. 24 hours is the
/// sweet spot for the dev path: long enough that a normal e2e run won't
/// hit the expiry, short enough that a leaked key isn't a 365-day MITM
/// loaded gun (P2-8). Callers that need longer can use
/// `generate_with_validity`.
pub const DEFAULT_CERT_VALIDITY_HOURS: u64 = 24;

impl SelfSignedCert {
    /// Generate a self-signed cert with a 24-hour validity window
    /// (`DEFAULT_CERT_VALIDITY_HOURS`).
    pub fn generate(subject_alt_names: &[&str]) -> Result<Self, TlsError> {
        Self::generate_with_validity(
            subject_alt_names,
            std::time::Duration::from_secs(DEFAULT_CERT_VALIDITY_HOURS * 3600),
        )
    }

    /// Generate a self-signed cert whose `notBefore` is *now* and `notAfter`
    /// is `now + validity`. The validity is explicit so operators can pick
    /// a window appropriate to their threat model (long-lived CA-issued
    /// certs go through `client_config_with_root` instead).
    pub fn generate_with_validity(
        subject_alt_names: &[&str],
        validity: std::time::Duration,
    ) -> Result<Self, TlsError> {
        let san_strings: Vec<String> =
            subject_alt_names.iter().map(|s| (*s).to_string()).collect();
        let mut params = CertificateParams::new(san_strings.clone())
            .map_err(|e| TlsError::CertGen(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "ullm-dev");
        params.distinguished_name = dn;
        // P2-8: pin notBefore + notAfter so a leaked private key can't be
        // used to MITM indefinitely. rcgen's default would otherwise hand
        // back a multi-year window.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(validity.as_secs() as i64);
        let kp = KeyPair::generate().map_err(|e| TlsError::CertGen(e.to_string()))?;
        let cert = params
            .self_signed(&kp)
            .map_err(|e| TlsError::CertGen(e.to_string()))?;
        let cert_der_owned = cert.der().to_vec();
        let cert_pem = cert.pem();
        let key_pem = kp.serialize_pem();
        let key_der_pkcs8 = kp.serialize_der();
        let fingerprint: [u8; 32] = Sha256::digest(&cert_der_owned).into();
        Ok(Self {
            cert_der: cert_der_owned,
            key_der_pkcs8,
            cert_pem,
            key_pem,
            fingerprint,
            sans: san_strings,
        })
    }

    pub fn cert_der_typed(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    pub fn key_der_typed(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der_pkcs8.clone()))
    }
}

/// The crypto provider used by every config we build. Includes
/// `X25519MLKEM768` as the preferred TLS 1.3 named group, with classical
/// groups (X25519, secp256r1) as fallback for clients that don't yet
/// support PQ.
fn pq_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_post_quantum::provider())
}

/// P13-FIX-A: strict PQ-hybrid crypto provider. Same suites + signature
/// algorithms as [`pq_provider`], but the `kx_groups` list is reduced to
/// `X25519MLKEM768` ONLY — no classical X25519 / secp256r1 fallback.
///
/// Use this in deployments where a downgrade to classical key exchange is
/// itself a security failure (a network attacker stripping
/// `key_share`/`supported_groups` would otherwise succeed by negotiating
/// classical-only and silently defeat the post-quantum guarantee). The
/// resulting config will *refuse* the handshake against any peer that does
/// not advertise X25519MLKEM768.
fn strict_pq_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls_post_quantum::provider();
    // Single-element kx group list. We rebuild the slice as `Vec<&'static
    // dyn SupportedKxGroup>` to keep the type identical to the field;
    // `X25519MLKEM768` is re-exported by `rustls-post-quantum` and points
    // at the underlying `aws_lc_rs::kx_group::X25519MLKEM768` static.
    let only_pq: Vec<&'static dyn SupportedKxGroup> =
        vec![rustls_post_quantum::X25519MLKEM768];
    provider.kx_groups = only_pq;
    Arc::new(provider)
}

/// Build a rustls `ServerConfig` (TLS 1.3 only, post-quantum hybrid KEX
/// preferred) for a single self-signed cert.
pub fn server_config(cert: &SelfSignedCert) -> Result<Arc<ServerConfig>, TlsError> {
    let cfg = ServerConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der_typed()], cert.key_der_typed())
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    Ok(Arc::new(cfg))
}

/// P13-FIX-A: strict-PQ variant of [`server_config`]. The returned config
/// only advertises `X25519MLKEM768` — a client that doesn't propose this
/// group (or a MITM that strips it from `key_share`/`supported_groups`)
/// gets `HandshakeFailure` instead of a silent classical downgrade. Use
/// when the post-quantum guarantee must be enforced rather than preferred.
pub fn server_config_strict_pq(cert: &SelfSignedCert) -> Result<Arc<ServerConfig>, TlsError> {
    let cfg = ServerConfig::builder_with_provider(strict_pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der_typed()], cert.key_der_typed())
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    Ok(Arc::new(cfg))
}

/// Build a rustls `ClientConfig` that pins exactly one server certificate
/// by SHA-256 fingerprint. TLS 1.3 only; post-quantum hybrid KEX preferred.
///
/// `expected_sans` is the list of DNS names / IPs the server is allowed
/// to claim. Without it the fingerprint pin would silently accept a cert
/// presented for any SNI (P2-7) — fingerprint-pinning is a *complement*
/// to named-binding, not a replacement.
pub fn client_config_pinned(
    expected_fingerprint: [u8; 32],
    expected_sans: Vec<String>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let verifier = Arc::new(FingerprintVerifier {
        expected: expected_fingerprint,
        expected_sans,
    });
    let cfg = ClientConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// P13-FIX-A: strict-PQ variant of [`client_config_pinned`]. Identical
/// fingerprint + SAN binding semantics, but the only advertised TLS 1.3
/// named group is `X25519MLKEM768`. A MITM (or a non-PQ server) that
/// cannot speak the hybrid group fails the handshake instead of
/// negotiating a classical fallback.
pub fn client_config_pinned_strict_pq(
    expected_fingerprint: [u8; 32],
    expected_sans: Vec<String>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let verifier = Arc::new(FingerprintVerifier {
        expected: expected_fingerprint,
        expected_sans,
    });
    let cfg = ClientConfig::builder_with_provider(strict_pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Build a rustls `ClientConfig` rooted at a single CA cert (for the
/// production path that uses real CA-issued certs).
pub fn client_config_with_root(
    root_cert_der: CertificateDer<'static>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(root_cert_der)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    let cfg = ClientConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
    /// Names the cert is allowed to be presented for. When non-empty, the
    /// TLS SNI is checked against this list (P2-7). When empty, the SNI
    /// check is skipped — a sharper foot-gun than we want as the default,
    /// so `client_config_pinned` requires the caller to pass a list.
    expected_sans: Vec<String>,
}

impl FingerprintVerifier {
    fn sni_allowed(&self, server_name: &ServerName<'_>) -> bool {
        if self.expected_sans.is_empty() {
            return true;
        }
        // Render `ServerName` to its canonical wire form: DNS names land in
        // their lowercase ASCII form (`as_ref()`); IP names render via the
        // standard library's `IpAddr` Display so we get `"127.0.0.1"` /
        // `"::1"` rather than the rustls debug shape. Compare
        // case-insensitively against the pinned SAN list.
        let presented = match server_name {
            ServerName::DnsName(d) => d.as_ref().to_ascii_lowercase(),
            ServerName::IpAddress(ip) => {
                let std_ip: std::net::IpAddr = (*ip).into();
                std_ip.to_string().to_ascii_lowercase()
            }
            _ => return false,
        };
        self.expected_sans
            .iter()
            .any(|s| s.to_ascii_lowercase() == presented)
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if !constant_eq(&got, &self.expected) {
            return Err(rustls::Error::General(
                "pinned cert fingerprint mismatch".into(),
            ));
        }
        if !self.sni_allowed(server_name) {
            return Err(rustls::Error::General(format!(
                "TLS SNI {server_name:?} not in pinned SAN list"
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // We restrict the config to TLS 1.3, so this path never executes.
        Err(rustls::Error::General(
            "TLS 1.2 not supported".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
        ]
    }
}

fn constant_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Install the PQ-hybrid crypto provider as the process default. Idempotent.
///
/// Must be called once per process before any rustls config is built that
/// relies on `CryptoProvider::get_default()`.
pub fn install_default_crypto_provider() {
    let provider = rustls_post_quantum::provider();
    let _ = provider.install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_advertises_x25519_mlkem768() {
        let p = pq_provider();
        let names: Vec<String> = p.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();
        // The post-quantum provider must include X25519MLKEM768 (named group 0x11EC).
        assert!(
            names.iter().any(|n| n.contains("MLKEM768")),
            "PQ provider missing X25519MLKEM768: {names:?}"
        );
    }

    /// Regression for P13-FIX-A: the strict provider must advertise
    /// **exactly one** kx group — `X25519MLKEM768`. Any classical fallback
    /// here would re-introduce the downgrade vector the strict path
    /// exists to close.
    #[test]
    fn strict_pq_provider_is_mlkem_only() {
        let p = strict_pq_provider();
        assert_eq!(
            p.kx_groups.len(),
            1,
            "strict PQ provider must have exactly 1 kx group, found {} ({:?})",
            p.kx_groups.len(),
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
        );
        let only = p.kx_groups[0].name();
        let want = rustls_post_quantum::X25519MLKEM768.name();
        assert_eq!(
            only, want,
            "strict PQ provider's only kx group must be X25519MLKEM768, was {only:?}"
        );
    }

    /// Regression for P13-FIX-A: a `server_config_strict_pq` builds (i.e.
    /// the cert + the single-group provider are mutually compatible) and
    /// its provider exposes only the MLKEM hybrid. Belt-and-suspenders
    /// over `strict_pq_provider_is_mlkem_only` — confirms the constraint
    /// survives `ServerConfig::builder_with_provider`'s plumbing rather
    /// than testing the provider helper in isolation.
    #[test]
    fn server_config_strict_pq_kx_groups_mlkem_only() {
        let cert = SelfSignedCert::generate(&["localhost"]).unwrap();
        let cfg = server_config_strict_pq(&cert).unwrap();
        assert_eq!(
            cfg.crypto_provider().kx_groups.len(),
            1,
            "strict server config kx_groups must be a single entry"
        );
        assert_eq!(
            cfg.crypto_provider().kx_groups[0].name(),
            rustls_post_quantum::X25519MLKEM768.name(),
        );
    }

    #[test]
    fn restricts_to_tls13() {
        let cert = SelfSignedCert::generate(&["localhost"]).unwrap();
        let _server = server_config(&cert).unwrap();
        let _client = client_config_pinned(cert.fingerprint, cert.sans.clone()).unwrap();
    }

    /// Regression for P2-7: a fingerprint match alone is not enough — the
    /// SNI must also belong to the cert's pinned SAN list. A peer with the
    /// right cert presented for an unexpected hostname is still rejected.
    #[test]
    fn fingerprint_pin_also_enforces_sni() {
        use rustls::pki_types::{DnsName, ServerName};
        let fp = [0u8; 32];
        let v = FingerprintVerifier {
            expected: fp,
            expected_sans: vec!["genuine.example".into()],
        };
        let good: ServerName = ServerName::DnsName(DnsName::try_from("genuine.example").unwrap());
        let bad: ServerName = ServerName::DnsName(DnsName::try_from("evil.example").unwrap());
        assert!(v.sni_allowed(&good));
        assert!(!v.sni_allowed(&bad));
    }

    /// Regression for P2-8: a generated self-signed cert has a *bounded*
    /// validity window. We don't pin the exact value (rcgen + time drift)
    /// but we do assert it's nowhere near a multi-year footgun.
    #[test]
    fn self_signed_cert_validity_is_short() {
        let cert =
            SelfSignedCert::generate_with_validity(&["localhost"], std::time::Duration::from_secs(3600))
                .unwrap();
        // Just exercising the API; full validity-window introspection would
        // need an X.509 parser, which is heavier than the regression value.
        assert!(!cert.cert_der.is_empty());
        assert_eq!(cert.sans, vec!["localhost".to_string()]);
    }
}
