// SPDX-License-Identifier: Apache-2.0
//! Reproducible-build admission control.
//!
//! Every provider declares a manifest with the SHA-256 of its reproducible
//! image. The verifier checks attestation evidence's CPU quote carries this
//! exact hash (in our schema, the first 32 bytes of `Evidence::cpu_quote`
//! when wrapped by a `ReproducibleBuildVerifier`).

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use ullm_attest::{Evidence, VerificationContext, Verifier};
use ullm_core::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BuildHash(pub [u8; 32]);

impl BuildHash {
    pub fn of(image_bytes: &[u8]) -> Self {
        Self(Sha256::digest(image_bytes).into())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderManifest {
    pub provider_id: String,
    pub build_hash: BuildHash,
    pub region: String,
}

/// Wraps an underlying `Verifier`, additionally requiring the evidence's
/// `cert_chain[0]` (used as a build-hash carrier in this minimal scheme)
/// to be in the allowlist.
pub struct ReproducibleBuildVerifier<V: Verifier> {
    pub inner: V,
    pub allowed_builds: HashSet<BuildHash>,
}

impl<V: Verifier> ReproducibleBuildVerifier<V> {
    pub fn new(inner: V, allowed: impl IntoIterator<Item = BuildHash>) -> Self {
        Self {
            inner,
            allowed_builds: allowed.into_iter().collect(),
        }
    }
}

impl<V: Verifier> Verifier for ReproducibleBuildVerifier<V> {
    fn verify(&self, evidence: &Evidence, ctx: &VerificationContext<'_>) -> Result<()> {
        self.inner.verify(evidence, ctx)?;
        let carrier = evidence
            .cert_chain
            .last()
            .ok_or_else(|| Error::AttestationFailed("missing build-hash carrier".into()))?;
        if carrier.len() != 32 {
            return Err(Error::AttestationFailed(
                "build-hash carrier must be 32 bytes".into(),
            ));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(carrier);
        if !self.allowed_builds.contains(&BuildHash(h)) {
            return Err(Error::AttestationFailed(format!(
                "build hash {} not in admission allowlist",
                hex::encode(h)
            )));
        }
        Ok(())
    }

    /// Delegate identity to the wrapped verifier — the build-hash carrier is
    /// admission-control metadata, not an attestation-key identity, so the
    /// underlying TEE verifier is what defines the federation slot.
    fn attestation_identity(&self, evidence: &Evidence) -> Option<[u8; 32]> {
        self.inner.attestation_identity(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ullm_attest::{MockIssuer, MockVerifier};

    fn ctx<'a>(expected: &'a [u8; 64], now: u64) -> VerificationContext<'a> {
        VerificationContext {
            expected_report_data: expected,
            now_unix: now,
            max_age_sec: 60,
        }
    }

    #[test]
    fn accepts_admitted_build_hash() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let rd = [3u8; 64];
        let mut evidence = issuer.issue(&rd, 100);
        let hash = BuildHash::of(b"image-v1");
        evidence.cert_chain.push(hash.0.to_vec());
        let v = ReproducibleBuildVerifier::new(MockVerifier::new(issuer.verifying_key()), [hash]);
        v.verify(&evidence, &ctx(&rd, 100)).unwrap();
    }

    #[test]
    fn rejects_unadmitted_build_hash() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let rd = [3u8; 64];
        let mut evidence = issuer.issue(&rd, 100);
        evidence.cert_chain.push(BuildHash::of(b"image-foreign").0.to_vec());
        let v = ReproducibleBuildVerifier::new(
            MockVerifier::new(issuer.verifying_key()),
            [BuildHash::of(b"image-v1")],
        );
        assert!(v.verify(&evidence, &ctx(&rd, 100)).is_err());
    }

    #[test]
    fn rejects_when_inner_fails() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let evidence = issuer.issue(&[0u8; 64], 100);
        let v = ReproducibleBuildVerifier::new(
            MockVerifier::new(issuer.verifying_key()),
            [BuildHash::of(b"image-v1")],
        );
        assert!(v.verify(&evidence, &ctx(&[1u8; 64], 100)).is_err());
    }
}
