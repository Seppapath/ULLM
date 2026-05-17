// SPDX-License-Identifier: Apache-2.0
//! Mock attestation backend.
//!
//! A `MockIssuer` produces evidence by signing `report_data || issued_at` with
//! an Ed25519 key. A `MockVerifier` checks the signature against the trusted
//! public key list. This is **not** a real TEE — it lets the rest of the stack
//! exercise the full handshake-to-verification flow locally.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use ullm_core::{Error, Result};

use crate::evidence::{Evidence, QuoteKind};
use crate::verifier::{VerificationContext, Verifier};

#[derive(Clone)]
pub struct MockIssuer {
    signing: SigningKey,
}

impl MockIssuer {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            signing: SigningKey::generate(rng),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn issue(&self, report_data: &[u8; 64], now_unix: u64) -> Evidence {
        let mut msg = Vec::with_capacity(64 + 8);
        msg.extend_from_slice(report_data);
        msg.extend_from_slice(&now_unix.to_be_bytes());
        let sig: Signature = self.signing.sign(&msg);
        Evidence {
            cpu_quote_kind: QuoteKind::Mock,
            cpu_quote: sig.to_bytes().to_vec(),
            gpu_quote: vec![],
            cert_chain: vec![self.signing.verifying_key().as_bytes().to_vec()],
            report_data: *report_data,
            issued_at_unix: now_unix,
        }
    }
}

pub struct MockVerifier {
    trust_root: VerifyingKey,
}

impl MockVerifier {
    pub fn new(trust_root: VerifyingKey) -> Self {
        Self { trust_root }
    }
}

impl Verifier for MockVerifier {
    fn verify(&self, evidence: &Evidence, ctx: &VerificationContext<'_>) -> Result<()> {
        if evidence.cpu_quote_kind != QuoteKind::Mock {
            return Err(Error::AttestationFailed(
                "expected mock quote kind".into(),
            ));
        }
        // Phase 3 (P3-1): constant-time compare on the slice form of the
        // 64-byte channel-binding payload.
        if !bool::from(
            subtle::ConstantTimeEq::ct_eq(
                evidence.report_data.as_slice(),
                ctx.expected_report_data.as_slice(),
            ),
        ) {
            return Err(Error::AttestationFailed("report_data mismatch".into()));
        }
        if ctx.now_unix.saturating_sub(evidence.issued_at_unix) > ctx.max_age_sec {
            return Err(Error::StaleAttestation {
                ttl_sec: ctx.max_age_sec,
            });
        }
        let cert_pk_bytes: &Vec<u8> = evidence
            .cert_chain
            .first()
            .ok_or_else(|| Error::AttestationFailed("missing cert".into()))?;
        let cert_pk_arr: [u8; 32] = cert_pk_bytes[..]
            .try_into()
            .map_err(|_| Error::AttestationFailed("bad cert length".into()))?;
        if cert_pk_arr != *self.trust_root.as_bytes() {
            return Err(Error::AttestationFailed("untrusted attestation key".into()));
        }
        let sig_bytes: [u8; 64] = evidence.cpu_quote[..]
            .try_into()
            .map_err(|_| Error::AttestationFailed("bad signature length".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&evidence.report_data);
        msg.extend_from_slice(&evidence.issued_at_unix.to_be_bytes());
        self.trust_root
            .verify(&msg, &sig)
            .map_err(|_| Error::AttestationFailed("bad signature".into()))?;
        Ok(())
    }

    /// MockVerifier identity is SHA-256 over the verifier's trust-root
    /// public key bound to the evidence's `report_data`. Acceptable
    /// because MockVerifier is dev-only.
    ///
    /// The trust-root pubkey component is what distinguishes "different
    /// vendors" in dev: each `MockIssuer` has its own Ed25519 key, so
    /// federation slots wired with three distinct issuers (the normal
    /// dev pattern) produce three distinct identities.
    ///
    /// `report_data` is mixed in so an attacker who somehow shares a
    /// trust-root across two slots (misconfiguration) still gets one
    /// identity per session; and so the regression-test attack
    /// (two evidences with same report_data submitted to slots wired
    /// to the SAME mock issuer) collides as it should.
    fn attestation_identity(&self, evidence: &Evidence) -> Option<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(b"ullm/mock-verifier/v1");
        h.update(self.trust_root.as_bytes());
        h.update(evidence.report_data);
        Some(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn ctx<'a>(expected: &'a [u8; 64], now: u64) -> VerificationContext<'a> {
        VerificationContext {
            expected_report_data: expected,
            now_unix: now,
            max_age_sec: 60,
        }
    }

    #[test]
    fn happy_path() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let verifier = MockVerifier::new(issuer.verifying_key());
        let rd = [7u8; 64];
        let ev = issuer.issue(&rd, 100);
        verifier.verify(&ev, &ctx(&rd, 110)).unwrap();
    }

    #[test]
    fn stale_rejected() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let verifier = MockVerifier::new(issuer.verifying_key());
        let rd = [7u8; 64];
        let ev = issuer.issue(&rd, 100);
        assert!(verifier.verify(&ev, &ctx(&rd, 200)).is_err());
    }

    #[test]
    fn wrong_report_data_rejected() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let verifier = MockVerifier::new(issuer.verifying_key());
        let ev = issuer.issue(&[7u8; 64], 100);
        assert!(verifier.verify(&ev, &ctx(&[8u8; 64], 100)).is_err());
    }

    #[test]
    fn wrong_trust_root_rejected() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let other = MockIssuer::random(&mut rng);
        let verifier = MockVerifier::new(other.verifying_key());
        let rd = [7u8; 64];
        let ev = issuer.issue(&rd, 100);
        assert!(verifier.verify(&ev, &ctx(&rd, 100)).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut rng = OsRng;
        let issuer = MockIssuer::random(&mut rng);
        let verifier = MockVerifier::new(issuer.verifying_key());
        let rd = [7u8; 64];
        let mut ev = issuer.issue(&rd, 100);
        ev.cpu_quote[0] ^= 0xFF;
        assert!(verifier.verify(&ev, &ctx(&rd, 100)).is_err());
    }
}
