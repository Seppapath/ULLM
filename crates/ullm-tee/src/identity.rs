// SPDX-License-Identifier: Apache-2.0
//! Long-lived TEE identity + medium-term pre-keys.

use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use ullm_attest::MockIssuer;
use ullm_crypto::{
    ml_kem_keypair, ml_kem_pk_bytes, MlKemPublicKey, MlKemSecretKey, X25519PublicKey,
    X25519SecretKey,
};
use ullm_handshake::{PreKeyBundle, SIG_DOMAIN_BUNDLE};

/// Holds every secret a TEE needs to publish a pre-key bundle and respond to
/// a handshake. In real deployment these would live in TEE-sealed storage.
pub struct TeeIdentity {
    pub id_sk: SigningKey,
    pub spk_sk_x25519: X25519SecretKey,
    pub spk_pk_x25519: X25519PublicKey,
    pub pq_sk_mlkem: MlKemSecretKey,
    pub pq_pk_mlkem: MlKemPublicKey,
    pub attest_issuer: MockIssuer,
    /// Phase 3: 32-byte commitment to the verifiable model's weights. Bound
    /// into the attestation `report_data` so a client that verifies the
    /// bundle's attestation also verifies the TEE is running the expected
    /// model.
    pub weight_commit: [u8; 32],
}

impl TeeIdentity {
    pub fn random<R: CryptoRngCore>(rng: &mut R, weight_commit: [u8; 32]) -> Self {
        let id_sk = SigningKey::generate(rng);
        let spk_sk = X25519SecretKey::random_from_rng(&mut *rng);
        let spk_pk = X25519PublicKey::from(&spk_sk);
        let (pq_sk, pq_pk) = ml_kem_keypair(rng);
        let attest_issuer = MockIssuer::random(rng);
        Self {
            id_sk,
            spk_sk_x25519: spk_sk,
            spk_pk_x25519: spk_pk,
            pq_sk_mlkem: pq_sk,
            pq_pk_mlkem: pq_pk,
            attest_issuer,
            weight_commit,
        }
    }

    pub fn id_pk(&self) -> VerifyingKey {
        self.id_sk.verifying_key()
    }

    /// Construct a fresh pre-key bundle for a given attestation_nonce.
    ///
    /// The bundle:
    /// - signs `(id_pk || spk_pk || pq_pk)` with the Ed25519 identity
    /// - embeds attestation evidence binding `report_data_for_bundle` (a fixed
    ///   pre-handshake binding) into the mock attestation
    pub fn build_bundle(&self, attestation_nonce: &[u8; 32], now_unix: u64) -> PreKeyBundle {
        let pq_pk_bytes = ml_kem_pk_bytes(&self.pq_pk_mlkem);
        let id_pk_bytes = *self.id_pk().as_bytes();
        let spk_pk_bytes = *self.spk_pk_x25519.as_bytes();

        // Bundle binding payload — fits inside the 64-byte report_data field
        // by hashing identity || pre-keys || nonce || weight_commit. Cross-
        // binding the weight commitment means a client that verifies the
        // attestation also pins which model the TEE is running.
        let report_data = bundle_report_data(
            &id_pk_bytes,
            &spk_pk_bytes,
            &pq_pk_bytes,
            attestation_nonce,
            &self.weight_commit,
        );
        let evidence = self.attest_issuer.issue(&report_data, now_unix);
        let evidence_bytes = ullm_attest::evidence::encode_evidence(&evidence)
            .expect("postcard encode is infallible for valid Evidence");

        // P4-1: prepend a domain-separation tag so this signature can never
        // be transferred to satisfy a handshake-signature verification (or
        // any other future Ed25519 signature site on the same key). The
        // verifier in `ullm-client::attest_check::verify_bundle` prepends
        // the same constant; mismatch → verify fails.
        let mut to_sign = Vec::with_capacity(
            SIG_DOMAIN_BUNDLE.len()
                + id_pk_bytes.len()
                + spk_pk_bytes.len()
                + pq_pk_bytes.len()
                + evidence_bytes.len(),
        );
        to_sign.extend_from_slice(SIG_DOMAIN_BUNDLE);
        to_sign.extend_from_slice(&id_pk_bytes);
        to_sign.extend_from_slice(&spk_pk_bytes);
        to_sign.extend_from_slice(&pq_pk_bytes);
        to_sign.extend_from_slice(&evidence_bytes);
        let sig: Signature = self.id_sk.sign(&to_sign);

        PreKeyBundle {
            id_pk: id_pk_bytes,
            spk_pk_x25519: spk_pk_bytes,
            pq_pk_mlkem: pq_pk_bytes,
            attestation_evidence: evidence_bytes,
            signature: sig.to_bytes(),
        }
    }
}

pub fn bundle_report_data(
    id_pk: &[u8; 32],
    spk_pk: &[u8; 32],
    pq_pk: &[u8],
    nonce: &[u8; 32],
    weight_commit: &[u8; 32],
) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"ULLM-v1 bundle-attest");
    h.update(id_pk);
    h.update(spk_pk);
    h.update(pq_pk);
    h.update(nonce);
    h.update(weight_commit);
    h.finalize().into()
}
