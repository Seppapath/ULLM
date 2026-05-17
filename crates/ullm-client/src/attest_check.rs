// SPDX-License-Identifier: Apache-2.0
//! Client-side verification of a server pre-key bundle.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ullm_attest::{evidence::decode_evidence, MockVerifier, VerificationContext, Verifier as _};
use ullm_core::{Error, Result};
use ullm_handshake::{PreKeyBundle, SIG_DOMAIN_BUNDLE};

/// Verify (a) the identity signature over the bundle, (b) the attestation
/// evidence binds to the bundle's pre-keys + nonce + expected weight
/// commitment, and (c) freshness.
///
/// `expected_weight_commit` cross-binds the TEE's model: the bundle is
/// rejected if the TEE's attestation `report_data` does not include this
/// exact commitment.
pub fn verify_bundle(
    bundle: &PreKeyBundle,
    expected_nonce: &[u8; 32],
    expected_weight_commit: &[u8; 32],
    trust_root: &VerifyingKey,
    now_unix: u64,
    max_age_sec: u64,
) -> Result<VerifyingKey> {
    let id_pk = VerifyingKey::from_bytes(&bundle.id_pk)
        .map_err(|_| Error::AttestationFailed("invalid id_pk".into()))?;

    // P4-1: prepend `SIG_DOMAIN_BUNDLE` — must match the signer in
    // `ullm-tee::identity::TeeIdentity::build_bundle`. Without the
    // prefix on both sides the verify would silently accept (or reject)
    // depending on which side updated first.
    let mut to_verify = Vec::with_capacity(
        SIG_DOMAIN_BUNDLE.len()
            + bundle.id_pk.len()
            + bundle.spk_pk_x25519.len()
            + bundle.pq_pk_mlkem.len()
            + bundle.attestation_evidence.len(),
    );
    to_verify.extend_from_slice(SIG_DOMAIN_BUNDLE);
    to_verify.extend_from_slice(&bundle.id_pk);
    to_verify.extend_from_slice(&bundle.spk_pk_x25519);
    to_verify.extend_from_slice(&bundle.pq_pk_mlkem);
    to_verify.extend_from_slice(&bundle.attestation_evidence);
    let sig = Signature::from_bytes(&bundle.signature);
    id_pk
        .verify(&to_verify, &sig)
        .map_err(|_| Error::AttestationFailed("bad bundle signature".into()))?;

    let evidence = decode_evidence(&bundle.attestation_evidence)?;
    let expected_report_data = bundle_report_data(
        &bundle.id_pk,
        &bundle.spk_pk_x25519,
        &bundle.pq_pk_mlkem,
        expected_nonce,
        expected_weight_commit,
    );
    let verifier = MockVerifier::new(*trust_root);
    let ctx = VerificationContext {
        expected_report_data: &expected_report_data,
        now_unix,
        max_age_sec,
    };
    verifier.verify(&evidence, &ctx)?;
    Ok(id_pk)
}

/// Mirror of `ullm_tee::identity::bundle_report_data`.
fn bundle_report_data(
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
