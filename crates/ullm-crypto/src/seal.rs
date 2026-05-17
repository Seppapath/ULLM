// SPDX-License-Identifier: Apache-2.0
//! TEE-sealed KEK + AES-256-GCM-SIV wrap for at-rest blobs.
//!
//! In production, the KEK is derived from a TEE platform sealing key
//! (SEV-SNP `MSG_KEY_REQ` or TDX SEAM-sealing) so it can only be re-derived
//! by the same measured workload on the same hardware. Here we model the
//! KEK as a 32-byte secret generated at TEE startup; it's rotated on
//! reboot. The cipher is AES-256-GCM-SIV (RFC 8452), which is misuse-
//! resistant against nonce reuse — important because TEE snapshot/restore
//! can re-emit counter values.

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use rand_core::CryptoRngCore;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum SealError {
    #[error("AES-GCM-SIV decryption failed")]
    Open,
    #[error("nonce must be 12 bytes")]
    BadNonce,
}

/// 32-byte sealed key-encryption key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealedKek(pub [u8; 32]);

impl SealedKek {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        Self(k)
    }
}

/// Wrap `plaintext` under `kek`. The 12-byte nonce must be unique per
/// (kek, aad) pair; AES-GCM-SIV is misuse-resistant so a collision degrades
/// only to revealing whether two ciphertexts share plaintext.
pub fn seal(kek: &SealedKek, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new((&kek.0).into());
    let n = Nonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: plaintext, aad })
        .expect("AES-GCM-SIV encrypt is infallible for valid inputs")
}

pub fn unseal(kek: &SealedKek, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256GcmSiv::new((&kek.0).into());
    let n = Nonce::from_slice(nonce);
    cipher
        .decrypt(n, Payload { msg: ciphertext, aad })
        .map_err(|_| SealError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip() {
        let kek = SealedKek::random(&mut OsRng);
        let nonce = [3u8; 12];
        let aad = b"tenant=acme|session=01|pos=42";
        let ct = seal(&kek, &nonce, aad, b"kv cache row");
        let pt = unseal(&kek, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, b"kv cache row");
    }

    #[test]
    fn aad_binding_enforced() {
        let kek = SealedKek::random(&mut OsRng);
        let ct = seal(&kek, &[0u8; 12], b"good aad", b"x");
        assert!(unseal(&kek, &[0u8; 12], b"bad aad", &ct).is_err());
    }

    #[test]
    fn key_isolation() {
        let kek_a = SealedKek::random(&mut OsRng);
        let kek_b = SealedKek::random(&mut OsRng);
        let ct = seal(&kek_a, &[0u8; 12], b"aad", b"data");
        assert!(unseal(&kek_b, &[0u8; 12], b"aad", &ct).is_err());
    }
}
