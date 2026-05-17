// SPDX-License-Identifier: Apache-2.0
//! HKDF-SHA-256 wrappers with strict domain separation.
//!
//! Phase 1 uses SHA-256: 32-byte PRK matches the 32-byte chain keys and AEAD
//! keys, avoiding length mismatches. The protocol spec mentions SHA-384 as
//! aspirational; Phase 2 may upgrade once the ratchet keys are widened.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kex::HybridSecret;

pub const INFO_RECORD_C2S: &[u8] = b"ULLM-v1 record c2s";
pub const INFO_RECORD_S2C: &[u8] = b"ULLM-v1 record s2c";
pub const INFO_NONCE_SALT: &[u8] = b"ULLM-v1 nonce salt";
pub const INFO_CHAIN: &[u8] = b"ULLM-v1 chain";
pub const INFO_MSG: &[u8] = b"ULLM-v1 msg";
pub const INFO_TURN_RATCHET: &[u8] = b"ULLM-v1 turn ratchet";

/// 32-byte root key fed into the per-direction chain keys and the per-turn ratchet.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

/// `HKDF-Extract(salt, ikm)` returning the 32-byte SHA-256 PRK.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

/// `HKDF-Expand(prk, info, len)`.
///
/// Returns a `Zeroizing<Vec<u8>>` so the derived key material is wiped on
/// drop (P3-8). The previous return type was a plain `Vec<u8>` and every
/// caller had to remember to copy-into-array + drop-quick to avoid heap
/// residue — making zeroization the *type*'s job removes the foot-gun.
pub fn expand(prk: &[u8; 32], info: &[u8], len: usize) -> zeroize::Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte prk is valid for SHA-256");
    let mut out = zeroize::Zeroizing::new(vec![0u8; len]);
    hk.expand(info, &mut out).expect("len <= 255*HashLen");
    out
}

/// Derive the root key from the handshake transcript hash and the hybrid shared secret.
pub fn derive_root(transcript_hash: &[u8], hybrid: &HybridSecret) -> RootKey {
    let prk = extract(transcript_hash, &hybrid.0);
    RootKey(prk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_expand_is_deterministic() {
        let prk_a = extract(b"salt", b"ikm");
        let prk_b = extract(b"salt", b"ikm");
        assert_eq!(prk_a, prk_b);

        let out_a = expand(&prk_a, b"info", 64);
        let out_b = expand(&prk_b, b"info", 64);
        assert_eq!(out_a, out_b);
        assert_eq!(out_a.len(), 64);

        let out_diff = expand(&prk_a, b"different", 64);
        assert_ne!(out_a, out_diff);
    }
}
