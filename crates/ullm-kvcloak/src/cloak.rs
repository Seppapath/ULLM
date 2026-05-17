// SPDX-License-Identifier: Apache-2.0
//! Cloak/uncloak: linear keystream XOR followed by a per-block permutation.

use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of one KV-cache row in this synthetic model. Real models use
/// `head_dim * 2 * num_heads` bytes per token; this is a fixed power-of-two
/// for clean tests + fuzzing.
pub const CLOAK_BLOCK_LEN: usize = 256;

/// Per-session secret key for KV cloaking. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CloakKey {
    transform_key: [u8; 32],
    permute_seed: [u8; 32],
    /// 16-byte session nonce: keeps two sessions with the same `(position,
    /// keys)` from producing identical cloaked outputs.
    session_nonce: [u8; 16],
}

impl CloakKey {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut k = Self {
            transform_key: [0; 32],
            permute_seed: [0; 32],
            session_nonce: [0; 16],
        };
        rng.fill_bytes(&mut k.transform_key);
        rng.fill_bytes(&mut k.permute_seed);
        rng.fill_bytes(&mut k.session_nonce);
        k
    }

    pub fn from_parts(transform_key: [u8; 32], permute_seed: [u8; 32], session_nonce: [u8; 16]) -> Self {
        Self {
            transform_key,
            permute_seed,
            session_nonce,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloakedKvBlock(pub [u8; CLOAK_BLOCK_LEN]);

/// Apply the linear transform then the permutation.
pub fn cloak(key: &CloakKey, position: u64, kv: &[u8; CLOAK_BLOCK_LEN]) -> CloakedKvBlock {
    // 1) keystream XOR
    let mut buf = *kv;
    apply_keystream(&key.transform_key, &key.session_nonce, position, &mut buf);
    // 2) permutation
    let perm = derive_permutation(&key.permute_seed, &key.session_nonce, position);
    let mut out = [0u8; CLOAK_BLOCK_LEN];
    for (dst, &src) in out.iter_mut().zip(perm.iter()) {
        *dst = buf[src as usize];
    }
    CloakedKvBlock(out)
}

/// Reverse of `cloak`: invert the permutation, then re-XOR the keystream.
pub fn uncloak(
    key: &CloakKey,
    position: u64,
    cloaked: &CloakedKvBlock,
) -> [u8; CLOAK_BLOCK_LEN] {
    let perm = derive_permutation(&key.permute_seed, &key.session_nonce, position);
    let mut buf = [0u8; CLOAK_BLOCK_LEN];
    for (i, &p) in perm.iter().enumerate() {
        buf[p as usize] = cloaked.0[i];
    }
    apply_keystream(&key.transform_key, &key.session_nonce, position, &mut buf);
    buf
}

fn apply_keystream(key: &[u8; 32], session_nonce: &[u8; 16], position: u64, buf: &mut [u8]) {
    // We don't use ChaCha20Poly1305's AEAD here — we just want the raw
    // keystream as an invertible XOR. Use a fresh HKDF expansion per
    // (key, session_nonce, position) to materialize CLOAK_BLOCK_LEN bytes.
    let hk = Hkdf::<Sha256>::new(Some(session_nonce), key);
    let mut info = Vec::with_capacity(b"ULLM-v1 kv-keystream".len() + 8);
    info.extend_from_slice(b"ULLM-v1 kv-keystream");
    info.extend_from_slice(&position.to_be_bytes());
    let mut ks = [0u8; CLOAK_BLOCK_LEN];
    hk.expand(&info, &mut ks).expect("len <= 255*HashLen");
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
}

fn derive_permutation(seed: &[u8; 32], session_nonce: &[u8; 16], position: u64) -> [u8; CLOAK_BLOCK_LEN] {
    // Fisher–Yates with HKDF-Sha256-derived index stream.
    let hk = Hkdf::<Sha256>::new(Some(session_nonce), seed);
    let mut info = Vec::with_capacity(b"ULLM-v1 kv-permute".len() + 8);
    info.extend_from_slice(b"ULLM-v1 kv-permute");
    info.extend_from_slice(&position.to_be_bytes());
    // 4 bytes per swap index, CLOAK_BLOCK_LEN-1 swaps.
    let bytes_needed = (CLOAK_BLOCK_LEN - 1) * 4;
    let mut rand_bytes = vec![0u8; bytes_needed];
    hk.expand(&info, &mut rand_bytes).expect("bytes_needed <= 255*HashLen");

    let mut out = [0u8; CLOAK_BLOCK_LEN];
    for i in 0..CLOAK_BLOCK_LEN {
        out[i] = i as u8;
    }
    for i in (1..CLOAK_BLOCK_LEN).rev() {
        let off = (i - 1) * 4;
        let r = u32::from_be_bytes([
            rand_bytes[off],
            rand_bytes[off + 1],
            rand_bytes[off + 2],
            rand_bytes[off + 3],
        ]);
        let j = (r as usize) % (i + 1);
        out.swap(i, j);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn cloak_uncloak_is_identity() {
        let key = CloakKey::random(&mut OsRng);
        let mut kv = [0u8; CLOAK_BLOCK_LEN];
        for i in 0..CLOAK_BLOCK_LEN {
            kv[i] = (i ^ 0x55) as u8;
        }
        let c = cloak(&key, 7, &kv);
        let back = uncloak(&key, 7, &c);
        assert_eq!(kv, back);
    }

    #[test]
    fn different_positions_produce_different_cloaks() {
        let key = CloakKey::random(&mut OsRng);
        let kv = [0xAA; CLOAK_BLOCK_LEN];
        let c0 = cloak(&key, 0, &kv);
        let c1 = cloak(&key, 1, &kv);
        assert_ne!(c0.0, c1.0);
    }

    #[test]
    fn different_keys_produce_different_cloaks() {
        let k1 = CloakKey::random(&mut OsRng);
        let k2 = CloakKey::random(&mut OsRng);
        let kv = [0xAA; CLOAK_BLOCK_LEN];
        let c1 = cloak(&k1, 0, &kv);
        let c2 = cloak(&k2, 0, &kv);
        assert_ne!(c1.0, c2.0);
    }

    #[test]
    fn wrong_key_does_not_uncloak() {
        let k1 = CloakKey::random(&mut OsRng);
        let k2 = CloakKey::random(&mut OsRng);
        let kv = [0xAA; CLOAK_BLOCK_LEN];
        let c = cloak(&k1, 0, &kv);
        let back = uncloak(&k2, 0, &c);
        assert_ne!(back, kv);
    }

    #[test]
    fn permutation_is_valid_bijection() {
        let key = CloakKey::random(&mut OsRng);
        let perm = derive_permutation(&key.permute_seed, &key.session_nonce, 42);
        let mut seen = [false; CLOAK_BLOCK_LEN];
        for &p in &perm {
            assert!(!seen[p as usize], "duplicate in permutation");
            seen[p as usize] = true;
        }
        assert!(seen.iter().all(|&b| b));
    }
}
