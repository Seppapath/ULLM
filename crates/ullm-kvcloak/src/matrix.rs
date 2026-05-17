// SPDX-License-Identifier: Apache-2.0
//! KV-Cloak in matrix form, per the NDSS 2026 description.
//!
//! Real models compute attention over `Fp`-valued (after quantization)
//! key/value vectors. KV-Cloak replaces each cached `(k, v)` with
//! `(P·L·k, P·L·v)` where:
//!
//! - `L` is a secret invertible lower-triangular matrix
//!   (guaranteed invertible by non-zero diagonals; cheap to invert).
//! - `P` is a secret random permutation matrix (orthogonal, `P^-1 = P^T`).
//!
//! Under HBM exposure, an adversary sees only `P·L·k`. Without `L` and `P`
//! the original `k`, `v` are recoverable only by inverting an unknown
//! invertible matrix — infeasible.
//!
//! The fully-fused attention operator from the paper (precomposing `S^-1·P^T`
//! into the per-head projection weights) is not implemented here; what is
//! shipped is the per-vector cloak transform plus its inverse, suitable
//! for the Petridish SPD process model in `spd.rs` and for plugging behind
//! a real attention kernel when one lands.

use ff::Field;
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use ullm_zk::Fp;

/// Per-vector dimension. Matches the Phase 3 model.
pub const VEC_DIM: usize = 8;

/// Secret invertible lower-triangular matrix `L` plus permutation `P`.
pub struct MatrixCloakKey {
    /// L stored as a flat row-major 64-element vector; non-zero diagonal.
    pub l: [[Fp; VEC_DIM]; VEC_DIM],
    /// Permutation: `perm[i] = j` means the i-th output coordinate comes
    /// from the j-th post-`L` position.
    pub perm: [usize; VEC_DIM],
}

impl MatrixCloakKey {
    /// Derive a key from a 32-byte seed (e.g. per-tenant cloak seed).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"ULLM-kvcloak-matrix-v1"), seed);
        // Pull deterministic bytes for L (64 elements × 64-byte reduction)
        // and the permutation seed.
        const PER_ELEM_BYTES: usize = 64;
        let l_bytes_total = VEC_DIM * VEC_DIM * PER_ELEM_BYTES;
        let mut raw = vec![0u8; l_bytes_total + 64];
        hk.expand(b"l-and-perm", &mut raw)
            .expect("HKDF within Sha256 budget");

        let mut l = [[Fp::zero(); VEC_DIM]; VEC_DIM];
        for i in 0..VEC_DIM {
            for j in 0..VEC_DIM {
                if j > i {
                    continue; // lower-triangular: above-diagonal entries are zero
                }
                let off = (i * VEC_DIM + j) * PER_ELEM_BYTES;
                let mut chunk = [0u8; PER_ELEM_BYTES];
                chunk.copy_from_slice(&raw[off..off + PER_ELEM_BYTES]);
                let mut v = fp_from_wide(&chunk);
                if i == j && bool::from(v.is_zero()) {
                    // Force diagonal non-zero so L is invertible.
                    v = Fp::one();
                }
                l[i][j] = v;
            }
        }

        // Derive the permutation from the trailing 64 bytes via Fisher–Yates.
        let perm_seed_off = l_bytes_total;
        let mut perm: [usize; VEC_DIM] = std::array::from_fn(|i| i);
        for i in (1..VEC_DIM).rev() {
            let r = u64::from_be_bytes([
                raw[perm_seed_off + i * 8],
                raw[perm_seed_off + i * 8 + 1],
                raw[perm_seed_off + i * 8 + 2],
                raw[perm_seed_off + i * 8 + 3],
                raw[perm_seed_off + i * 8 + 4],
                raw[perm_seed_off + i * 8 + 5],
                raw[perm_seed_off + i * 8 + 6],
                raw[perm_seed_off + i * 8 + 7],
            ]);
            let j = (r as usize) % (i + 1);
            perm.swap(i, j);
        }
        Self { l, perm }
    }

    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }
}

/// Apply `P · L · v`.
pub fn cloak_vector(key: &MatrixCloakKey, v: &[Fp; VEC_DIM]) -> [Fp; VEC_DIM] {
    let lv = matvec_lower(&key.l, v);
    let mut out = [Fp::zero(); VEC_DIM];
    for (i, &src) in key.perm.iter().enumerate() {
        out[i] = lv[src];
    }
    out
}

/// Recover `v` from `P · L · v`.
pub fn uncloak_vector(key: &MatrixCloakKey, cloaked: &[Fp; VEC_DIM]) -> [Fp; VEC_DIM] {
    // P^T · cloaked: scatter cloaked[i] back into position perm[i].
    let mut lv = [Fp::zero(); VEC_DIM];
    for (i, &src) in key.perm.iter().enumerate() {
        lv[src] = cloaked[i];
    }
    inverse_matvec_lower(&key.l, &lv)
}

fn matvec_lower(l: &[[Fp; VEC_DIM]; VEC_DIM], v: &[Fp; VEC_DIM]) -> [Fp; VEC_DIM] {
    let mut out = [Fp::zero(); VEC_DIM];
    for i in 0..VEC_DIM {
        let mut acc = Fp::zero();
        for j in 0..=i {
            acc += l[i][j] * v[j];
        }
        out[i] = acc;
    }
    out
}

/// Forward-substitute `L · x = b` for lower-triangular `L` with non-zero diag.
fn inverse_matvec_lower(l: &[[Fp; VEC_DIM]; VEC_DIM], b: &[Fp; VEC_DIM]) -> [Fp; VEC_DIM] {
    let mut x = [Fp::zero(); VEC_DIM];
    for i in 0..VEC_DIM {
        let mut acc = b[i];
        for j in 0..i {
            acc -= l[i][j] * x[j];
        }
        let diag_inv = l[i][i].invert().expect("non-zero diagonal");
        x[i] = acc * diag_inv;
    }
    x
}

fn fp_from_wide(bytes: &[u8; 64]) -> Fp {
    use ff::PrimeField;
    use sha2::{Digest, Sha256};
    let arr: [u8; 32] = Sha256::digest(bytes).into();
    let mut clamped = arr;
    clamped[31] &= 0x3F;
    Fp::from_repr_vartime(clamped).expect("clamped < p")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sample_vec(salt: u64) -> [Fp; VEC_DIM] {
        std::array::from_fn(|i| Fp::from((i as u64 + 1) * (salt + 13)))
    }

    #[test]
    fn cloak_uncloak_roundtrip() {
        let key = MatrixCloakKey::random(&mut OsRng);
        let v = sample_vec(0);
        let cloaked = cloak_vector(&key, &v);
        let back = uncloak_vector(&key, &cloaked);
        assert_eq!(back, v);
    }

    #[test]
    fn different_keys_produce_different_cloaks() {
        let k1 = MatrixCloakKey::random(&mut OsRng);
        let k2 = MatrixCloakKey::random(&mut OsRng);
        let v = sample_vec(7);
        assert_ne!(cloak_vector(&k1, &v), cloak_vector(&k2, &v));
    }

    #[test]
    fn wrong_key_does_not_recover_input() {
        let k1 = MatrixCloakKey::random(&mut OsRng);
        let k2 = MatrixCloakKey::random(&mut OsRng);
        let v = sample_vec(3);
        let cloaked = cloak_vector(&k1, &v);
        let bogus = uncloak_vector(&k2, &cloaked);
        assert_ne!(bogus, v);
    }

    #[test]
    fn linearity_preserved_under_cloak() {
        // L is a linear operator and so is P. Therefore the cloak commutes
        // with linear combinations:  cloak(αv + βw) == α·cloak(v) + β·cloak(w).
        let key = MatrixCloakKey::random(&mut OsRng);
        let v = sample_vec(5);
        let w = sample_vec(11);
        let alpha = Fp::from(3u64);
        let beta = Fp::from(7u64);
        let mut combined = [Fp::zero(); VEC_DIM];
        for i in 0..VEC_DIM {
            combined[i] = alpha * v[i] + beta * w[i];
        }
        let c_combined = cloak_vector(&key, &combined);
        let c_v = cloak_vector(&key, &v);
        let c_w = cloak_vector(&key, &w);
        let mut expected = [Fp::zero(); VEC_DIM];
        for i in 0..VEC_DIM {
            expected[i] = alpha * c_v[i] + beta * c_w[i];
        }
        assert_eq!(c_combined, expected);
    }

    #[test]
    fn permutation_is_a_valid_bijection() {
        let key = MatrixCloakKey::random(&mut OsRng);
        let mut seen = [false; VEC_DIM];
        for &p in &key.perm {
            assert!(!seen[p], "duplicate index in permutation");
            seen[p] = true;
        }
        assert!(seen.iter().all(|&b| b));
    }
}
