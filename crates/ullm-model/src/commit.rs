// SPDX-License-Identifier: Apache-2.0
//! Poseidon commitment over a fixed-length vector of `Fp` elements.
//!
//! Uses `ConstantLength<VEC_DIM>` so the native commit matches the
//! halo2_gadgets in-circuit hash byte-for-byte.

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonPrimitive, P128Pow5T3};
use halo2_proofs::pasta::Fp;
use ullm_zk::fp_to_bytes;

use crate::model::VEC_DIM;

/// Tree-depth concept retained for compatibility; with `ConstantLength<8>`
/// there is no Merkle structure — the hash is a single Poseidon absorption.
pub const MERKLE_DEPTH: usize = 0;

/// Native `ConstantLength<VEC_DIM>` Poseidon hash. Matches the in-circuit
/// `vector_hash_native` from `ullm-zk::layer`.
pub fn vector_commit_native(data: &[Fp]) -> Fp {
    assert_eq!(data.len(), VEC_DIM, "vector must be VEC_DIM elements");
    let mut arr = [Fp::zero(); VEC_DIM];
    arr.copy_from_slice(data);
    PoseidonPrimitive::<Fp, P128Pow5T3, ConstantLength<VEC_DIM>, 3, 2>::init().hash(arr)
}

pub fn vector_commit(data: &[Fp]) -> [u8; 32] {
    fp_to_bytes(vector_commit_native(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_are_deterministic() {
        let v: Vec<Fp> = (0..VEC_DIM).map(|i| Fp::from(i as u64)).collect();
        let a = vector_commit_native(&v);
        let b = vector_commit_native(&v);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_produce_different_commits() {
        let v1: Vec<Fp> = (0..VEC_DIM).map(|i| Fp::from(i as u64)).collect();
        let mut v2 = v1.clone();
        v2[3] = Fp::from(999u64);
        assert_ne!(vector_commit_native(&v1), vector_commit_native(&v2));
    }

    #[test]
    fn matches_zk_layer_native_hash() {
        let arr: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from(i as u64 + 1));
        let a = vector_commit_native(&arr);
        let b = ullm_zk::layer::vector_hash_native(&arr);
        assert_eq!(a, b);
    }
}
