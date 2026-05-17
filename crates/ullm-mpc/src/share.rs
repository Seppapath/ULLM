// SPDX-License-Identifier: Apache-2.0
//! Additive secret shares over `Fp`.

use ff::Field;
use rand_core::CryptoRngCore;
use ullm_model::VEC_DIM;
use ullm_zk::Fp;

/// Additive share of a single field element. `s_0 + s_1 = s (mod p)`.
///
/// `Fp` does not implement `Zeroize` (Pasta keeps internals private), so
/// callers that need wipe-on-drop should serialize to bytes via
/// `ullm_zk::fp_to_bytes` and zeroize the byte buffer themselves.
#[derive(Clone)]
pub struct Share(pub Fp);

impl Share {
    pub fn zero() -> Self {
        Self(Fp::zero())
    }
}

/// Component-wise share of a `VEC_DIM`-element vector.
#[derive(Clone)]
pub struct VectorShare(pub [Fp; VEC_DIM]);

/// Split `value` into two uniformly random additive shares.
pub fn share_value<R: CryptoRngCore>(value: Fp, rng: &mut R) -> (Share, Share) {
    let s0 = Fp::random(&mut *rng);
    let s1 = value - s0;
    (Share(s0), Share(s1))
}

/// Split a vector component-wise.
pub fn share_vector<R: CryptoRngCore>(v: &[Fp; VEC_DIM], rng: &mut R) -> (VectorShare, VectorShare) {
    let mut s0 = [Fp::zero(); VEC_DIM];
    let mut s1 = [Fp::zero(); VEC_DIM];
    for i in 0..VEC_DIM {
        let (a, b) = share_value(v[i], rng);
        s0[i] = a.0;
        s1[i] = b.0;
    }
    (VectorShare(s0), VectorShare(s1))
}

/// Reconstruct a single secret from its two shares.
pub fn reconstruct(s0: &Share, s1: &Share) -> Fp {
    s0.0 + s1.0
}

/// Reconstruct a vector from two component shares.
pub fn reconstruct_vector(s0: &VectorShare, s1: &VectorShare) -> [Fp; VEC_DIM] {
    let mut out = [Fp::zero(); VEC_DIM];
    for i in 0..VEC_DIM {
        out[i] = s0.0[i] + s1.0[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn share_then_reconstruct() {
        let mut rng = OsRng;
        let v = Fp::from(42u64);
        let (a, b) = share_value(v, &mut rng);
        assert_eq!(reconstruct(&a, &b), v);
    }

    #[test]
    fn vector_share_then_reconstruct() {
        let mut rng = OsRng;
        let v: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i + 1) as u64));
        let (a, b) = share_vector(&v, &mut rng);
        assert_eq!(reconstruct_vector(&a, &b), v);
    }

    #[test]
    fn lone_share_leaks_nothing() {
        // A single share is uniformly distributed in Fp — equivalent to a
        // one-time pad. We can only assert it differs from the secret for a
        // *specific* random seed.
        let mut rng = OsRng;
        let v = Fp::from(42u64);
        let (a, _) = share_value(v, &mut rng);
        // With overwhelming probability, the random share isn't equal to the
        // secret value.
        assert_ne!(a.0, v);
    }
}
