// SPDX-License-Identifier: Apache-2.0
use ff::PrimeField;
use halo2_proofs::pasta::Fp;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};

use crate::commit::vector_commit_native;
use crate::trace::Trace;

pub const VEC_DIM: usize = 8;
pub const NUM_LAYERS: usize = 8;

#[derive(Clone, Debug)]
pub struct Layer {
    pub w: [[Fp; VEC_DIM]; VEC_DIM],
    pub b: [Fp; VEC_DIM],
}

#[derive(Clone, Debug)]
pub struct Model {
    pub layers: [Layer; NUM_LAYERS],
    /// 32-byte weight commitment: `SHA-256("ULLM-v1 model" || layer_commit(0) || ... || layer_commit(N-1))`
    /// where each layer commit is `vector_commit_native` over `(w_flat || b)`.
    weight_commit: [u8; 32],
}

impl Model {
    /// Derive the model from a 32-byte seed. Same seed → same model.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"ULLM-v1 model seed"), seed);
        let per_layer_bytes = (VEC_DIM * VEC_DIM + VEC_DIM) * 64;

        let mut layers = Vec::with_capacity(NUM_LAYERS);
        for layer_idx in 0..NUM_LAYERS {
            let mut info = b"weights/".to_vec();
            info.extend_from_slice(&(layer_idx as u32).to_be_bytes());
            let mut raw = vec![0u8; per_layer_bytes];
            hk.expand(&info, &mut raw)
                .expect("per-layer expand within HKDF-Sha256 budget");

            let mut off = 0;
            let mut w = [[Fp::zero(); VEC_DIM]; VEC_DIM];
            for i in 0..VEC_DIM {
                for j in 0..VEC_DIM {
                    let mut bytes = [0u8; 64];
                    bytes.copy_from_slice(&raw[off..off + 64]);
                    off += 64;
                    w[i][j] = fp_from_wide(&bytes);
                }
            }
            let mut b = [Fp::zero(); VEC_DIM];
            for i in 0..VEC_DIM {
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(&raw[off..off + 64]);
                off += 64;
                b[i] = fp_from_wide(&bytes);
            }
            layers.push(Layer { w, b });
        }

        let layers: [Layer; NUM_LAYERS] = layers.try_into().expect("size matches");
        let weight_commit = compute_weight_commit(&layers);
        Self {
            layers,
            weight_commit,
        }
    }

    pub fn weight_commit(&self) -> [u8; 32] {
        self.weight_commit
    }

    /// Run inference: `input → layer_0 → … → layer_{N-1} → output`.
    /// Returns the full activation trace (N+1 vectors).
    pub fn run(&self, input: [Fp; VEC_DIM]) -> Trace {
        let mut activations = Vec::with_capacity(NUM_LAYERS + 1);
        activations.push(input);
        let mut cur = input;
        for layer in &self.layers {
            let mut next = [Fp::zero(); VEC_DIM];
            for i in 0..VEC_DIM {
                let mut acc = layer.b[i];
                for j in 0..VEC_DIM {
                    acc += layer.w[i][j] * cur[j];
                }
                next[i] = acc;
            }
            activations.push(next);
            cur = next;
        }
        Trace { activations }
    }

    /// The per-layer weight commitment that the Halo2 circuit takes as a
    /// public input. `vector_commit_native(W flat || b)`.
    pub fn layer_weight_commit(&self, layer_idx: usize) -> Fp {
        let layer = &self.layers[layer_idx];
        let mut data = Vec::with_capacity(VEC_DIM * VEC_DIM + VEC_DIM);
        for row in &layer.w {
            for v in row {
                data.push(*v);
            }
        }
        for v in &layer.b {
            data.push(*v);
        }
        vector_commit_native(&data)
    }
}

/// Wide-to-Fp reduction. 64 input bytes are SHA-256-hashed to 32 bytes,
/// the top two bits cleared (Pallas has p ≈ 2^254), and the result is read
/// as `Fp`. Bias is ≤ 2^-126 — negligible for a synthetic test model.
fn fp_from_wide(bytes: &[u8; 64]) -> Fp {
    let mut h = Sha256::new();
    h.update(bytes);
    let arr: [u8; 32] = h.finalize().into();
    let mut clamped = arr;
    clamped[31] &= 0x3F;
    Fp::from_repr_vartime(clamped).expect("clamped < p")
}

fn compute_weight_commit(layers: &[Layer; NUM_LAYERS]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"ULLM-v1 model");
    for layer in layers {
        for row in &layer.w {
            for v in row {
                h.update(v.to_repr());
            }
        }
        for v in &layer.b {
            h.update(v.to_repr());
        }
    }
    let wide: [u8; 64] = h.finalize().into();
    let mut out = [0u8; 32];
    out.copy_from_slice(&wide[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let seed = [42u8; 32];
        let m1 = Model::from_seed(&seed);
        let m2 = Model::from_seed(&seed);
        assert_eq!(m1.weight_commit(), m2.weight_commit());
        let input = [Fp::from(1u64); VEC_DIM];
        let t1 = m1.run(input);
        let t2 = m2.run(input);
        for (a, b) in t1.activations.iter().zip(t2.activations.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let m1 = Model::from_seed(&[1u8; 32]);
        let m2 = Model::from_seed(&[2u8; 32]);
        assert_ne!(m1.weight_commit(), m2.weight_commit());
    }

    #[test]
    fn run_produces_correct_number_of_activations() {
        let m = Model::from_seed(&[0u8; 32]);
        let trace = m.run([Fp::from(7u64); VEC_DIM]);
        assert_eq!(trace.activations.len(), NUM_LAYERS + 1);
    }
}
