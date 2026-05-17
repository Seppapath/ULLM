// SPDX-License-Identifier: Apache-2.0
//! Per-party MPC compute. Each party holds one share of the inputs and
//! produces one share of the outputs; the bias `b` is added by exactly one
//! party so the shares sum to `W·x + b`.

use ullm_model::{Model, NUM_LAYERS, VEC_DIM};
use ullm_zk::Fp;

use crate::share::VectorShare;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartyId {
    Zero,
    One,
}

impl PartyId {
    /// Exactly one party owns the bias contribution per layer.
    pub fn owns_bias(self) -> bool {
        matches!(self, PartyId::Zero)
    }
}

/// One MPC party. Holds its own input share, the public model, and emits
/// activation shares for each layer.
pub struct Party<'a> {
    pub id: PartyId,
    pub model: &'a Model,
}

impl<'a> Party<'a> {
    pub fn new(id: PartyId, model: &'a Model) -> Self {
        Self { id, model }
    }

    /// Run the model on a share of the input; return per-layer shares of
    /// each activation (length = NUM_LAYERS + 1, including the input share).
    pub fn run_share(&self, input_share: &VectorShare) -> Vec<VectorShare> {
        let mut activations: Vec<VectorShare> = Vec::with_capacity(NUM_LAYERS + 1);
        activations.push(input_share.clone());
        let mut cur = input_share.clone();

        for layer in &self.model.layers {
            let mut next = [Fp::zero(); VEC_DIM];
            for i in 0..VEC_DIM {
                let mut acc = if self.id.owns_bias() {
                    layer.b[i]
                } else {
                    Fp::zero()
                };
                for j in 0..VEC_DIM {
                    acc += layer.w[i][j] * cur.0[j];
                }
                next[i] = acc;
            }
            cur = VectorShare(next);
            activations.push(cur.clone());
        }
        activations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{reconstruct_vector, share_vector};
    use rand::rngs::OsRng;
    use ullm_model::Model;

    #[test]
    fn two_party_eval_matches_plaintext() {
        let mut rng = OsRng;
        let model = Model::from_seed(&[7u8; 32]);
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i + 1) as u64 * 3));
        let plaintext = model.run(x);

        let (x0, x1) = share_vector(&x, &mut rng);
        let p0 = Party::new(PartyId::Zero, &model);
        let p1 = Party::new(PartyId::One, &model);
        let a0 = p0.run_share(&x0);
        let a1 = p1.run_share(&x1);

        for layer_idx in 0..=NUM_LAYERS {
            let reconstructed = reconstruct_vector(&a0[layer_idx], &a1[layer_idx]);
            assert_eq!(
                reconstructed, plaintext.activations[layer_idx],
                "layer {layer_idx} share reconstruction mismatch"
            );
        }
    }

    #[test]
    fn bias_owned_by_exactly_one_party() {
        // Sanity: if both owned the bias the sum would double-count it.
        assert!(PartyId::Zero.owns_bias() ^ PartyId::One.owns_bias());
    }
}
