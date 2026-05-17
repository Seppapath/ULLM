// SPDX-License-Identifier: Apache-2.0
//! Client-side MPC session driver.
//!
//! `MpcSession::run` is non-interactive once shares are distributed:
//! - Client splits `input` into shares.
//! - Each party emits per-layer output shares (locally, in parallel).
//! - Client reconstructs the output by summing component shares.
//!
//! This implementation is in-process — real deployment would have each party
//! be a separate operator-run server with its own TLS channel to the client.

use rand_core::CryptoRngCore;
use ullm_model::{Model, NUM_LAYERS, VEC_DIM};
use ullm_zk::Fp;

use crate::party::{Party, PartyId};
use crate::share::{reconstruct_vector, share_vector, VectorShare};

pub struct MpcSession<'a> {
    pub model: &'a Model,
}

pub struct ClientTranscript {
    pub input: [Fp; VEC_DIM],
    pub output: [Fp; VEC_DIM],
    pub per_layer_outputs: Vec<[Fp; VEC_DIM]>,
}

pub struct MpcResponse {
    pub party0_shares: Vec<VectorShare>,
    pub party1_shares: Vec<VectorShare>,
}

impl<'a> MpcSession<'a> {
    pub fn new(model: &'a Model) -> Self {
        Self { model }
    }

    /// End-to-end honest-but-curious 2PC over the model.
    pub fn run<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        input: [Fp; VEC_DIM],
    ) -> (ClientTranscript, MpcResponse) {
        let (s0, s1) = share_vector(&input, rng);
        let p0 = Party::new(PartyId::Zero, self.model);
        let p1 = Party::new(PartyId::One, self.model);
        let shares0 = p0.run_share(&s0);
        let shares1 = p1.run_share(&s1);

        let mut per_layer = Vec::with_capacity(NUM_LAYERS + 1);
        for i in 0..=NUM_LAYERS {
            per_layer.push(reconstruct_vector(&shares0[i], &shares1[i]));
        }
        let output = per_layer.last().copied().expect("non-empty");

        let transcript = ClientTranscript {
            input,
            output,
            per_layer_outputs: per_layer,
        };
        let response = MpcResponse {
            party0_shares: shares0,
            party1_shares: shares1,
        };
        (transcript, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn mpc_matches_plaintext_inference() {
        let model = Model::from_seed(&[0u8; 32]);
        let mut rng = OsRng;
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i + 1) as u64 * 5));
        let plain = model.run(x);
        let (transcript, _) = MpcSession::new(&model).run(&mut rng, x);
        assert_eq!(transcript.output, *plain.output());
        for i in 0..=NUM_LAYERS {
            assert_eq!(transcript.per_layer_outputs[i], plain.activations[i]);
        }
    }
}
