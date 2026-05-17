// SPDX-License-Identifier: Apache-2.0
use halo2_proofs::pasta::Fp;
use ullm_zk::fp_to_bytes;

use crate::commit::vector_commit_native;
use crate::model::VEC_DIM;

/// Activation trace through the model.
#[derive(Clone, Debug)]
pub struct Trace {
    /// `activations[0]` is the input; `activations[i]` (i > 0) is the output
    /// of layer i-1. Length = NUM_LAYERS + 1.
    pub activations: Vec<[Fp; VEC_DIM]>,
}

impl Trace {
    /// Native commit over each activation. Length = NUM_LAYERS + 1.
    pub fn commits(&self) -> TraceCommits {
        let mut field = Vec::with_capacity(self.activations.len());
        let mut bytes = Vec::with_capacity(self.activations.len());
        for v in &self.activations {
            let c = vector_commit_native(v);
            field.push(c);
            bytes.push(fp_to_bytes(c));
        }
        TraceCommits { field, bytes }
    }

    pub fn input(&self) -> &[Fp; VEC_DIM] {
        &self.activations[0]
    }

    pub fn output(&self) -> &[Fp; VEC_DIM] {
        self.activations.last().expect("non-empty trace")
    }
}

#[derive(Clone, Debug)]
pub struct TraceCommits {
    pub field: Vec<Fp>,
    pub bytes: Vec<[u8; 32]>,
}
