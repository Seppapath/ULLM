// SPDX-License-Identifier: Apache-2.0
//! Synthetic deterministic model + activation commitments.
//!
//! This module stands in for real attention layers. Phase 3's cryptographic
//! contract is what's real: a deterministic computation `output =
//! Model::run(input)`, a weight commitment derivable from a seed, and a
//! Merkle-Poseidon commitment over each activation vector. A `Watcher` can
//! reproduce the trace deterministically from `input` + `seed` and detect
//! any tampering.
//!
//! Field: Pallas `Fp` (consistent with `ullm-zk`'s Halo2 setup).
//!
//! Shape:
//!   - `VEC_DIM = 8` elements per activation vector
//!   - `NUM_LAYERS = 8` layers
//!   - Each layer applies `y_i = sum_j W_ij * x_j + b_i` (mod p)
//!
//! Weights are HKDF-derived from a 32-byte master seed so two parties with
//! the same seed produce the same model.

pub mod commit;
pub mod model;
pub mod trace;

pub use commit::{vector_commit, vector_commit_native};
pub use model::{Layer, Model, NUM_LAYERS, VEC_DIM};
pub use trace::{Trace, TraceCommits};
