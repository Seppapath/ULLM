// SPDX-License-Identifier: Apache-2.0
//! Honest-but-curious 2PC over the synthetic model.
//!
//! Two parties each hold one *additive share* of a secret `Fp` value:
//! `s = s_0 + s_1 (mod p)`. Because model weights `W` and bias `b` are
//! public (committed via attestation), the entire forward pass `y = W·x + b`
//! is **linear in the secrets** and can be evaluated non-interactively:
//!
//! - Party 0 computes `y_0 = W·x_0 + b`
//! - Party 1 computes `y_1 = W·x_1`         (only one party adds the bias)
//!
//! and `y = y_0 + y_1`. Neither party alone learns `x` or any intermediate.
//!
//! This is the same shape as real-world 2PC for transformer-block linear
//! projections; nonlinearities (softmax/GELU) would add a Beaver-triple
//! preprocessing phase, which is out of scope for Phase 4's scaffolding.
//!
//! Trust model: non-colluding parties. If both parties collude and exchange
//! shares, they trivially reconstruct `x` — which is precisely the
//! assumption every 2PC system makes.

pub mod share;
pub mod party;
pub mod transcript;

pub use party::{Party, PartyId};
pub use share::{reconstruct_vector, share_value, share_vector, Share, VectorShare};
pub use transcript::{ClientTranscript, MpcResponse, MpcSession};
