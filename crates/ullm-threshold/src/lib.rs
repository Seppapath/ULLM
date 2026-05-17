// SPDX-License-Identifier: Apache-2.0
//! FROST-Ed25519 t-of-n threshold signing.
//!
//! Used as a replacement for the single-party `ReceiptSigner`: now N
//! federation operators each hold a share of the signing key, and any `t`
//! of them can cooperate to produce an Ed25519 signature verifiable by the
//! existing receipts verifier. No single operator can forge.
//!
//! Three-round protocol (compressed into one helper because we hold all
//! parties in-process for the demo):
//!
//! 1. **DKG**: trusted-dealer key-share generation
//!    (`distribute_with_trusted_dealer`, gated by `trusted-dealer` feature)
//! 2. **Commit**: each participant emits a one-shot nonce commitment
//!    (`Participant::commit`)
//! 3. **Sign**: each participant produces a signature share given the
//!    aggregated commitments + message (`Participant::sign`)
//! 4. **Aggregate**: combine `t` shares into a single Ed25519 signature
//!    (`Aggregator::finalize`)
//!
//! The resulting signature verifies under `verifying_key()` exactly like an
//! ed25519-dalek signature.

pub mod dkg;
pub mod participant;
pub mod sign;

pub use dkg::KeyShares;
#[cfg(feature = "trusted-dealer")]
#[allow(deprecated)]
pub use dkg::{distribute, distribute_with_trusted_dealer};
pub use participant::Participant;
pub use sign::{aggregate, sign_once};
