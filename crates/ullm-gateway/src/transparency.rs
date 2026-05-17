// SPDX-License-Identifier: Apache-2.0
//! Thin re-exports of [`ullm_transparency`] for callers that still address
//! the gateway as the transparency-log owner.
//!
//! The transparency log itself — signed tree heads, inclusion proofs, and
//! witness cosignatures — lives in the standalone `ullm-transparency`
//! crate. The gateway hosts an instance and serves it over HTTP via the
//! routes in `proxy.rs`.

pub use ullm_transparency::{
    InclusionProof, LogEntry, LogStatus, SignedTreeHead, TransparencyLog, TreeHead,
    WitnessCosignature, WitnessKeyset,
};
