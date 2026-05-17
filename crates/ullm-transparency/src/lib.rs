// SPDX-License-Identifier: Apache-2.0
//! Append-only Sigsum-style transparency log.
//!
//! A `TransparencyLog` owns:
//!
//! - **Append-only leaves** persisted to a JSONL file on every append, so
//!   restarts preserve the full history.
//! - **A SHA-256 Merkle tree** computed over the leaves, with inclusion
//!   proofs for any seq.
//! - **A Signed Tree Head (STH)** — `(size, root, timestamp)` signed by the
//!   logger's Ed25519 key.
//! - **Witness cosignatures** — third parties can co-sign the latest STH;
//!   the auditor binary checks that ≥ t witnesses have endorsed the head.
//!
//! All data is reproducible: given the leaf bytes and the size, anyone can
//! re-compute the root and verify the STH signature against the logger's
//! public key.

pub mod auditor;
pub mod inclusion;
pub mod log;
pub mod merkle;
pub mod sth;
pub mod witness;

pub use auditor::{verify_inclusion_against_head, AuditError};
pub use inclusion::InclusionProof;
pub use log::{FsyncPolicy, LogEntry, LogStatus, TransparencyLog};
pub use merkle::{empty_root, merkle_root, root_of_leaves};
pub use sth::{SignedTreeHead, TreeHead};
pub use witness::{WitnessCosignature, WitnessKeyset};
