// SPDX-License-Identifier: Apache-2.0
//! Attestation evidence formats and verifiers.
//!
//! Phase 1 ships:
//! - `Evidence` envelope carrying a typed CPU quote + an opaque GPU quote
//! - Real **TDX v4** binary parser (`tdx`)
//! - Real **SEV-SNP** attestation-report parser (`snp`)
//! - **NVIDIA NRAS** JSON/JWS parser (`nvidia`)
//! - A `MockVerifier` for local dev (signs evidence with a test Ed25519 key)
//! - A `RealVerifier` that does structural validation + measurement-pin
//!   enforcement against caller-supplied allowlists
//!
//! Production TDX DCAP / AMD VCEK / NRAS PKI chaining plugs in on top of the
//! `RealVerifier` by implementing the `Verifier` trait.

pub mod evidence;
pub mod mock;
pub mod nvidia;
pub mod real_verifier;
pub mod signature;
pub mod snp;
pub mod tdx;
pub mod verifier;

pub use evidence::{Evidence, QuoteKind};
pub use mock::{MockIssuer, MockVerifier};
pub use nvidia::{NvidiaPayload, NvidiaQuote};
pub use real_verifier::{MeasurementPolicy, RealVerifier};
pub use signature::{verify_snp_report_signature, verify_tdx_quote_signature};
pub use snp::SnpReport;
pub use tdx::{TdReport, TdxQuote, TdxSignatureData};
pub use verifier::{VerificationContext, Verifier};
