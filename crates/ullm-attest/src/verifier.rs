// SPDX-License-Identifier: Apache-2.0
use ullm_core::Result;

use crate::evidence::Evidence;

/// Inputs the caller (handshake driver) feeds into the verifier.
pub struct VerificationContext<'a> {
    /// Expected channel-binding payload (computed by the handshake).
    pub expected_report_data: &'a [u8; 64],
    /// Wall-clock seconds at verification time.
    pub now_unix: u64,
    /// Maximum age of the attestation in seconds.
    pub max_age_sec: u64,
}

/// Pluggable attestation backend. Real backends (TDX, SEV-SNP, NRAS) implement
/// this trait; the mock implementation is in `mock.rs`.
pub trait Verifier {
    fn verify(&self, evidence: &Evidence, ctx: &VerificationContext<'_>) -> Result<()>;

    /// Return a stable 32-byte cryptographic identity for the underlying
    /// attestation. This is used by `MultiVendorVerifier` to dedup PASSING
    /// evidence by attestation-key identity rather than caller-supplied
    /// `QuoteKind` labels — see P13-FIX-E.
    ///
    /// Implementations should return a value derived from cryptographic
    /// material that an attacker controlling a single physical node cannot
    /// forge across vendors:
    /// - TDX: SHA-256 over the attestation key + cert-data (QE identity).
    /// - SEV-SNP: SHA-256 over the VCEK / chip identity bytes.
    /// - NRAS: SHA-256 over the JWS-signed message + signature (NVIDIA root
    ///   pubkey is not currently transported in the envelope, so we anchor
    ///   the identity to the signed material; see LIMITATIONS in module
    ///   docs).
    /// - Mock: SHA-256 over `evidence.report_data` (dev-only).
    ///
    /// Returns `None` only when the verifier cannot extract any stable
    /// identity from the evidence — in which case the federation aggregator
    /// must NOT count the slot as contributing to the threshold.
    fn attestation_identity(&self, evidence: &Evidence) -> Option<[u8; 32]>;
}
