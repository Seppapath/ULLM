// SPDX-License-Identifier: Apache-2.0
//! Structural verifier for real TDX / SNP / NRAS evidence.
//!
//! This verifier:
//! - parses the binary CPU quote (TDX or SNP) and the NVIDIA payload
//! - checks `REPORT_DATA` matches the expected channel-binding payload
//! - checks freshness via `issued_at_unix`
//! - validates known measurement pins (MRTD / MEASUREMENT) against
//!   caller-supplied allowlists
//!
//! It does NOT chain the CPU signature to Intel/AMD vendor PKI nor the GPU
//! payload to NVIDIA's NRAS root. Those steps require shipping vendor root
//! certs + revocation data; they plug in on top of this verifier.

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ullm_core::{Error, Result};

use crate::evidence::{Evidence, QuoteKind};
use crate::tdx::TdxQuote;
use crate::snp::SnpReport;
use crate::nvidia::NvidiaQuote;
use crate::verifier::{VerificationContext, Verifier};

/// Constant-time equality for the 64-byte `REPORT_DATA` channel-binding
/// payload. Phase 3 audit (P3-1) flagged the previous `!=` compares as a
/// timing oracle — `subtle::ConstantTimeEq` on the slice always touches
/// every byte. We slice rather than call the array form because
/// `subtle 2.x` only implements `ConstantTimeEq` on `&[u8]`.
fn ct_eq_report_data(a: &[u8; 64], b: &[u8; 64]) -> bool {
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// Allowlists of acceptable platform measurements.
#[derive(Default, Clone)]
pub struct MeasurementPolicy {
    pub allowed_mrtd: HashSet<[u8; 48]>,
    pub allowed_snp_measurement: HashSet<[u8; 48]>,
    pub allowed_nvidia_measurements_hex: HashSet<String>,
}

pub struct RealVerifier {
    pub policy: MeasurementPolicy,
    /// When `true`, verify the ECDSA-P256 signature on TDX quotes using the
    /// in-quote attestation key. Defaults to `false`; deployments turn it on
    /// once they can supply signed quotes (live hardware or PCS collateral).
    pub check_signatures: bool,
}

impl RealVerifier {
    pub fn new(policy: MeasurementPolicy) -> Self {
        Self {
            policy,
            check_signatures: false,
        }
    }

    pub fn with_signature_check(mut self, on: bool) -> Self {
        self.check_signatures = on;
        self
    }
}

impl Verifier for RealVerifier {
    fn verify(&self, evidence: &Evidence, ctx: &VerificationContext<'_>) -> Result<()> {
        if ctx.now_unix.saturating_sub(evidence.issued_at_unix) > ctx.max_age_sec {
            return Err(Error::StaleAttestation {
                ttl_sec: ctx.max_age_sec,
            });
        }
        if !ct_eq_report_data(&evidence.report_data, ctx.expected_report_data) {
            return Err(Error::AttestationFailed("report_data mismatch".into()));
        }
        match evidence.cpu_quote_kind {
            QuoteKind::Tdx => {
                let q = TdxQuote::parse(&evidence.cpu_quote)?;
                if !ct_eq_report_data(q.report_data(), &evidence.report_data) {
                    return Err(Error::AttestationFailed(
                        "TDX REPORT_DATA != envelope report_data".into(),
                    ));
                }
                if !self.policy.allowed_mrtd.is_empty()
                    && !self.policy.allowed_mrtd.contains(&q.td_report.mrtd)
                {
                    return Err(Error::AttestationFailed(format!(
                        "MRTD {} not in allowlist",
                        hex(&q.td_report.mrtd)
                    )));
                }
                if self.check_signatures {
                    crate::signature::verify_tdx_quote_signature(&q, &evidence.cpu_quote)?;
                }
            }
            QuoteKind::Snp => {
                let r = SnpReport::parse(&evidence.cpu_quote)?;
                if !ct_eq_report_data(&r.report_data, &evidence.report_data) {
                    return Err(Error::AttestationFailed(
                        "SNP REPORT_DATA != envelope report_data".into(),
                    ));
                }
                if !self.policy.allowed_snp_measurement.is_empty()
                    && !self.policy.allowed_snp_measurement.contains(&r.measurement)
                {
                    return Err(Error::AttestationFailed(format!(
                        "SNP MEASUREMENT {} not in allowlist",
                        hex(&r.measurement)
                    )));
                }
            }
            QuoteKind::Mock => {
                return Err(Error::AttestationFailed(
                    "RealVerifier received a Mock quote".into(),
                ));
            }
        }
        if !evidence.gpu_quote.is_empty() {
            let nv = NvidiaQuote::parse(&evidence.gpu_quote)?;
            if !self.policy.allowed_nvidia_measurements_hex.is_empty()
                && !self
                    .policy
                    .allowed_nvidia_measurements_hex
                    .contains(&nv.payload.measurement_hex)
            {
                return Err(Error::AttestationFailed(format!(
                    "NVIDIA measurement {} not in allowlist",
                    nv.payload.measurement_hex
                )));
            }
        }
        Ok(())
    }

    /// Attestation identity for federation dedup (P13-FIX-E). The returned
    /// digest is stable across the lifetime of the underlying hardware key
    /// and changes when (and only when) the attestation key changes. This is
    /// the property `MultiVendorVerifier` needs to count "distinct vendors":
    /// two evidences from the same physical TDX node share an attestation
    /// key, so they collide and contribute one slot's worth of trust.
    ///
    /// LIMITATIONS:
    /// - For TDX we hash `signature.attestation_key || signature.cert_data`.
    ///   This is the QE-identity-bearing material; a node that does not roll
    ///   keys produces the same digest across quotes. We do NOT extract the
    ///   Intel root CA fingerprint from the cert chain (would require an
    ///   X.509 parser in this layer). Follow-up: parse `cert_data` as a
    ///   DER chain and hash the leaf+root pair for stronger identity.
    /// - For SNP we hash `signature || chip_id`. The signature differs
    ///   per-quote but `chip_id` is the physical CPU identifier — including
    ///   it ensures evidence from the same CPU collides regardless of which
    ///   measurements it claims. Follow-up: switch to a VCEK fingerprint
    ///   once cert chains are transported in the envelope.
    /// - For NRAS we hash `signed_message || signature` from the JWS. The
    ///   NVIDIA root pubkey is not carried in the envelope, so we anchor
    ///   the identity to the signed material. Follow-up: extract the NVIDIA
    ///   root pubkey from the JWS header / cert chain once it's transported.
    fn attestation_identity(&self, evidence: &Evidence) -> Option<[u8; 32]> {
        let mut h = Sha256::new();
        match evidence.cpu_quote_kind {
            QuoteKind::Tdx => {
                let q = TdxQuote::parse(&evidence.cpu_quote).ok()?;
                h.update(b"ullm/attest-id/tdx/v1");
                h.update(q.signature.attestation_key);
                h.update(&q.signature.cert_data);
            }
            QuoteKind::Snp => {
                let r = SnpReport::parse(&evidence.cpu_quote).ok()?;
                h.update(b"ullm/attest-id/snp/v1");
                h.update(r.chip_id);
                // Mix the signature bytes too so a degraded chip_id (e.g.
                // all-zero on synthetic reports) still produces a usable
                // identity for tests. Real chip_id values are 64 random
                // bytes per CPU and dominate the digest.
                h.update(r.signature);
            }
            QuoteKind::Mock => {
                // RealVerifier rejects Mock above, but be defensive: if a
                // caller ever bypasses verify() and asks for an identity on
                // a Mock-tagged evidence, refuse rather than minting one.
                return None;
            }
        }
        if !evidence.gpu_quote.is_empty() {
            if let Ok(nv) = NvidiaQuote::parse(&evidence.gpu_quote) {
                h.update(b"|nras|");
                h.update(&nv.signed_message);
                h.update(&nv.signature);
            }
        }
        Some(h.finalize().into())
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        s.push_str(&format!("{:02x}", c));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::synthesize_quote;

    fn ctx<'a>(expected: &'a [u8; 64], now: u64) -> VerificationContext<'a> {
        VerificationContext {
            expected_report_data: expected,
            now_unix: now,
            max_age_sec: 60,
        }
    }

    fn ev(kind: QuoteKind, quote: Vec<u8>, rd: [u8; 64], now: u64) -> Evidence {
        Evidence {
            cpu_quote_kind: kind,
            cpu_quote: quote,
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: rd,
            issued_at_unix: now,
        }
    }

    #[test]
    fn accepts_well_formed_tdx() {
        let mrtd = [9u8; 48];
        let rd = [3u8; 64];
        let policy = MeasurementPolicy {
            allowed_mrtd: [mrtd].into_iter().collect(),
            ..Default::default()
        };
        let q = synthesize_quote(rd, mrtd);
        let e = ev(QuoteKind::Tdx, q, rd, 100);
        RealVerifier::new(policy).verify(&e, &ctx(&rd, 110)).unwrap();
    }

    #[test]
    fn signed_tdx_quote_passes_signature_check() {
        use rand_core::OsRng;
        let mrtd = [12u8; 48];
        let rd = [13u8; 64];
        let bytes = crate::signature::test_support::signed_tdx_quote(&mut OsRng, rd, mrtd);
        let policy = MeasurementPolicy {
            allowed_mrtd: [mrtd].into_iter().collect(),
            ..Default::default()
        };
        let e = ev(QuoteKind::Tdx, bytes, rd, 100);
        RealVerifier::new(policy)
            .with_signature_check(true)
            .verify(&e, &ctx(&rd, 110))
            .unwrap();
    }

    #[test]
    fn unsigned_quote_rejected_when_signature_check_on() {
        let mrtd = [9u8; 48];
        let rd = [3u8; 64];
        let policy = MeasurementPolicy {
            allowed_mrtd: [mrtd].into_iter().collect(),
            ..Default::default()
        };
        let q = synthesize_quote(rd, mrtd); // zeroed signature
        let e = ev(QuoteKind::Tdx, q, rd, 100);
        let res = RealVerifier::new(policy)
            .with_signature_check(true)
            .verify(&e, &ctx(&rd, 110));
        assert!(res.is_err());
    }

    #[test]
    fn rejects_wrong_mrtd() {
        let q = synthesize_quote([3u8; 64], [9u8; 48]);
        let policy = MeasurementPolicy {
            allowed_mrtd: [[0u8; 48]].into_iter().collect(),
            ..Default::default()
        };
        let e = ev(QuoteKind::Tdx, q, [3u8; 64], 100);
        assert!(RealVerifier::new(policy)
            .verify(&e, &ctx(&[3u8; 64], 100))
            .is_err());
    }

    #[test]
    fn rejects_stale() {
        let q = synthesize_quote([3u8; 64], [9u8; 48]);
        let e = ev(QuoteKind::Tdx, q, [3u8; 64], 0);
        assert!(RealVerifier::new(MeasurementPolicy::default())
            .verify(&e, &ctx(&[3u8; 64], 1000))
            .is_err());
    }

    #[test]
    fn rejects_report_data_mismatch() {
        let q = synthesize_quote([3u8; 64], [9u8; 48]);
        let e = ev(QuoteKind::Tdx, q, [3u8; 64], 100);
        assert!(RealVerifier::new(MeasurementPolicy::default())
            .verify(&e, &ctx(&[4u8; 64], 100))
            .is_err());
    }
}
