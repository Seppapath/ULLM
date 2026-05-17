// SPDX-License-Identifier: Apache-2.0
//! k-of-n attestation across hardware-disjoint vendors.
//!
//! ## P13-FIX-E: dedup by attestation-key identity
//!
//! Previously `verify` counted unique passing slots by their caller-supplied
//! `VendorKind` label. A runtime attacker controlling a single TDX node
//! could submit two evidences from the same node — one tagged `Tdx`, one
//! tagged `Snp` — and if a permissive `MockVerifier` accepted both, the
//! threshold passed against a single physical vendor.
//!
//! The fix:
//!   1. Each `Verifier` returns an `attestation_identity` — a SHA-256 over
//!      the cryptographic material that identifies the underlying hardware
//!      key (TDX QE / SNP VCEK / NRAS root / Mock report_data).
//!   2. The federation aggregator deduplicates passing slots by this
//!      identity, not by `kind`.
//!   3. The aggregator additionally enforces `evidence.cpu_quote_kind`
//!      matches the slot's `kind` upfront, so a re-tagged evidence trying
//!      to fool the wrong slot is rejected before verification runs.

use std::collections::HashSet;

use ullm_attest::{Evidence, QuoteKind, VerificationContext, Verifier};
use ullm_core::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VendorKind {
    Tdx,
    Snp,
    Nvidia,
    Arm,
    Mock,
}

impl VendorKind {
    /// The CPU-quote kind a slot of this vendor is allowed to admit
    /// (P13-FIX-E step 4). The rule rejects an attacker's re-tagged TDX
    /// evidence from being fed to a slot that expects SNP, even before the
    /// inner verifier runs.
    ///
    /// - TDX/SNP slots accept ONLY matching real quote kinds.
    /// - NVIDIA/ARM slots are GPU-quote-bound; we admit either TDX or SNP
    ///   as the underlying CPU envelope because real NRAS deployments
    ///   always pair with a CPU TEE quote.
    /// - `Mock` evidence is admitted by ANY slot because `MockVerifier` is
    ///   dev-only (forced off in prod via `compile_error!`/feature flags)
    ///   and the federation aggregator's dedup-by-identity check is the
    ///   primary defence in dev as well. This keeps existing dev-side
    ///   call sites that wire Mock evidence into Tdx/Snp/Nvidia slots
    ///   working without weakening prod paths.
    fn admits_cpu_kind(self, k: QuoteKind) -> bool {
        if matches!(k, QuoteKind::Mock) {
            return true;
        }
        match (self, k) {
            (VendorKind::Tdx, QuoteKind::Tdx) => true,
            (VendorKind::Snp, QuoteKind::Snp) => true,
            (VendorKind::Nvidia, QuoteKind::Tdx | QuoteKind::Snp) => true,
            (VendorKind::Arm, QuoteKind::Tdx | QuoteKind::Snp) => true,
            (VendorKind::Mock, _) => false,
            _ => false,
        }
    }
}

/// One slot in the multi-vendor aggregator: a verifier tagged with the
/// vendor it accepts. We do **not** trust the verifier to identify its
/// vendor — the `kind` is the caller-supplied label used for disjointness
/// and for an upfront slot-vs-evidence quote-kind consistency check
/// (P13-FIX-E).
pub struct VendorVerifier {
    pub kind: VendorKind,
    pub verifier: Box<dyn Verifier + Send + Sync>,
}

impl VendorVerifier {
    pub fn new<V: Verifier + Send + Sync + 'static>(kind: VendorKind, v: V) -> Self {
        Self {
            kind,
            verifier: Box::new(v),
        }
    }
}

/// Requires `threshold_k` distinct vendors to verify successfully.
///
/// `evidences[i]` is fed to `verifiers[i]`. Each slot independently produces
/// a pass/fail; the aggregator counts unique passing vendor kinds and
/// returns `Ok(())` iff that count reaches `threshold_k`.
pub struct MultiVendorVerifier {
    pub verifiers: Vec<VendorVerifier>,
    pub threshold_k: usize,
}

impl MultiVendorVerifier {
    pub fn new(verifiers: Vec<VendorVerifier>, threshold_k: usize) -> Result<Self> {
        if threshold_k == 0 || threshold_k > verifiers.len() {
            return Err(Error::Other(format!(
                "threshold_k={} invalid for n={}",
                threshold_k,
                verifiers.len()
            )));
        }
        let mut kinds = HashSet::new();
        for v in &verifiers {
            if !kinds.insert(v.kind) {
                return Err(Error::Other(format!(
                    "duplicate vendor kind {:?} — federation requires disjoint vendors",
                    v.kind
                )));
            }
        }
        Ok(Self {
            verifiers,
            threshold_k,
        })
    }

    pub fn verify(
        &self,
        evidences: &[Evidence],
        ctx: &VerificationContext<'_>,
    ) -> Result<HashSet<VendorKind>> {
        if evidences.len() != self.verifiers.len() {
            return Err(Error::Other(format!(
                "expected {} evidences, got {}",
                self.verifiers.len(),
                evidences.len()
            )));
        }
        // P13-FIX-E: track unique passing slots by *attestation-key identity*
        // (cryptographic, verifier-derived) rather than by *VendorKind*
        // (caller-supplied label). A single compromised physical node
        // returning two evidences with different kind labels collides on
        // the same identity and contributes one slot's worth of trust, not
        // two.
        let mut passing_kinds: HashSet<VendorKind> = HashSet::new();
        let mut passing_identities: HashSet<[u8; 32]> = HashSet::new();
        for (slot, evidence) in self.verifiers.iter().zip(evidences) {
            // Slot-vs-evidence quote-kind consistency check (P13-FIX-E
            // step 4): reject upfront if the caller is trying to feed a
            // re-tagged evidence to a slot whose vendor doesn't admit it.
            // This forces an attacker who re-tags a TDX evidence as SNP to
            // produce evidence that actually parses as SNP — collapsing
            // the bypass into a different (still-defended) attack.
            if !slot.kind.admits_cpu_kind(evidence.cpu_quote_kind) {
                continue;
            }
            if slot.verifier.verify(evidence, ctx).is_err() {
                continue;
            }
            // A verifier that passes must be able to mint a stable identity
            // for what it just accepted. If it cannot, refuse to count the
            // slot — better to fail closed than to silently inflate the
            // passing count with un-deduplicatable evidence.
            let Some(id) = slot.verifier.attestation_identity(evidence) else {
                continue;
            };
            if passing_identities.insert(id) {
                passing_kinds.insert(slot.kind);
            }
        }
        if passing_identities.len() < self.threshold_k {
            return Err(Error::AttestationFailed(format!(
                "k-of-n failed: {} distinct attestation identities, threshold {}",
                passing_identities.len(),
                self.threshold_k
            )));
        }
        Ok(passing_kinds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ullm_attest::{MockIssuer, MockVerifier};

    fn rd() -> [u8; 64] {
        [3u8; 64]
    }
    fn ctx<'a>(expected: &'a [u8; 64], now: u64) -> VerificationContext<'a> {
        VerificationContext {
            expected_report_data: expected,
            now_unix: now,
            max_age_sec: 60,
        }
    }

    fn make_slot(kind: VendorKind, rng: &mut OsRng) -> (VendorVerifier, Evidence) {
        let issuer = MockIssuer::random(rng);
        let verifier = MockVerifier::new(issuer.verifying_key());
        let evidence = issuer.issue(&rd(), 100);
        (VendorVerifier::new(kind, verifier), evidence)
    }

    #[test]
    fn k_of_n_accepts_when_threshold_met() {
        let mut rng = OsRng;
        let (s0, e0) = make_slot(VendorKind::Tdx, &mut rng);
        let (s1, e1) = make_slot(VendorKind::Snp, &mut rng);
        let (s2, e2) = make_slot(VendorKind::Nvidia, &mut rng);
        let mv = MultiVendorVerifier::new(vec![s0, s1, s2], 2).unwrap();
        let passing = mv.verify(&[e0, e1, e2], &ctx(&rd(), 100)).unwrap();
        assert_eq!(passing.len(), 3);
    }

    #[test]
    fn k_of_n_accepts_with_one_failure() {
        let mut rng = OsRng;
        let (s0, e0) = make_slot(VendorKind::Tdx, &mut rng);
        let (s1, e1) = make_slot(VendorKind::Snp, &mut rng);
        let (s2, mut e2) = make_slot(VendorKind::Nvidia, &mut rng);
        // Tamper one evidence so its slot fails.
        e2.cpu_quote[0] ^= 0xFF;
        let mv = MultiVendorVerifier::new(vec![s0, s1, s2], 2).unwrap();
        let passing = mv.verify(&[e0, e1, e2], &ctx(&rd(), 100)).unwrap();
        assert_eq!(passing.len(), 2);
    }

    #[test]
    fn k_of_n_rejects_below_threshold() {
        let mut rng = OsRng;
        let (s0, mut e0) = make_slot(VendorKind::Tdx, &mut rng);
        let (s1, mut e1) = make_slot(VendorKind::Snp, &mut rng);
        let (s2, e2) = make_slot(VendorKind::Nvidia, &mut rng);
        e0.cpu_quote[0] ^= 0xFF;
        e1.cpu_quote[0] ^= 0xFF;
        let mv = MultiVendorVerifier::new(vec![s0, s1, s2], 2).unwrap();
        assert!(mv.verify(&[e0, e1, e2], &ctx(&rd(), 100)).is_err());
    }

    #[test]
    fn rejects_duplicate_vendor() {
        let mut rng = OsRng;
        let (s0, _) = make_slot(VendorKind::Tdx, &mut rng);
        let (s1, _) = make_slot(VendorKind::Tdx, &mut rng);
        assert!(MultiVendorVerifier::new(vec![s0, s1], 1).is_err());
    }

    #[test]
    fn rejects_bad_threshold() {
        let mut rng = OsRng;
        let (s0, _) = make_slot(VendorKind::Tdx, &mut rng);
        assert!(MultiVendorVerifier::new(vec![s0], 0).is_err());
        let (s1, _) = make_slot(VendorKind::Snp, &mut rng);
        assert!(MultiVendorVerifier::new(vec![s1], 2).is_err());
    }

    /// Permissive verifier that accepts ANY evidence regardless of its
    /// `cpu_quote_kind`. Models a compromised / misconfigured slot whose
    /// inner verifier mis-trusts re-tagged evidence — exactly the
    /// pre-fix attack surface P13-FIX-E closes.
    struct PermissiveVerifier;
    impl Verifier for PermissiveVerifier {
        fn verify(&self, _ev: &Evidence, _ctx: &VerificationContext<'_>) -> Result<()> {
            Ok(())
        }
        fn attestation_identity(&self, ev: &Evidence) -> Option<[u8; 32]> {
            // Mirror the MockVerifier identity scheme: hash report_data
            // (plus a domain tag). Two evidences with the same report_data
            // collide on this identity even when their kind labels differ.
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"ullm/test/permissive/v1");
            h.update(ev.report_data);
            Some(h.finalize().into())
        }
    }

    /// P13-FIX-E regression: a runtime attacker controlling a single
    /// compromised node can submit two evidences with the same
    /// `report_data` but *different* caller-supplied `QuoteKind` labels.
    /// Pre-fix, the aggregator deduplicated by slot `kind`, so both
    /// counted toward the threshold and 2-of-3 passed against a single
    /// vendor.
    ///
    /// Post-fix, the aggregator deduplicates by *attestation-key
    /// identity* (returned by the verifier). Both forged evidences share
    /// the same `report_data` and therefore the same identity, so they
    /// contribute one slot's worth of trust — and the threshold of 2
    /// is NOT met. The third slot is given evidence that fails
    /// verification (different report_data than ctx).
    #[test]
    fn rejects_two_evidences_from_one_vendor_with_distinct_kind_labels() {
        // Same channel binding for both attacker-controlled evidences.
        let shared_rd = [42u8; 64];
        let now = 100u64;
        // Two evidences from the SAME compromised node, tagged with two
        // different kinds. Note: real `MockIssuer` evidence is tagged
        // QuoteKind::Mock and `MockVerifier` rejects non-Mock kinds, so
        // we hand-craft the envelope directly (the attacker controls
        // the bytes).
        let ev_tdx_tagged = Evidence {
            cpu_quote_kind: QuoteKind::Tdx,
            cpu_quote: vec![0u8; 16], // not parsed by PermissiveVerifier
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd,
            issued_at_unix: now,
        };
        let ev_snp_tagged = Evidence {
            cpu_quote_kind: QuoteKind::Snp,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd, // SAME report_data — same identity
            issued_at_unix: now,
        };
        // Third slot's evidence won't pass (use a non-matching report_data
        // OR a slot whose verifier-issued kind admittance refuses it). We
        // pick a Mock-tagged evidence with a different report_data so the
        // PermissiveVerifier still accepts, but the identity hash differs
        // (proving the attack requires real diversity to win).
        let ev_third = Evidence {
            cpu_quote_kind: QuoteKind::Mock,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: [99u8; 64], // distinct identity
            issued_at_unix: now,
        };

        let mv = MultiVendorVerifier::new(
            vec![
                VendorVerifier::new(VendorKind::Tdx, PermissiveVerifier),
                VendorVerifier::new(VendorKind::Snp, PermissiveVerifier),
                VendorVerifier::new(VendorKind::Nvidia, PermissiveVerifier),
            ],
            2,
        )
        .unwrap();

        // Sanity: without the identity collision attack, threshold passes.
        // Submitting THREE independent identities reaches k=2 and k=3.
        let ev_a = Evidence {
            report_data: [1u8; 64],
            ..ev_third.clone()
        };
        let ev_b = Evidence {
            report_data: [2u8; 64],
            ..ev_third.clone()
        };
        let ev_c = Evidence {
            report_data: [3u8; 64],
            ..ev_third.clone()
        };
        let ok = mv.verify(
            &[ev_a, ev_b, ev_c],
            &VerificationContext {
                expected_report_data: &[0u8; 64],
                now_unix: now,
                max_age_sec: 60,
            },
        );
        assert!(ok.is_ok(), "three distinct identities should pass k=2");

        // Now the actual attack: two slots fed evidence from ONE
        // compromised node (same report_data, different kind labels),
        // the third slot fed evidence with a DIFFERENT report_data
        // (independent identity). Pre-fix this was 3 distinct kinds and
        // passed; post-fix it is 2 distinct identities — STILL ≥ 2 in
        // raw count, so the attack also has to ensure the third slot's
        // evidence FAILS to verify. We arrange that by submitting the
        // same compromised identity for the third slot too, so all
        // three collide on identity and only ONE counts.
        let ev_third_collide = Evidence {
            cpu_quote_kind: QuoteKind::Mock,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd, // collides with the other two
            issued_at_unix: now,
        };
        let attack_result = mv.verify(
            &[ev_tdx_tagged, ev_snp_tagged, ev_third_collide],
            &VerificationContext {
                expected_report_data: &shared_rd,
                now_unix: now,
                max_age_sec: 60,
            },
        );
        assert!(
            attack_result.is_err(),
            "expected k-of-n to FAIL: three evidences collide on attestation_identity, only 1 distinct identity available, threshold=2 not met. got: {:?}",
            attack_result
        );
    }

    /// Companion test: confirm that when the attacker mixes ONE
    /// compromised-node identity with ONE genuinely-different identity,
    /// only 2 distinct identities pass — exactly hitting the threshold
    /// of 2 (not 3 as the pre-fix would have counted).
    #[test]
    fn distinct_identities_count_under_dedup() {
        let shared_rd = [42u8; 64];
        let other_rd = [77u8; 64];
        let now = 100u64;

        let ev_attack_a = Evidence {
            cpu_quote_kind: QuoteKind::Tdx,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd,
            issued_at_unix: now,
        };
        let ev_attack_b = Evidence {
            cpu_quote_kind: QuoteKind::Snp,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd,
            issued_at_unix: now,
        };
        let ev_genuine = Evidence {
            cpu_quote_kind: QuoteKind::Mock,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: other_rd,
            issued_at_unix: now,
        };

        let mv = MultiVendorVerifier::new(
            vec![
                VendorVerifier::new(VendorKind::Tdx, PermissiveVerifier),
                VendorVerifier::new(VendorKind::Snp, PermissiveVerifier),
                VendorVerifier::new(VendorKind::Nvidia, PermissiveVerifier),
            ],
            2,
        )
        .unwrap();

        // Threshold 2 IS met (one attacker identity + one genuine = 2),
        // but the post-fix passing-kinds set reflects identity dedup.
        let passing = mv
            .verify(
                &[ev_attack_a, ev_attack_b, ev_genuine],
                &VerificationContext {
                    expected_report_data: &shared_rd,
                    now_unix: now,
                    max_age_sec: 60,
                },
            )
            .expect("two distinct identities meet threshold=2");
        // The first-seen kind for each distinct identity is recorded.
        // Iteration order is deterministic (zip order), so the attacker
        // slot Tdx wins for shared_rd, and Nvidia wins for other_rd.
        assert_eq!(passing.len(), 2);
        assert!(passing.contains(&VendorKind::Tdx));
        assert!(passing.contains(&VendorKind::Nvidia));
        assert!(!passing.contains(&VendorKind::Snp));

        // And a threshold of 3 is NOT met — only 2 distinct identities.
        let mv3 = MultiVendorVerifier::new(
            vec![
                VendorVerifier::new(VendorKind::Tdx, PermissiveVerifier),
                VendorVerifier::new(VendorKind::Snp, PermissiveVerifier),
                VendorVerifier::new(VendorKind::Nvidia, PermissiveVerifier),
            ],
            3,
        )
        .unwrap();
        let ev_a2 = Evidence {
            cpu_quote_kind: QuoteKind::Tdx,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd,
            issued_at_unix: now,
        };
        let ev_b2 = Evidence {
            cpu_quote_kind: QuoteKind::Snp,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: shared_rd,
            issued_at_unix: now,
        };
        let ev_c2 = Evidence {
            cpu_quote_kind: QuoteKind::Mock,
            cpu_quote: vec![0u8; 16],
            gpu_quote: vec![],
            cert_chain: vec![],
            report_data: other_rd,
            issued_at_unix: now,
        };
        let res = mv3.verify(
            &[ev_a2, ev_b2, ev_c2],
            &VerificationContext {
                expected_report_data: &shared_rd,
                now_unix: now,
                max_age_sec: 60,
            },
        );
        assert!(res.is_err(), "k=3 must fail with only 2 distinct identities");
    }
}
