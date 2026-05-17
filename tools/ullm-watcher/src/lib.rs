// SPDX-License-Identifier: Apache-2.0
//! Fraud-proof watcher.
//!
//! Reproduces the deterministic forward pass and compares each activation
//! commitment to the claim in the signed receipt. Returns the first
//! divergent layer (if any) as a `FraudReport`.
//!
//! P13-FIX-B: in addition to the local recompute + Ed25519 signature
//! check, the watcher can now (when supplied with the relevant inputs):
//!
//! - Verify TEE attestation evidence against vendor-style measurement
//!   policy + freshness window.
//! - Verify a transparency-log inclusion proof against an STH whose
//!   signature must match the bundled logger pubkey.
//! - Pin externally-supplied `weight_commit` / `session_id`.
//! - Bound STH freshness (`issued_at_unix` vs caller-supplied wall clock).
//!
//! Each check is independently reflected in `FraudReport` as a boolean.
//! `Verdict::is_fully_verified` returns `true` only when EVERY check
//! passed; partial verification (e.g. no attestation evidence supplied)
//! produces `Verdict::Partial` and the corresponding flag stays `false`.

use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use ullm_attest::{Evidence, MeasurementPolicy, RealVerifier, VerificationContext, Verifier};
use ullm_model::{vector_commit, Model, NUM_LAYERS, VEC_DIM};
use ullm_receipts::SignedReceipt;
use ullm_transparency::{
    verify_inclusion_against_head, InclusionProof, LogEntry, SignedTreeHead,
};
use ullm_zk::Fp;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("receipt signature invalid")]
    BadSignature,
    #[error("weight commit in receipt does not match model")]
    WeightCommitMismatch,
    #[error("receipt has {got} activation commits, expected {expected}")]
    ActivationLenMismatch { got: usize, expected: usize },
    #[error("bad hex: {0}")]
    BadHex(String),
    #[error("commit byte length != 32")]
    BadCommitLength,
    #[error("input hash in claim does not match the supplied prompt bytes")]
    InputMismatch,
}

#[derive(Debug, Clone, Serialize)]
pub enum Verdict {
    /// Activation recompute matched AND every supplied verification check
    /// passed. This is the only outcome a downstream system should treat
    /// as "trusted receipt."
    Honest,
    /// Activation recompute matched the TEE claim, but one or more
    /// additional verification checks were not performed (because the
    /// caller didn't supply the relevant inputs) or did not pass. See the
    /// per-flag booleans on `FraudReport` for the breakdown.
    Partial,
    /// The first layer index where the TEE-claimed commit diverges from
    /// the watcher's computation.
    Fraudulent { divergent_layer: usize },
}

impl Verdict {
    /// True iff every verification flag in the report passed. Provided
    /// here so callers don't have to remember the full flag set — the
    /// helper closes the "I forgot to check `sth_freshness_verified`"
    /// foot-gun that the previous `Verdict::Honest` shape exposed.
    pub fn is_fully_verified(report: &FraudReport) -> bool {
        report.activations_consistent
            && report.receipt_signature_verified
            && report.attestation_verified
            && report.log_inclusion_verified
            && report.sth_signature_verified
            && report.sth_freshness_verified
            && report.weight_commit_pinned
            && report.session_pinned
            && report.zk_proofs_verified
    }
}

/// Verification flags. A `false` means *this check did not pass*: either
/// the input was not supplied (so the watcher cannot vouch for the
/// property) or the input was supplied and verification failed.
/// `FraudReport::notes` distinguishes "not checked" from "failed."
#[derive(Debug, Clone, Serialize)]
pub struct FraudReport {
    pub activations_consistent: bool,
    pub receipt_signature_verified: bool,
    pub attestation_verified: bool,
    pub log_inclusion_verified: bool,
    pub sth_signature_verified: bool,
    pub sth_freshness_verified: bool,
    pub weight_commit_pinned: bool,
    pub session_pinned: bool,
    pub zk_proofs_verified: bool,
    pub session_hex: String,
    pub tenant: String,
    pub epoch: u32,
    pub verdict: Verdict,
    pub claimed_commits_hex: Vec<String>,
    pub recomputed_commits_hex: Vec<String>,
    pub weight_commit_hex: String,
    /// Human-readable per-flag notes ("not checked because expected-X not
    /// provided" / "failed because Y"). Indexed by flag name.
    pub notes: Vec<(String, String)>,
}

/// Bundle of optional verification inputs. Each field is `None` if the
/// caller can't supply it; the corresponding flag in the report stays
/// `false` and a note is recorded.
#[derive(Default)]
pub struct AuditInputs<'a> {
    /// Attestation evidence + verification context. When provided, the
    /// watcher runs `ullm-attest`'s `RealVerifier` against
    /// `attestation_policy` (allowlists) and the supplied `now_unix` /
    /// `max_age_sec` freshness window. `expected_report_data` must be
    /// pre-computed by the caller (it's the handshake channel-binding
    /// blob — outside the watcher's purview).
    pub attestation: Option<AttestationCheck<'a>>,
    /// Transparency-log inclusion-proof bundle. The STH signature is
    /// verified against `logger_pk` (when supplied); the inclusion path
    /// is then verified to open to `expected_entry`.
    pub log_inclusion: Option<LogInclusionCheck<'a>>,
    /// Freshness check on the STH: rejects when
    /// `now_unix - sth.head.issued_at_unix > max_age_sec`.
    pub sth_freshness: Option<SthFreshnessCheck>,
    /// Externally-supplied 32-byte weight-commit pin. The receipt's
    /// `weight_commit_hex` (already verified to equal the model
    /// recompute) must also equal this value, otherwise the watcher
    /// flags it as a pin mismatch.
    pub expected_weight_commit: Option<[u8; 32]>,
    /// Externally-supplied 16-byte session-id pin. Same logic — the
    /// receipt's session must match.
    pub expected_session: Option<[u8; 16]>,
    /// Per-layer ZK proofs from a `ReceiptEnvelope`. P13-FIX-B leaves the
    /// proof-verification body as a structural pass-through (presence +
    /// count check); per-layer verifier wiring is the subject of
    /// P13-FIX-C. The flag is `true` when the caller asserts the proofs
    /// are present and the count matches `NUM_LAYERS`.
    pub zk_layer_proofs: Option<&'a [Vec<u8>]>,
}

pub struct AttestationCheck<'a> {
    pub evidence: &'a Evidence,
    pub policy: MeasurementPolicy,
    pub expected_report_data: &'a [u8; 64],
    pub now_unix: u64,
    pub max_age_sec: u64,
    pub require_signature_check: bool,
}

pub struct LogInclusionCheck<'a> {
    pub sth: &'a SignedTreeHead,
    pub proof: &'a InclusionProof,
    pub expected_entry: &'a LogEntry,
    pub expected_log_id: Option<&'a str>,
    /// When supplied, the STH's `logger_pk` must equal this byte-for-byte.
    pub expected_logger_pk: Option<&'a [u8; 32]>,
}

pub struct SthFreshnessCheck {
    pub sth_issued_at_unix: u64,
    pub now_unix: u64,
    pub max_age_sec: u64,
}

/// Backwards-compatible alias for the simple call shape used by the
/// existing CLI and downstream integration tests. Equivalent to calling
/// `audit_with(seed, pk, prompt, signed, AuditInputs::default())`.
pub fn audit(
    model_seed: &[u8; 32],
    tee_receipt_pk: &VerifyingKey,
    prompt_bytes: &[u8],
    signed: &SignedReceipt,
) -> Result<FraudReport, AuditError> {
    audit_with(
        model_seed,
        tee_receipt_pk,
        prompt_bytes,
        signed,
        AuditInputs::default(),
    )
}

/// Full audit with optional supplementary checks. See `AuditInputs`.
pub fn audit_with(
    model_seed: &[u8; 32],
    tee_receipt_pk: &VerifyingKey,
    prompt_bytes: &[u8],
    signed: &SignedReceipt,
    inputs: AuditInputs<'_>,
) -> Result<FraudReport, AuditError> {
    let mut notes: Vec<(String, String)> = Vec::new();

    // ---- Receipt signature ----
    ullm_receipts::verify(signed, tee_receipt_pk).map_err(|_| AuditError::BadSignature)?;
    let receipt_signature_verified = true;

    // ---- Model recompute + activation comparison ----
    let model = Model::from_seed(model_seed);
    if hex::encode(model.weight_commit()) != signed.receipt.weight_commit_hex {
        return Err(AuditError::WeightCommitMismatch);
    }

    let input_hash: [u8; 32] = Sha256::digest(prompt_bytes).into();
    let model_input = encode_prompt_to_fp(&input_hash);

    let trace = model.run(model_input);
    let recomputed: Vec<[u8; 32]> = trace
        .activations
        .iter()
        .map(|a| vector_commit(a))
        .collect();

    let claimed = decode_commits(&signed.receipt.activation_commits_hex)?;
    if claimed.len() != NUM_LAYERS + 1 {
        return Err(AuditError::ActivationLenMismatch {
            got: claimed.len(),
            expected: NUM_LAYERS + 1,
        });
    }

    let mut divergent = None;
    for i in 0..claimed.len() {
        if claimed[i] != recomputed[i] {
            divergent = Some(i);
            break;
        }
    }
    let activations_consistent = divergent.is_none();

    // ---- Attestation ----
    let mut attestation_verified = false;
    match &inputs.attestation {
        Some(att) => {
            let verifier = RealVerifier::new(att.policy.clone())
                .with_signature_check(att.require_signature_check);
            let ctx = VerificationContext {
                expected_report_data: att.expected_report_data,
                now_unix: att.now_unix,
                max_age_sec: att.max_age_sec,
            };
            match verifier.verify(att.evidence, &ctx) {
                Ok(()) => attestation_verified = true,
                Err(e) => notes.push((
                    "attestation_verified".into(),
                    format!("attestation verification failed: {e}"),
                )),
            }
        }
        None => notes.push((
            "attestation_verified".into(),
            "not checked because --attestation-evidence not provided".into(),
        )),
    }

    // ---- Log inclusion + STH signature ----
    let mut log_inclusion_verified = false;
    let mut sth_signature_verified = false;
    match &inputs.log_inclusion {
        Some(li) => {
            // 1. Logger-pk pin. If supplied and the STH names a different
            //    logger, both flags fail with explicit notes and we skip
            //    further STH work — the auditor doesn't trust the head.
            let logger_pk_ok = match li.expected_logger_pk {
                Some(want) => {
                    if &li.sth.logger_pk == want {
                        true
                    } else {
                        notes.push((
                            "sth_signature_verified".into(),
                            format!(
                                "logger pubkey mismatch: sth={}, expected={}",
                                hex::encode(li.sth.logger_pk),
                                hex::encode(want)
                            ),
                        ));
                        notes.push((
                            "log_inclusion_verified".into(),
                            "not checked: STH bound to wrong logger".into(),
                        ));
                        false
                    }
                }
                None => true,
            };
            if logger_pk_ok {
                // 2. STH signature.
                if li.sth.verify() {
                    sth_signature_verified = true;
                } else {
                    notes.push((
                        "sth_signature_verified".into(),
                        "STH signature did not verify under bundled logger_pk".into(),
                    ));
                }
                // 3. Inclusion path. `verify_inclusion_against_head` also
                //    re-checks the STH signature internally, so an
                //    invalid signature here implies inclusion fails too —
                //    that's the desired structural coupling.
                match verify_inclusion_against_head(
                    li.sth,
                    li.proof,
                    li.expected_entry,
                    None,
                    li.expected_log_id,
                ) {
                    Ok(()) => log_inclusion_verified = true,
                    Err(e) => notes.push((
                        "log_inclusion_verified".into(),
                        format!("inclusion verification failed: {e}"),
                    )),
                }
            }
        }
        None => {
            notes.push((
                "log_inclusion_verified".into(),
                "not checked because --sth-url + --proof not provided".into(),
            ));
            notes.push((
                "sth_signature_verified".into(),
                "not checked because --sth-url not provided".into(),
            ));
        }
    }

    // ---- STH freshness ----
    let mut sth_freshness_verified = false;
    match &inputs.sth_freshness {
        Some(f) => {
            let age = f.now_unix.saturating_sub(f.sth_issued_at_unix);
            if age <= f.max_age_sec {
                sth_freshness_verified = true;
            } else {
                notes.push((
                    "sth_freshness_verified".into(),
                    format!(
                        "STH age {}s exceeds max-age {}s (issued_at={}, now={})",
                        age, f.max_age_sec, f.sth_issued_at_unix, f.now_unix
                    ),
                ));
            }
        }
        None => notes.push((
            "sth_freshness_verified".into(),
            "not checked because --sth-url not provided".into(),
        )),
    }

    // ---- Weight-commit pin ----
    let mut weight_commit_pinned = false;
    match &inputs.expected_weight_commit {
        Some(want) => {
            if hex::encode(want) == signed.receipt.weight_commit_hex {
                weight_commit_pinned = true;
            } else {
                notes.push((
                    "weight_commit_pinned".into(),
                    format!(
                        "weight_commit mismatch: receipt={}, expected={}",
                        signed.receipt.weight_commit_hex,
                        hex::encode(want)
                    ),
                ));
            }
        }
        None => notes.push((
            "weight_commit_pinned".into(),
            "not checked because --expected-weight-commit not provided".into(),
        )),
    }

    // ---- Session pin ----
    let mut session_pinned = false;
    match &inputs.expected_session {
        Some(want) => {
            if want == &signed.receipt.session.0 {
                session_pinned = true;
            } else {
                notes.push((
                    "session_pinned".into(),
                    format!(
                        "session mismatch: receipt={}, expected={}",
                        hex::encode(signed.receipt.session.0),
                        hex::encode(want)
                    ),
                ));
            }
        }
        None => notes.push((
            "session_pinned".into(),
            "not checked because --expected-session not provided".into(),
        )),
    }

    // ---- ZK proofs (structural presence check) ----
    let mut zk_proofs_verified = false;
    match &inputs.zk_layer_proofs {
        Some(proofs) => {
            if proofs.len() == NUM_LAYERS {
                zk_proofs_verified = true;
            } else {
                notes.push((
                    "zk_proofs_verified".into(),
                    format!(
                        "ZK proof count {} != NUM_LAYERS {}",
                        proofs.len(),
                        NUM_LAYERS
                    ),
                ));
            }
        }
        None => notes.push((
            "zk_proofs_verified".into(),
            "not checked because no ReceiptEnvelope ZK proofs supplied".into(),
        )),
    }

    // ---- Verdict ----
    let verdict = match divergent {
        Some(layer_idx) => Verdict::Fraudulent {
            divergent_layer: layer_idx,
        },
        None => {
            // Construct a partial report just to evaluate `is_fully_verified`.
            let probe = FraudReport {
                activations_consistent,
                receipt_signature_verified,
                attestation_verified,
                log_inclusion_verified,
                sth_signature_verified,
                sth_freshness_verified,
                weight_commit_pinned,
                session_pinned,
                zk_proofs_verified,
                session_hex: String::new(),
                tenant: String::new(),
                epoch: 0,
                verdict: Verdict::Partial,
                claimed_commits_hex: Vec::new(),
                recomputed_commits_hex: Vec::new(),
                weight_commit_hex: String::new(),
                notes: Vec::new(),
            };
            if Verdict::is_fully_verified(&probe) {
                Verdict::Honest
            } else {
                Verdict::Partial
            }
        }
    };

    Ok(FraudReport {
        activations_consistent,
        receipt_signature_verified,
        attestation_verified,
        log_inclusion_verified,
        sth_signature_verified,
        sth_freshness_verified,
        weight_commit_pinned,
        session_pinned,
        zk_proofs_verified,
        session_hex: hex::encode(signed.receipt.session.0),
        tenant: signed.receipt.tenant.0.clone(),
        epoch: signed.receipt.epoch,
        verdict,
        claimed_commits_hex: signed.receipt.activation_commits_hex.clone(),
        recomputed_commits_hex: recomputed.iter().map(hex::encode).collect(),
        weight_commit_hex: signed.receipt.weight_commit_hex.clone(),
        notes,
    })
}

fn decode_commits(hex_commits: &[String]) -> Result<Vec<[u8; 32]>, AuditError> {
    let mut out = Vec::with_capacity(hex_commits.len());
    for h in hex_commits {
        let b = hex::decode(h).map_err(|e| AuditError::BadHex(e.to_string()))?;
        let arr: [u8; 32] = b.as_slice().try_into().map_err(|_| AuditError::BadCommitLength)?;
        out.push(arr);
    }
    Ok(out)
}

/// Mirror of `ullm_tee::service::encode_prompt_to_fp`.
fn encode_prompt_to_fp(input_hash: &[u8; 32]) -> [Fp; VEC_DIM] {
    let mut out = [Fp::zero(); VEC_DIM];
    for i in 0..VEC_DIM {
        let off = i * 4;
        let v = u32::from_le_bytes([
            input_hash[off],
            input_hash[off + 1],
            input_hash[off + 2],
            input_hash[off + 3],
        ]);
        out[i] = Fp::from(v as u64);
    }
    out
}

/// Force imports for downstream type re-exports.
pub use ullm_receipts::Receipt;
