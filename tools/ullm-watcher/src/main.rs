// SPDX-License-Identifier: Apache-2.0
//! `ullm-watcher` binary.
//!
//! Usage:
//!   ullm-watcher \
//!     --model-seed <hex32> \
//!     --tee-pk <hex32> \
//!     --prompt <utf8 string> \
//!     --receipt <path/to/signed_receipt.postcard> \
//!     [--attestation-evidence <path/to/evidence.postcard>] \
//!     [--attestation-report-data <hex64>] \
//!     [--attestation-now <unix-secs>] \
//!     [--attestation-max-age-secs <N>] \
//!     [--sth-url <path-or-file://>] \
//!     [--proof <path/to/inclusion_proof.json>] \
//!     [--log-entry <path/to/entry.json>] \
//!     [--expected-log-id <string>] \
//!     [--logger-pk <hex32>] \
//!     [--freshness-now <unix-secs>] \
//!     [--freshness-max-age-secs <N>] \
//!     [--expected-weight-commit <hex32>] \
//!     [--expected-session <hex16>] \
//!     [--zk-envelope]
//!
//! Prints a JSON `FraudReport`.
//!
//! Exit codes:
//!   0 = `Honest` (all supplied checks passed and recompute matches)
//!   1 = `Fraudulent` (activation recompute diverged)
//!   2 = I/O or parse errors
//!   3 = `Partial` (recompute matched but one or more optional checks failed
//!       OR the caller didn't supply enough inputs for "fully verified")
//!
//! The `Partial` exit code is new in P13-FIX-B: the prior contract returned
//! `Honest` (exit 0) whenever activations recomputed correctly, regardless
//! of whether the watcher had any evidence about attestation, log
//! inclusion, or freshness. That was misleading. Operators that want the
//! old "best-effort" behaviour can run without the optional flags and
//! treat exit 3 the same as exit 0; production deployments should reject
//! anything that isn't exit 0.

use std::path::Path;
use std::process::ExitCode;

use ed25519_dalek::VerifyingKey;
use ullm_attest::{Evidence, MeasurementPolicy};
use ullm_receipts::{ReceiptEnvelope, SignedReceipt};
use ullm_transparency::{InclusionProof, LogEntry, SignedTreeHead};
use ullm_watcher::{
    audit_with, AttestationCheck, AuditInputs, LogInclusionCheck, SthFreshnessCheck, Verdict,
};

/// P3-9: refuse to follow symlinks supplied as CLI arguments. Operators
/// can be tricked into running `ullm-watcher --receipt /tmp/foo` where
/// `/tmp/foo` is a symlink to `/etc/passwd` or another secret on disk.
/// We open only regular files via their literal path.
fn read_regular_file(path: &str) -> Result<Vec<u8>, String> {
    let p = Path::new(path);
    let meta = std::fs::symlink_metadata(p)
        .map_err(|e| format!("symlink_metadata {path}: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing to read {path}: path is a symlink (P3-9 hardening)"
        ));
    }
    if !meta.is_file() {
        return Err(format!("refusing to read {path}: not a regular file"));
    }
    std::fs::read(p).map_err(|e| format!("read {path}: {e}"))
}

/// `--sth-url` may be a bare path or a `file://` URL. We deliberately do
/// NOT pull in an HTTP client just for the watcher — operators that need
/// to fetch over the wire should pipe `curl` into a temp file and pass
/// the path. This keeps the watcher's dependency surface small (matters
/// for supply-chain hardening: P12-E flagged the per-binary footprint).
fn resolve_sth_path(value: &str) -> Result<String, String> {
    if let Some(rest) = value.strip_prefix("file://") {
        // Strip a leading slash on Windows so `file:///C:/...` works.
        #[cfg(windows)]
        {
            if let Some(without) = rest.strip_prefix('/') {
                return Ok(without.to_string());
            }
        }
        Ok(rest.to_string())
    } else if value.starts_with("http://") || value.starts_with("https://") {
        Err(format!(
            "--sth-url: http(s):// URLs are not fetched by the watcher (curl into a temp file and pass the path or a file:// URL). Got: {value}"
        ))
    } else {
        Ok(value.to_string())
    }
}

fn bail2(msg: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", msg.as_ref());
    ExitCode::from(2)
}

fn parse_hex32(flag: &str, v: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(v).map_err(|e| format!("{flag}: invalid hex ({e})"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{flag}: must decode to exactly 32 bytes, got {}", bytes.len()))
}

fn parse_hex16(flag: &str, v: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(v).map_err(|e| format!("{flag}: invalid hex ({e})"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{flag}: must decode to exactly 16 bytes, got {}", bytes.len()))
}

fn parse_hex64(flag: &str, v: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(v).map_err(|e| format!("{flag}: invalid hex ({e})"))?;
    let arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{flag}: must decode to exactly 64 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut seed: Option<[u8; 32]> = None;
    let mut tee_pk: Option<VerifyingKey> = None;
    let mut prompt: Option<Vec<u8>> = None;
    let mut receipt_path: Option<String> = None;

    let mut attestation_evidence_path: Option<String> = None;
    let mut attestation_report_data: Option<[u8; 64]> = None;
    let mut attestation_now: Option<u64> = None;
    let mut attestation_max_age: u64 = 600;

    let mut sth_path: Option<String> = None;
    let mut proof_path: Option<String> = None;
    let mut log_entry_path: Option<String> = None;
    let mut expected_log_id: Option<String> = None;
    let mut logger_pk: Option<[u8; 32]> = None;

    let mut freshness_now: Option<u64> = None;
    let mut freshness_max_age: u64 = 600;

    let mut expected_weight_commit: Option<[u8; 32]> = None;
    let mut expected_session: Option<[u8; 16]> = None;
    let mut zk_envelope: bool = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--model-seed" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match parse_hex32("--model-seed", &v) {
                    Ok(s) => seed = Some(s),
                    Err(e) => return bail2(e),
                }
            }
            "--tee-pk" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                let arr = match parse_hex32("--tee-pk", &v) {
                    Ok(a) => a,
                    Err(e) => return bail2(e),
                };
                tee_pk = Some(match VerifyingKey::from_bytes(&arr) {
                    Ok(k) => k,
                    Err(e) => return bail2(format!("--tee-pk: not a valid Ed25519 key: {e}")),
                });
            }
            "--prompt" => match next_value(&mut args, &flag) {
                Ok(v) => prompt = Some(v.into_bytes()),
                Err(e) => return bail2(e),
            },
            "--receipt" => match next_value(&mut args, &flag) {
                Ok(v) => receipt_path = Some(v),
                Err(e) => return bail2(e),
            },
            "--attestation-evidence" => match next_value(&mut args, &flag) {
                Ok(v) => attestation_evidence_path = Some(v),
                Err(e) => return bail2(e),
            },
            "--attestation-report-data" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match parse_hex64("--attestation-report-data", &v) {
                    Ok(a) => attestation_report_data = Some(a),
                    Err(e) => return bail2(e),
                }
            }
            "--attestation-now" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match v.parse::<u64>() {
                    Ok(n) => attestation_now = Some(n),
                    Err(e) => return bail2(format!("--attestation-now: {e}")),
                }
            }
            "--attestation-max-age-secs" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match v.parse::<u64>() {
                    Ok(n) => attestation_max_age = n,
                    Err(e) => return bail2(format!("--attestation-max-age-secs: {e}")),
                }
            }
            "--sth-url" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match resolve_sth_path(&v) {
                    Ok(p) => sth_path = Some(p),
                    Err(e) => return bail2(e),
                }
            }
            "--proof" => match next_value(&mut args, &flag) {
                Ok(v) => proof_path = Some(v),
                Err(e) => return bail2(e),
            },
            "--log-entry" => match next_value(&mut args, &flag) {
                Ok(v) => log_entry_path = Some(v),
                Err(e) => return bail2(e),
            },
            "--expected-log-id" => match next_value(&mut args, &flag) {
                Ok(v) => expected_log_id = Some(v),
                Err(e) => return bail2(e),
            },
            "--logger-pk" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match parse_hex32("--logger-pk", &v) {
                    Ok(a) => logger_pk = Some(a),
                    Err(e) => return bail2(e),
                }
            }
            "--freshness-now" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match v.parse::<u64>() {
                    Ok(n) => freshness_now = Some(n),
                    Err(e) => return bail2(format!("--freshness-now: {e}")),
                }
            }
            "--freshness-max-age-secs" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match v.parse::<u64>() {
                    Ok(n) => freshness_max_age = n,
                    Err(e) => return bail2(format!("--freshness-max-age-secs: {e}")),
                }
            }
            "--expected-weight-commit" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match parse_hex32("--expected-weight-commit", &v) {
                    Ok(a) => expected_weight_commit = Some(a),
                    Err(e) => return bail2(e),
                }
            }
            "--expected-session" => {
                let v = match next_value(&mut args, &flag) {
                    Ok(v) => v,
                    Err(e) => return bail2(e),
                };
                match parse_hex16("--expected-session", &v) {
                    Ok(a) => expected_session = Some(a),
                    Err(e) => return bail2(e),
                }
            }
            "--zk-envelope" => {
                // The receipt path then must point at a `ReceiptEnvelope`
                // (postcard) rather than a bare `SignedReceipt`. Toggle
                // is explicit because the envelope is a strict superset.
                zk_envelope = true;
            }
            other => return bail2(format!("unknown arg: {other}")),
        }
    }

    let seed = match seed {
        Some(s) => s,
        None => return bail2("--model-seed required"),
    };
    let tee_pk = match tee_pk {
        Some(k) => k,
        None => return bail2("--tee-pk required"),
    };
    let prompt = match prompt {
        Some(p) => p,
        None => return bail2("--prompt required"),
    };
    let receipt_path = match receipt_path {
        Some(p) => p,
        None => return bail2("--receipt required"),
    };
    let receipt_bytes = match read_regular_file(&receipt_path) {
        Ok(b) => b,
        Err(e) => return bail2(e),
    };

    let (signed, zk_layer_proofs_owned): (SignedReceipt, Option<Vec<Vec<u8>>>) = if zk_envelope {
        let env: ReceiptEnvelope = match postcard::from_bytes(&receipt_bytes) {
            Ok(e) => e,
            Err(e) => return bail2(format!("--receipt: postcard ReceiptEnvelope decode failed: {e}")),
        };
        (env.signed_receipt, Some(env.zk_layer_proofs))
    } else {
        let s: SignedReceipt = match postcard::from_bytes(&receipt_bytes) {
            Ok(s) => s,
            Err(e) => return bail2(format!("--receipt: postcard decode failed: {e}")),
        };
        (s, None)
    };

    // Load attestation evidence (and optional report-data) if supplied.
    let evidence_owned: Option<Evidence> = match attestation_evidence_path.as_deref() {
        Some(p) => {
            let b = match read_regular_file(p) {
                Ok(b) => b,
                Err(e) => return bail2(e),
            };
            match postcard::from_bytes::<Evidence>(&b) {
                Ok(e) => Some(e),
                Err(e) => return bail2(format!("--attestation-evidence: postcard decode failed: {e}")),
            }
        }
        None => None,
    };

    // The expected_report_data field is required by RealVerifier. If the
    // operator didn't pin it explicitly, we fall back to the evidence's
    // own value — which collapses the channel-binding check to "the
    // quote names itself" (trivially true). We loudly flag this so the
    // operator knows they got a degraded check.
    let report_data_pinned;
    let report_data_buf: [u8; 64] = match (attestation_report_data, &evidence_owned) {
        (Some(rd), _) => {
            report_data_pinned = true;
            rd
        }
        (None, Some(ev)) => {
            report_data_pinned = false;
            ev.report_data
        }
        (None, None) => {
            report_data_pinned = false;
            [0u8; 64]
        }
    };

    // STH bundle.
    let sth_owned: Option<SignedTreeHead> = match sth_path.as_deref() {
        Some(p) => {
            let b = match read_regular_file(p) {
                Ok(b) => b,
                Err(e) => return bail2(e),
            };
            match serde_json::from_slice(&b) {
                Ok(s) => Some(s),
                Err(e) => return bail2(format!("--sth-url: JSON decode failed: {e}")),
            }
        }
        None => None,
    };
    let proof_owned: Option<InclusionProof> = match proof_path.as_deref() {
        Some(p) => {
            let b = match read_regular_file(p) {
                Ok(b) => b,
                Err(e) => return bail2(e),
            };
            match serde_json::from_slice(&b) {
                Ok(s) => Some(s),
                Err(e) => return bail2(format!("--proof: JSON decode failed: {e}")),
            }
        }
        None => None,
    };
    let log_entry_owned: Option<LogEntry> = match log_entry_path.as_deref() {
        Some(p) => {
            let b = match read_regular_file(p) {
                Ok(b) => b,
                Err(e) => return bail2(e),
            };
            match serde_json::from_slice(&b) {
                Ok(s) => Some(s),
                Err(e) => return bail2(format!("--log-entry: JSON decode failed: {e}")),
            }
        }
        None => None,
    };

    // Build AuditInputs.
    let mut inputs = AuditInputs::default();
    if let Some(ev) = evidence_owned.as_ref() {
        let now = attestation_now.unwrap_or(ev.issued_at_unix);
        inputs.attestation = Some(AttestationCheck {
            evidence: ev,
            policy: MeasurementPolicy::default(),
            expected_report_data: &report_data_buf,
            now_unix: now,
            max_age_sec: attestation_max_age,
            require_signature_check: false,
        });
    }
    // STH freshness — only check when an STH is supplied.
    let freshness_holder: Option<SthFreshnessCheck> = sth_owned.as_ref().map(|s| {
        SthFreshnessCheck {
            sth_issued_at_unix: s.head.issued_at_unix,
            now_unix: freshness_now.unwrap_or(s.head.issued_at_unix),
            max_age_sec: freshness_max_age,
        }
    });
    if let Some(f) = freshness_holder {
        inputs.sth_freshness = Some(f);
    }
    // Log inclusion bundle. All three (sth, proof, log-entry) are needed.
    if let (Some(sth_ref), Some(proof_ref), Some(entry_ref)) = (
        sth_owned.as_ref(),
        proof_owned.as_ref(),
        log_entry_owned.as_ref(),
    ) {
        inputs.log_inclusion = Some(LogInclusionCheck {
            sth: sth_ref,
            proof: proof_ref,
            expected_entry: entry_ref,
            expected_log_id: expected_log_id.as_deref(),
            expected_logger_pk: logger_pk.as_ref(),
        });
    }
    inputs.expected_weight_commit = expected_weight_commit;
    inputs.expected_session = expected_session;
    if let Some(proofs) = zk_layer_proofs_owned.as_deref() {
        inputs.zk_layer_proofs = Some(proofs);
    }

    let report = match audit_with(&seed, &tee_pk, &prompt, &signed, inputs) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("audit error: {e}");
            return ExitCode::from(2);
        }
    };

    if !report_data_pinned && report.attestation_verified {
        eprintln!(
            "WARNING: attestation channel-binding check was degraded (no --attestation-report-data supplied; the evidence's own report_data was used as the pin)"
        );
    }

    println!("{}", serde_json::to_string_pretty(&report).expect("json"));
    match report.verdict {
        Verdict::Honest => ExitCode::SUCCESS,
        Verdict::Fraudulent { .. } => ExitCode::from(1),
        Verdict::Partial => ExitCode::from(3),
    }
}
