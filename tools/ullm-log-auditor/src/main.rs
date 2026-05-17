// SPDX-License-Identifier: Apache-2.0
//! `ullm-log-auditor` — verify a transparency-log STH + inclusion proof + witness cosignatures,
//! and detect log forks by comparing two STHs at the same tree size.
//!
//! Usage (verify mode, default):
//!   ullm-log-auditor \
//!     --sth path/to/sth.json \
//!     --proof path/to/proof.json \
//!     [--witness-keyset path/to/witnesses.json] \
//!     [--expected-logger <hex32>] \
//!     [--expected-log-id <string>]
//!
//! Usage (fork-detection):
//!   ullm-log-auditor compare-sths \
//!     --sth-a path/to/sth_a.json \
//!     --sth-b path/to/sth_b.json \
//!     --logger-pk <hex32>
//!
//! Exit codes:
//!   verify mode: 0 = valid, 1 = invalid, 2 = bad input
//!   compare-sths:
//!     0 = consistent (same size+root OR different sizes; no fork evidence)
//!     1 = FORK DETECTED (same size, different roots) — also exits 1 if
//!         either STH signature fails to verify
//!     2 = bad input
//!
//! `--expected-log-id` pins the STH's log-identifier (P2-6). An auditor
//! that omits it accepts any log_id, which is fine for local testing but
//! leaves cross-log replay un-checked in production.

use std::process::ExitCode;

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use ullm_transparency::{
    verify_inclusion_against_head, InclusionProof, LogEntry, SignedTreeHead, WitnessCosignature,
    WitnessKeyset,
};

/// P3-9: refuse symlinks supplied as CLI args. Operators can be tricked
/// into reading `/etc/passwd` (or any other file the auditor process can
/// open) by feeding `--sth /tmp/foo` where `/tmp/foo` is a symlink.
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

#[derive(serde::Deserialize)]
struct WitnessKeysetFile {
    threshold: usize,
    witnesses_hex: Vec<String>,
    cosignatures: Vec<WitnessCosignature>,
}

fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1);
    let first = argv.next();
    match first.as_deref() {
        Some("compare-sths") => compare_sths(argv),
        // Anything else is the verify-mode flag stream. Put the first
        // arg back at the head so the loop sees it.
        Some(_) | None => {
            let combined: Vec<String> = first.into_iter().chain(argv).collect();
            verify_mode(combined.into_iter())
        }
    }
}

fn verify_mode<I: Iterator<Item = String>>(mut args: I) -> ExitCode {
    let mut sth_path: Option<String> = None;
    let mut proof_path: Option<String> = None;
    let mut entry_path: Option<String> = None;
    let mut witness_path: Option<String> = None;
    let mut expected_logger_hex: Option<String> = None;
    let mut expected_log_id: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--sth" => sth_path = args.next(),
            "--proof" => proof_path = args.next(),
            "--entry" => entry_path = args.next(),
            "--witness-keyset" => witness_path = args.next(),
            "--expected-logger" => expected_logger_hex = args.next(),
            "--expected-log-id" => expected_log_id = args.next(),
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let sth_path = match sth_path {
        Some(s) => s,
        None => {
            eprintln!("--sth required");
            return ExitCode::from(2);
        }
    };
    let proof_path = match proof_path {
        Some(s) => s,
        None => {
            eprintln!("--proof required");
            return ExitCode::from(2);
        }
    };

    let sth_bytes = match read_regular_file(&sth_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let sth: SignedTreeHead = match serde_json::from_slice(&sth_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("parse STH: {e}");
            return ExitCode::from(2);
        }
    };

    let proof_bytes = match read_regular_file(&proof_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let proof: InclusionProof = match serde_json::from_slice(&proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse proof: {e}");
            return ExitCode::from(2);
        }
    };

    // P2-4: the entry being audited must be supplied separately so the
    // proof binds to a known leaf — not just "some leaf whose hash matches
    // the root." `--entry` is required; without it we can't safely audit.
    let entry_path = match entry_path {
        Some(s) => s,
        None => {
            eprintln!("--entry required (path to the LogEntry JSON being audited)");
            return ExitCode::from(2);
        }
    };
    let entry_bytes = match read_regular_file(&entry_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let expected_entry: LogEntry = match serde_json::from_slice(&entry_bytes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("parse entry: {e}");
            return ExitCode::from(2);
        }
    };

    if let Some(hex_str) = expected_logger_hex {
        let bytes = match hex::decode(&hex_str) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("expected-logger hex: {e}");
                return ExitCode::from(2);
            }
        };
        if bytes != sth.logger_pk {
            eprintln!(
                "logger mismatch: sth has {}, expected {hex_str}",
                hex::encode(sth.logger_pk)
            );
            return ExitCode::from(1);
        }
    }

    let (keyset_opt, cosigs_owned);
    let cosigs_borrow: &[WitnessCosignature];
    if let Some(p) = witness_path {
        let raw = match read_regular_file(&p) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        let file: WitnessKeysetFile = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("parse witnesses: {e}");
                return ExitCode::from(2);
            }
        };
        let mut keys: Vec<VerifyingKey> = Vec::with_capacity(file.witnesses_hex.len());
        for h in &file.witnesses_hex {
            let bytes = match hex::decode(h) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("witness hex: {e}");
                    return ExitCode::from(2);
                }
            };
            let arr: [u8; 32] = match bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("witness key must be 32 bytes");
                    return ExitCode::from(2);
                }
            };
            match VerifyingKey::from_bytes(&arr) {
                Ok(k) => keys.push(k),
                Err(e) => {
                    eprintln!("witness key parse: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        keyset_opt = Some(WitnessKeyset {
            witnesses: keys,
            threshold: file.threshold,
        });
        cosigs_owned = file.cosignatures;
        cosigs_borrow = &cosigs_owned;
    } else {
        keyset_opt = None;
        cosigs_owned = Vec::new();
        cosigs_borrow = &cosigs_owned;
    }

    let result = verify_inclusion_against_head(
        &sth,
        &proof,
        &expected_entry,
        keyset_opt.as_ref().map(|k| (k, cosigs_borrow)),
        expected_log_id.as_deref(),
    );
    match result {
        Ok(()) => {
            println!(
                "{}",
                serde_json::json!({
                    "verdict": "valid",
                    "size": sth.head.size,
                    "root_hex": sth.head.root_hex,
                    "leaf_seq": proof.seq,
                })
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({
                    "verdict": "invalid",
                    "reason": e.to_string(),
                })
            );
            ExitCode::from(1)
        }
    }
}

/// `compare-sths` subcommand. P13-FIX-B: detect transparency-log forks.
/// A fork is two STHs at the same tree size advertising different roots
/// — that's logger equivocation, and the prior auditor binary had no
/// way to surface it. We require `--logger-pk` because the comparison
/// is only meaningful when both STHs are bound to the same logger
/// identity; otherwise an attacker could supply two unrelated STHs from
/// different loggers and claim "fork."
fn compare_sths<I: Iterator<Item = String>>(mut args: I) -> ExitCode {
    let mut a_path: Option<String> = None;
    let mut b_path: Option<String> = None;
    let mut logger_hex: Option<String> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--sth-a" => a_path = args.next(),
            "--sth-b" => b_path = args.next(),
            "--logger-pk" => logger_hex = args.next(),
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let a_path = match a_path {
        Some(p) => p,
        None => {
            eprintln!("compare-sths: --sth-a required");
            return ExitCode::from(2);
        }
    };
    let b_path = match b_path {
        Some(p) => p,
        None => {
            eprintln!("compare-sths: --sth-b required");
            return ExitCode::from(2);
        }
    };
    let logger_hex = match logger_hex {
        Some(h) => h,
        None => {
            eprintln!("compare-sths: --logger-pk required (32-byte hex)");
            return ExitCode::from(2);
        }
    };
    let logger_bytes: [u8; 32] = match hex::decode(&logger_hex) {
        Ok(b) => match b.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("compare-sths: --logger-pk must decode to exactly 32 bytes");
                return ExitCode::from(2);
            }
        },
        Err(e) => {
            eprintln!("compare-sths: --logger-pk hex: {e}");
            return ExitCode::from(2);
        }
    };

    let a_bytes = match read_regular_file(&a_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let b_bytes = match read_regular_file(&b_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let sth_a: SignedTreeHead = match serde_json::from_slice(&a_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("compare-sths: parse sth-a: {e}");
            return ExitCode::from(2);
        }
    };
    let sth_b: SignedTreeHead = match serde_json::from_slice(&b_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("compare-sths: parse sth-b: {e}");
            return ExitCode::from(2);
        }
    };

    // Both STHs must carry the expected logger pubkey and verify under
    // that key. Bad signatures or wrong pubkeys → exit 1 (invalid input
    // for fork analysis; we don't want to silently call "consistent"
    // when one STH is unsigned).
    if sth_a.logger_pk != logger_bytes {
        println!(
            "{}",
            serde_json::json!({
                "verdict": "invalid",
                "reason": "sth-a logger_pk does not match --logger-pk",
                "sth_a_logger_pk_hex": hex::encode(sth_a.logger_pk),
            })
        );
        return ExitCode::from(1);
    }
    if sth_b.logger_pk != logger_bytes {
        println!(
            "{}",
            serde_json::json!({
                "verdict": "invalid",
                "reason": "sth-b logger_pk does not match --logger-pk",
                "sth_b_logger_pk_hex": hex::encode(sth_b.logger_pk),
            })
        );
        return ExitCode::from(1);
    }
    if !sth_a.verify() {
        println!(
            "{}",
            serde_json::json!({
                "verdict": "invalid",
                "reason": "sth-a signature did not verify",
            })
        );
        return ExitCode::from(1);
    }
    if !sth_b.verify() {
        println!(
            "{}",
            serde_json::json!({
                "verdict": "invalid",
                "reason": "sth-b signature did not verify",
            })
        );
        return ExitCode::from(1);
    }

    if sth_a.head.size == sth_b.head.size && sth_a.head.root_hex != sth_b.head.root_hex {
        // FORK: equivocation by the logger. Emit both heads in full so a
        // downstream system can rebroadcast them as evidence.
        println!(
            "{}",
            serde_json::json!({
                "verdict": "fork_detected",
                "size": sth_a.head.size,
                "sth_a": {
                    "root_hex": sth_a.head.root_hex,
                    "issued_at_unix": sth_a.head.issued_at_unix,
                    "log_id": sth_a.head.log_id,
                    "signature_hex": hex::encode(sth_a.signature),
                },
                "sth_b": {
                    "root_hex": sth_b.head.root_hex,
                    "issued_at_unix": sth_b.head.issued_at_unix,
                    "log_id": sth_b.head.log_id,
                    "signature_hex": hex::encode(sth_b.signature),
                },
                "logger_pk_hex": hex::encode(logger_bytes),
            })
        );
        return ExitCode::from(1);
    }

    // No fork evidence. Two STHs at the same size with the same root, or
    // at different sizes (which is consistent with an append-only log
    // even though we cannot prove it without a consistency proof; see
    // FOLLOWUP below).
    let note = if sth_a.head.size == sth_b.head.size {
        "same size, same root"
    } else {
        "different sizes — no fork evidence; consistency proof recommended"
    };
    println!(
        "{}",
        serde_json::json!({
            "verdict": "consistent",
            "note": note,
            "sth_a_size": sth_a.head.size,
            "sth_b_size": sth_b.head.size,
            "sth_a_root_hex": sth_a.head.root_hex,
            "sth_b_root_hex": sth_b.head.root_hex,
        })
    );
    ExitCode::SUCCESS
}
