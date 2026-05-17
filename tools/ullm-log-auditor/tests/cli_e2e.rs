// SPDX-License-Identifier: Apache-2.0
//! End-to-end CLI exercise for the transparency-log auditor binary.

use std::process::Command;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ullm_transparency::{
    InclusionProof, SignedTreeHead, TransparencyLog, TreeHead, WitnessCosignature,
};

fn auditor_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop();
    p.pop();
    p.push(if cfg!(windows) {
        "ullm-log-auditor.exe"
    } else {
        "ullm-log-auditor"
    });
    p
}

fn write_json<T: serde::Serialize>(value: &T) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ullm-audit-{}.json", rand::random::<u64>()));
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

#[test]
fn auditor_accepts_well_formed_inputs() {
    let log = TransparencyLog::new();
    for i in 0..5 {
        log.append([i; 32], &[i, i + 1], 100 + i as u64).unwrap();
    }
    let entries = log.snapshot();
    let root = ullm_transparency::merkle_root(&entries);
    let head = TreeHead {
        size: entries.len() as u64,
        root_hex: hex::encode(root),
        issued_at_unix: 1000,
        log_id: "ullm-test-log".into(),
    };
    let logger = SigningKey::generate(&mut OsRng);
    let sth = SignedTreeHead::sign(head, &logger);
    let proof = InclusionProof::build(&entries, 2).unwrap();

    let sth_path = write_json(&sth);
    let proof_path = write_json(&proof);
    let entry_path = write_json(&entries[2]);
    let out = Command::new(auditor_bin())
        .arg("--sth")
        .arg(&sth_path)
        .arg("--proof")
        .arg(&proof_path)
        .arg("--entry")
        .arg(&entry_path)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected success; stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("\"verdict\":\"valid\""), "stdout: {stdout}");

    std::fs::remove_file(sth_path).ok();
    std::fs::remove_file(proof_path).ok();
    std::fs::remove_file(entry_path).ok();
}

#[test]
fn auditor_rejects_tampered_proof() {
    let log = TransparencyLog::new();
    for i in 0..3 {
        log.append([i; 32], &[i], 100 + i as u64).unwrap();
    }
    let entries = log.snapshot();
    let root = ullm_transparency::merkle_root(&entries);
    let head = TreeHead {
        size: entries.len() as u64,
        root_hex: hex::encode(root),
        issued_at_unix: 1,
        log_id: "ullm-test-log".into(),
    };
    let logger = SigningKey::generate(&mut OsRng);
    let sth = SignedTreeHead::sign(head, &logger);
    let mut proof = InclusionProof::build(&entries, 1).unwrap();
    // Flip a hex character in the leaf hash.
    let mut chars: Vec<char> = proof.leaf_hash_hex.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    proof.leaf_hash_hex = chars.into_iter().collect();

    let sth_path = write_json(&sth);
    let proof_path = write_json(&proof);
    let entry_path = write_json(&entries[1]);
    let out = Command::new(auditor_bin())
        .arg("--sth")
        .arg(&sth_path)
        .arg("--proof")
        .arg(&proof_path)
        .arg("--entry")
        .arg(&entry_path)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"verdict\":\"invalid\""), "stdout: {stdout}");

    std::fs::remove_file(sth_path).ok();
    std::fs::remove_file(proof_path).ok();
    std::fs::remove_file(entry_path).ok();
}

#[test]
fn auditor_enforces_witness_threshold() {
    let log = TransparencyLog::new();
    for i in 0..4 {
        log.append([i; 32], &[i], 100 + i as u64).unwrap();
    }
    let entries = log.snapshot();
    let root = ullm_transparency::merkle_root(&entries);
    let head = TreeHead {
        size: entries.len() as u64,
        root_hex: hex::encode(root),
        issued_at_unix: 1,
        log_id: "ullm-test-log".into(),
    };
    let logger = SigningKey::generate(&mut OsRng);
    let sth = SignedTreeHead::sign(head, &logger);
    let proof = InclusionProof::build(&entries, 0).unwrap();

    let w0 = SigningKey::generate(&mut OsRng);
    let w1 = SigningKey::generate(&mut OsRng);
    let w2 = SigningKey::generate(&mut OsRng);
    let cosigs = vec![
        WitnessCosignature::cosign(&sth, &w0),
        WitnessCosignature::cosign(&sth, &w1),
    ];
    let witness_file = serde_json::json!({
        "threshold": 2,
        "witnesses_hex": [
            hex::encode(w0.verifying_key().as_bytes()),
            hex::encode(w1.verifying_key().as_bytes()),
            hex::encode(w2.verifying_key().as_bytes()),
        ],
        "cosignatures": cosigs,
    });

    let sth_path = write_json(&sth);
    let proof_path = write_json(&proof);
    let entry_path = write_json(&entries[0]);
    let witness_path = write_json(&witness_file);
    let out = Command::new(auditor_bin())
        .arg("--sth")
        .arg(&sth_path)
        .arg("--proof")
        .arg(&proof_path)
        .arg("--entry")
        .arg(&entry_path)
        .arg("--witness-keyset")
        .arg(&witness_path)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");

    // Below-threshold case: only one valid cosignature.
    let witness_file_bad = serde_json::json!({
        "threshold": 2,
        "witnesses_hex": [
            hex::encode(w0.verifying_key().as_bytes()),
            hex::encode(w1.verifying_key().as_bytes()),
            hex::encode(w2.verifying_key().as_bytes()),
        ],
        "cosignatures": vec![WitnessCosignature::cosign(&sth, &w0)],
    });
    let bad_path = write_json(&witness_file_bad);
    let out2 = Command::new(auditor_bin())
        .arg("--sth")
        .arg(&sth_path)
        .arg("--proof")
        .arg(&proof_path)
        .arg("--entry")
        .arg(&entry_path)
        .arg("--witness-keyset")
        .arg(&bad_path)
        .output()
        .expect("spawn");
    assert_eq!(out2.status.code(), Some(1));

    for p in [sth_path, proof_path, entry_path, witness_path, bad_path] {
        std::fs::remove_file(p).ok();
    }
}

/// P13-FIX-B: `compare-sths` subcommand. Two STHs at the same tree size
/// with different roots is logger equivocation. The auditor must surface
/// it as `verdict: "fork_detected"` and exit 1.
#[test]
fn auditor_compare_sths_detects_fork() {
    let logger = SigningKey::generate(&mut OsRng);
    let logger_pk_hex = hex::encode(logger.verifying_key().as_bytes());

    let head_a = TreeHead {
        size: 7,
        root_hex: "aa".repeat(32),
        issued_at_unix: 1_700_000_000,
        log_id: "ullm-test-log".into(),
    };
    let head_b = TreeHead {
        size: 7,
        root_hex: "bb".repeat(32), // same size, DIFFERENT root → fork
        issued_at_unix: 1_700_000_100,
        log_id: "ullm-test-log".into(),
    };
    let sth_a = SignedTreeHead::sign(head_a, &logger);
    let sth_b = SignedTreeHead::sign(head_b, &logger);

    let path_a = write_json(&sth_a);
    let path_b = write_json(&sth_b);
    let out = Command::new(auditor_bin())
        .arg("compare-sths")
        .arg("--sth-a")
        .arg(&path_a)
        .arg("--sth-b")
        .arg(&path_b)
        .arg("--logger-pk")
        .arg(&logger_pk_hex)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for fork; stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("\"fork_detected\""),
        "stdout: {stdout}"
    );
    assert!(stdout.contains(&"aa".repeat(32)), "stdout: {stdout}");
    assert!(stdout.contains(&"bb".repeat(32)), "stdout: {stdout}");
    std::fs::remove_file(path_a).ok();
    std::fs::remove_file(path_b).ok();
}

/// `compare-sths` on two identical-root, identical-size STHs is reported
/// `consistent` and exits 0.
#[test]
fn auditor_compare_sths_consistent_same_root() {
    let logger = SigningKey::generate(&mut OsRng);
    let logger_pk_hex = hex::encode(logger.verifying_key().as_bytes());

    let head = TreeHead {
        size: 5,
        root_hex: "cc".repeat(32),
        issued_at_unix: 1_700_000_000,
        log_id: "ullm-test-log".into(),
    };
    let sth_a = SignedTreeHead::sign(head.clone(), &logger);
    let sth_b = SignedTreeHead::sign(head, &logger);

    let path_a = write_json(&sth_a);
    let path_b = write_json(&sth_b);
    let out = Command::new(auditor_bin())
        .arg("compare-sths")
        .arg("--sth-a")
        .arg(&path_a)
        .arg("--sth-b")
        .arg(&path_b)
        .arg("--logger-pk")
        .arg(&logger_pk_hex)
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stdout: {}", String::from_utf8_lossy(&out.stdout));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"consistent\""), "stdout: {stdout}");
    std::fs::remove_file(path_a).ok();
    std::fs::remove_file(path_b).ok();
}

/// `compare-sths` with a wrong `--logger-pk` for one of the STHs must
/// reject (exit 1) — the comparison is only meaningful when both heads
/// share the same logger identity.
#[test]
fn auditor_compare_sths_rejects_logger_mismatch() {
    let logger_a = SigningKey::generate(&mut OsRng);
    let logger_b = SigningKey::generate(&mut OsRng);
    // Pin to logger A's key, but feed in an STH from logger B.
    let logger_a_pk_hex = hex::encode(logger_a.verifying_key().as_bytes());

    let head = TreeHead {
        size: 3,
        root_hex: "dd".repeat(32),
        issued_at_unix: 1_700_000_000,
        log_id: "ullm-test-log".into(),
    };
    let sth_a = SignedTreeHead::sign(head.clone(), &logger_a);
    let sth_b = SignedTreeHead::sign(head, &logger_b);

    let path_a = write_json(&sth_a);
    let path_b = write_json(&sth_b);
    let out = Command::new(auditor_bin())
        .arg("compare-sths")
        .arg("--sth-a")
        .arg(&path_a)
        .arg("--sth-b")
        .arg(&path_b)
        .arg("--logger-pk")
        .arg(&logger_a_pk_hex)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"invalid\""),
        "stdout: {stdout}"
    );
    std::fs::remove_file(path_a).ok();
    std::fs::remove_file(path_b).ok();
}
