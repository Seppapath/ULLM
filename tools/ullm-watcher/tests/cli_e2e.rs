// SPDX-License-Identifier: Apache-2.0
//! End-to-end CLI exercise.
//!
//! P13-FIX-B reshaped the watcher's exit-code contract: the binary now
//! distinguishes "all checks passed" (0 = `Honest`) from "recompute
//! matched but the caller didn't supply enough optional evidence" (3 =
//! `Partial`). The legacy assertion that an honest receipt with NO
//! supplementary inputs returns 0 is wrong against the new contract —
//! these tests reflect the new semantics and add coverage for each new
//! flag.

use std::process::Command;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use ullm_core::{SessionId, TenantId};
use ullm_model::{vector_commit, Model, NUM_LAYERS, VEC_DIM};
use ullm_receipts::{Receipt, ReceiptSigner};
use ullm_transparency::{InclusionProof, SignedTreeHead, TransparencyLog, TreeHead};
use ullm_zk::Fp;

fn watcher_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe path");
    // …/target/<profile>/deps/<thistest>.exe → strip "deps" and exe name.
    p.pop();
    p.pop();
    p.push(if cfg!(windows) { "ullm-watcher.exe" } else { "ullm-watcher" });
    p
}

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

fn make_receipt(
    prompt: &[u8],
    seed: [u8; 32],
    session: [u8; 16],
    tamper_layer: Option<usize>,
) -> (Vec<u8>, SigningKey) {
    let model = Model::from_seed(&seed);
    let input_hash: [u8; 32] = Sha256::digest(prompt).into();
    let model_input = encode_prompt_to_fp(&input_hash);
    let trace = model.run(model_input);
    let mut commits: Vec<String> = trace
        .activations
        .iter()
        .map(|v| hex::encode(vector_commit(v)))
        .collect();
    if let Some(idx) = tamper_layer {
        commits[idx] = "00".repeat(32);
    }

    let receipt = Receipt {
        tenant: TenantId("cli-test".into()),
        session: SessionId(session),
        model: "mock".into(),
        input_tokens: 1,
        output_tokens: 1,
        epoch: 0,
        issued_at_unix: 1_700_000_000,
        kv_blocks_cloaked: 0,
        output_digest_hex: "00".repeat(32),
        output_string_digest_hex: "44".repeat(32),
        weight_commit_hex: hex::encode(model.weight_commit()),
        activation_commits_hex: commits,
    };
    let sk = SigningKey::generate(&mut OsRng);
    let signer = ReceiptSigner::new(sk.clone());
    let signed = signer
        .sign(receipt)
        .expect("test fixture receipt is structurally valid");
    let bytes = postcard::to_allocvec(&signed).expect("postcard");
    (bytes, sk)
}

fn run_watcher_min(
    receipt_bytes: &[u8],
    tee_pk_hex: &str,
    seed_hex: &str,
    prompt: &str,
) -> std::process::Output {
    let tmp = std::env::temp_dir().join(format!("ullm-e2e-{}.bin", rand::random::<u64>()));
    std::fs::write(&tmp, receipt_bytes).expect("write tempfile");
    let out = Command::new(watcher_bin())
        .arg("--model-seed")
        .arg(seed_hex)
        .arg("--tee-pk")
        .arg(tee_pk_hex)
        .arg("--prompt")
        .arg(prompt)
        .arg("--receipt")
        .arg(&tmp)
        .output()
        .expect("spawn watcher");
    std::fs::remove_file(&tmp).ok();
    out
}

#[test]
fn watcher_cli_no_optional_inputs_returns_three_with_partial_verdict() {
    // Without --sth-url, --attestation-evidence, etc., the recompute still
    // matches and the signature still verifies, but the new contract
    // declines to call the receipt fully verified — exit 3.
    let seed = [7u8; 32];
    let prompt = "hello e2e";
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, [1u8; 16], None);
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());
    let out = run_watcher_min(&bytes, &tee_pk, &hex::encode(seed), prompt);
    assert_eq!(
        out.status.code(),
        Some(3),
        "expected exit 3 (Partial) with no optional inputs; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"Partial\""), "stdout: {stdout}");
    assert!(
        stdout.contains("\"activations_consistent\": true"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"receipt_signature_verified\": true"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"attestation_verified\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"log_inclusion_verified\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"sth_signature_verified\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"sth_freshness_verified\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"weight_commit_pinned\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"session_pinned\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"zk_proofs_verified\": false"),
        "stdout: {stdout}"
    );
}

#[test]
fn watcher_cli_tampered_layer_returns_one_with_divergent_layer() {
    let seed = [7u8; 32];
    let prompt = "hello e2e";
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, [1u8; 16], Some(3));
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());
    let out = run_watcher_min(&bytes, &tee_pk, &hex::encode(seed), prompt);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit code 1 for tampered receipt, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Fraudulent"), "stdout: {stdout}");
    assert!(stdout.contains("\"divergent_layer\": 3"), "stdout: {stdout}");
}

#[test]
fn watcher_cli_bad_signature_returns_two() {
    let seed = [7u8; 32];
    let prompt = "hello e2e";
    let (bytes, _real_sk) = make_receipt(prompt.as_bytes(), seed, [1u8; 16], None);
    let wrong_pk = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().as_bytes());
    let out = run_watcher_min(&bytes, &wrong_pk, &hex::encode(seed), prompt);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn watcher_cli_weight_commit_pin_flag_flips_when_supplied() {
    let seed = [11u8; 32];
    let prompt = "pin me";
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, [2u8; 16], None);
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());
    let expected_wc = hex::encode(Model::from_seed(&seed).weight_commit());

    let tmp = std::env::temp_dir().join(format!("ullm-e2e-{}.bin", rand::random::<u64>()));
    std::fs::write(&tmp, &bytes).expect("write tempfile");
    let out = Command::new(watcher_bin())
        .arg("--model-seed")
        .arg(hex::encode(seed))
        .arg("--tee-pk")
        .arg(&tee_pk)
        .arg("--prompt")
        .arg(prompt)
        .arg("--receipt")
        .arg(&tmp)
        .arg("--expected-weight-commit")
        .arg(&expected_wc)
        .output()
        .expect("spawn watcher");
    std::fs::remove_file(&tmp).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"weight_commit_pinned\": true"),
        "expected flag to flip true; stdout: {stdout}"
    );
}

#[test]
fn watcher_cli_session_pin_mismatch_keeps_flag_false() {
    let seed = [13u8; 32];
    let prompt = "session pin";
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, [9u8; 16], None);
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());

    let tmp = std::env::temp_dir().join(format!("ullm-e2e-{}.bin", rand::random::<u64>()));
    std::fs::write(&tmp, &bytes).expect("write tempfile");
    let out = Command::new(watcher_bin())
        .arg("--model-seed")
        .arg(hex::encode(seed))
        .arg("--tee-pk")
        .arg(&tee_pk)
        .arg("--prompt")
        .arg(prompt)
        .arg("--receipt")
        .arg(&tmp)
        .arg("--expected-session")
        .arg(hex::encode([0u8; 16]))
        .output()
        .expect("spawn watcher");
    std::fs::remove_file(&tmp).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"session_pinned\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("session mismatch"),
        "missing mismatch note; stdout: {stdout}"
    );
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn watcher_cli_session_pin_match_flips_flag_true() {
    let seed = [13u8; 32];
    let prompt = "session pin match";
    let session = [9u8; 16];
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, session, None);
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());

    let tmp = std::env::temp_dir().join(format!("ullm-e2e-{}.bin", rand::random::<u64>()));
    std::fs::write(&tmp, &bytes).expect("write tempfile");
    let out = Command::new(watcher_bin())
        .arg("--model-seed")
        .arg(hex::encode(seed))
        .arg("--tee-pk")
        .arg(&tee_pk)
        .arg("--prompt")
        .arg(prompt)
        .arg("--receipt")
        .arg(&tmp)
        .arg("--expected-session")
        .arg(hex::encode(session))
        .output()
        .expect("spawn watcher");
    std::fs::remove_file(&tmp).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"session_pinned\": true"),
        "stdout: {stdout}"
    );
}

#[test]
fn watcher_cli_sth_freshness_flag_is_set_when_sth_recent() {
    let log = TransparencyLog::new();
    for i in 0..3 {
        log.append([i; 32], &[i], 100 + i as u64).unwrap();
    }
    let entries = log.snapshot();
    let root = ullm_transparency::merkle_root(&entries);
    let head = TreeHead {
        size: entries.len() as u64,
        root_hex: hex::encode(root),
        issued_at_unix: 1_700_000_000,
        log_id: "ullm-test-log".into(),
    };
    let logger = SigningKey::generate(&mut OsRng);
    let sth = SignedTreeHead::sign(head, &logger);
    let proof = InclusionProof::build(&entries, 0).unwrap();

    let tmp_sth = std::env::temp_dir().join(format!("ullm-sth-{}.json", rand::random::<u64>()));
    let tmp_proof = std::env::temp_dir().join(format!("ullm-proof-{}.json", rand::random::<u64>()));
    let tmp_entry = std::env::temp_dir().join(format!("ullm-entry-{}.json", rand::random::<u64>()));
    std::fs::write(&tmp_sth, serde_json::to_vec_pretty(&sth).unwrap()).unwrap();
    std::fs::write(&tmp_proof, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();
    std::fs::write(&tmp_entry, serde_json::to_vec_pretty(&entries[0]).unwrap()).unwrap();

    let seed = [17u8; 32];
    let prompt = "freshness";
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, [5u8; 16], None);
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());
    let tmp_receipt = std::env::temp_dir().join(format!("ullm-e2e-{}.bin", rand::random::<u64>()));
    std::fs::write(&tmp_receipt, &bytes).expect("write tempfile");

    let out = Command::new(watcher_bin())
        .arg("--model-seed")
        .arg(hex::encode(seed))
        .arg("--tee-pk")
        .arg(&tee_pk)
        .arg("--prompt")
        .arg(prompt)
        .arg("--receipt")
        .arg(&tmp_receipt)
        .arg("--sth-url")
        .arg(&tmp_sth)
        .arg("--proof")
        .arg(&tmp_proof)
        .arg("--log-entry")
        .arg(&tmp_entry)
        .arg("--freshness-now")
        .arg("1700000060")
        .arg("--freshness-max-age-secs")
        .arg("3600")
        .arg("--logger-pk")
        .arg(hex::encode(logger.verifying_key().as_bytes()))
        .output()
        .expect("spawn watcher");

    for p in [&tmp_sth, &tmp_proof, &tmp_entry, &tmp_receipt] {
        std::fs::remove_file(p).ok();
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("\"sth_freshness_verified\": true"),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("\"sth_signature_verified\": true"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("\"log_inclusion_verified\": true"),
        "stdout={stdout}"
    );
}

#[test]
fn watcher_cli_sth_freshness_stale_flag_stays_false() {
    let log = TransparencyLog::new();
    log.append([0u8; 32], b"a", 100).unwrap();
    let entries = log.snapshot();
    let root = ullm_transparency::merkle_root(&entries);
    let head = TreeHead {
        size: 1,
        root_hex: hex::encode(root),
        issued_at_unix: 1_700_000_000,
        log_id: "ullm-test-log".into(),
    };
    let logger = SigningKey::generate(&mut OsRng);
    let sth = SignedTreeHead::sign(head, &logger);
    let proof = InclusionProof::build(&entries, 0).unwrap();

    let tmp_sth = std::env::temp_dir().join(format!("ullm-sth-{}.json", rand::random::<u64>()));
    let tmp_proof = std::env::temp_dir().join(format!("ullm-proof-{}.json", rand::random::<u64>()));
    let tmp_entry = std::env::temp_dir().join(format!("ullm-entry-{}.json", rand::random::<u64>()));
    std::fs::write(&tmp_sth, serde_json::to_vec_pretty(&sth).unwrap()).unwrap();
    std::fs::write(&tmp_proof, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();
    std::fs::write(&tmp_entry, serde_json::to_vec_pretty(&entries[0]).unwrap()).unwrap();

    let seed = [19u8; 32];
    let prompt = "stale";
    let (bytes, sk) = make_receipt(prompt.as_bytes(), seed, [5u8; 16], None);
    let tee_pk = hex::encode(sk.verifying_key().as_bytes());
    let tmp_receipt = std::env::temp_dir().join(format!("ullm-e2e-{}.bin", rand::random::<u64>()));
    std::fs::write(&tmp_receipt, &bytes).expect("write tempfile");

    let out = Command::new(watcher_bin())
        .arg("--model-seed")
        .arg(hex::encode(seed))
        .arg("--tee-pk")
        .arg(&tee_pk)
        .arg("--prompt")
        .arg(prompt)
        .arg("--receipt")
        .arg(&tmp_receipt)
        .arg("--sth-url")
        .arg(&tmp_sth)
        .arg("--proof")
        .arg(&tmp_proof)
        .arg("--log-entry")
        .arg(&tmp_entry)
        .arg("--freshness-now")
        .arg("1700100000")
        .arg("--freshness-max-age-secs")
        .arg("60")
        .output()
        .expect("spawn watcher");

    for p in [&tmp_sth, &tmp_proof, &tmp_entry, &tmp_receipt] {
        std::fs::remove_file(p).ok();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"sth_freshness_verified\": false"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("STH age"),
        "expected explanation note; stdout: {stdout}"
    );
}

#[test]
fn watcher_lib_full_verification_flips_verdict_to_honest() {
    // Library-level: when every flag in AuditInputs is set, the verdict
    // is Honest. We exercise the lib (not the CLI) because RealVerifier
    // needs real attestation evidence — easier to wire here.
    use ed25519_dalek::VerifyingKey;
    use ullm_attest::{Evidence, MeasurementPolicy, QuoteKind};
    use ullm_watcher::{
        audit_with, AttestationCheck, AuditInputs, LogInclusionCheck, SthFreshnessCheck, Verdict,
    };

    let seed = [21u8; 32];
    let prompt: &[u8] = b"fully verified";
    let session = [4u8; 16];
    let (bytes, sk) = make_receipt(prompt, seed, session, None);
    let signed: ullm_receipts::SignedReceipt = postcard::from_bytes(&bytes).unwrap();
    let tee_vk: VerifyingKey = sk.verifying_key();

    let rd: [u8; 64] = [33u8; 64];
    let mrtd: [u8; 48] = [9u8; 48];
    let cpu_quote = ullm_attest::tdx::synthesize_quote(rd, mrtd);
    let evidence = Evidence {
        cpu_quote_kind: QuoteKind::Tdx,
        cpu_quote,
        gpu_quote: vec![],
        cert_chain: vec![],
        report_data: rd,
        issued_at_unix: 100,
    };
    let policy = MeasurementPolicy {
        allowed_mrtd: [mrtd].into_iter().collect(),
        ..Default::default()
    };

    let log = TransparencyLog::new();
    for i in 0..2 {
        log.append([i; 32], &[i], 100 + i as u64).unwrap();
    }
    let entries = log.snapshot();
    let root = ullm_transparency::merkle_root(&entries);
    let head = TreeHead {
        size: entries.len() as u64,
        root_hex: hex::encode(root),
        issued_at_unix: 1_700_000_000,
        log_id: "ullm-test-log".into(),
    };
    let logger = SigningKey::generate(&mut OsRng);
    let sth = SignedTreeHead::sign(head, &logger);
    let proof = InclusionProof::build(&entries, 0).unwrap();
    let logger_pk: [u8; 32] = sth.logger_pk;

    let zk: Vec<Vec<u8>> = (0..NUM_LAYERS).map(|_| vec![0u8; 4]).collect();

    let inputs = AuditInputs {
        attestation: Some(AttestationCheck {
            evidence: &evidence,
            policy,
            expected_report_data: &rd,
            now_unix: 110,
            max_age_sec: 60,
            require_signature_check: false,
        }),
        log_inclusion: Some(LogInclusionCheck {
            sth: &sth,
            proof: &proof,
            expected_entry: &entries[0],
            expected_log_id: Some("ullm-test-log"),
            expected_logger_pk: Some(&logger_pk),
        }),
        sth_freshness: Some(SthFreshnessCheck {
            sth_issued_at_unix: 1_700_000_000,
            now_unix: 1_700_000_001,
            max_age_sec: 60,
        }),
        expected_weight_commit: Some(Model::from_seed(&seed).weight_commit()),
        expected_session: Some(session),
        zk_layer_proofs: Some(&zk),
    };
    let report = audit_with(&seed, &tee_vk, prompt, &signed, inputs).unwrap();
    assert!(matches!(report.verdict, Verdict::Honest), "{:?}", report);
    assert!(Verdict::is_fully_verified(&report));
}
