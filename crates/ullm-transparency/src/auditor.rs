// SPDX-License-Identifier: Apache-2.0
//! Auditor primitives: combine STH signature check, inclusion-proof
//! verification, and witness-threshold enforcement into one call.

use thiserror::Error;

use crate::inclusion::InclusionProof;
use crate::log::LogEntry;
use crate::sth::SignedTreeHead;
use crate::witness::{WitnessCosignature, WitnessKeyset};

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("STH signature did not verify under the bundled logger key")]
    StoredSignatureInvalid,
    #[error("logger key {got} not in the expected-loggers list")]
    UnexpectedLogger { got: String },
    #[error("STH log_id {got:?} does not match expected {expected:?}")]
    UnexpectedLogId { got: String, expected: String },
    #[error("inclusion proof did not reconstruct the STH root")]
    InclusionPathInvalid,
    #[error("proof claims size {claimed}, STH advertises {advertised}")]
    SizeMismatch { claimed: u64, advertised: u64 },
    #[error("only {got} valid witness cosignatures; {needed} required")]
    InsufficientWitnesses { got: usize, needed: usize },
}

/// Full audit: signature → optional log-ID pin → optional witness threshold → inclusion path.
///
/// `expected_entry` is the log entry the auditor is trying to prove
/// inclusion of: the proof must bind to *exactly* that entry's leaf hash
/// (P2-4). `expected_log_id` pins which log we're auditing — when `Some`,
/// the STH's `log_id` must match exactly; when `None`, the field is
/// informational (back-compat with legacy heads, but every prod deployment
/// should pin).
pub fn verify_inclusion_against_head(
    sth: &SignedTreeHead,
    proof: &InclusionProof,
    expected_entry: &LogEntry,
    cosigs: Option<(&WitnessKeyset, &[WitnessCosignature])>,
    expected_log_id: Option<&str>,
) -> Result<(), AuditError> {
    if !sth.verify() {
        return Err(AuditError::StoredSignatureInvalid);
    }
    if let Some(want) = expected_log_id {
        if sth.head.log_id != want {
            return Err(AuditError::UnexpectedLogId {
                got: sth.head.log_id.clone(),
                expected: want.to_string(),
            });
        }
    }
    if proof.tree_size != sth.head.size {
        return Err(AuditError::SizeMismatch {
            claimed: proof.tree_size,
            advertised: sth.head.size,
        });
    }
    let root_bytes = decode32(&sth.head.root_hex).ok_or(AuditError::InclusionPathInvalid)?;
    if !proof.verify(root_bytes, expected_entry) {
        return Err(AuditError::InclusionPathInvalid);
    }
    if let Some((keyset, cosigs)) = cosigs {
        let got = keyset.count_valid(sth, cosigs);
        if got < keyset.threshold {
            return Err(AuditError::InsufficientWitnesses {
                got,
                needed: keyset.threshold,
            });
        }
    }
    Ok(())
}

fn decode32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::TransparencyLog;
    use crate::merkle::merkle_root;
    use crate::sth::{SignedTreeHead, TreeHead};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn end_to_end_audit_happy_path() {
        let log = TransparencyLog::new();
        for i in 0..5 {
            log.append([i; 32], &[i], 100 + i as u64).unwrap();
        }
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        let head = TreeHead {
            size: entries.len() as u64,
            root_hex: hex::encode(root),
            issued_at_unix: 1000,
            log_id: "ullm-test-log".into(),
        };
        let logger = SigningKey::generate(&mut OsRng);
        let sth = SignedTreeHead::sign(head, &logger);
        let proof = InclusionProof::build(&entries, 2).unwrap();

        let w0 = SigningKey::generate(&mut OsRng);
        let w1 = SigningKey::generate(&mut OsRng);
        let keyset = WitnessKeyset {
            witnesses: vec![w0.verifying_key(), w1.verifying_key()],
            threshold: 2,
        };
        let cosigs = vec![
            crate::witness::WitnessCosignature::cosign(&sth, &w0),
            crate::witness::WitnessCosignature::cosign(&sth, &w1),
        ];

        verify_inclusion_against_head(
            &sth,
            &proof,
            &entries[2],
            Some((&keyset, &cosigs)),
            Some("ullm-test-log"),
        )
        .unwrap();
    }

    /// Regression for P2-6: pinning an explicit log_id rejects an STH
    /// signed for a different log even if its signature checks out.
    #[test]
    fn rejects_log_id_mismatch() {
        let log = TransparencyLog::new();
        for i in 0..3 {
            log.append([i; 32], &[i], 100 + i as u64).unwrap();
        }
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        let head = TreeHead {
            size: entries.len() as u64,
            root_hex: hex::encode(root),
            issued_at_unix: 1,
            log_id: "log-A".into(),
        };
        let logger = SigningKey::generate(&mut OsRng);
        let sth = SignedTreeHead::sign(head, &logger);
        let proof = InclusionProof::build(&entries, 0).unwrap();
        let err = verify_inclusion_against_head(&sth, &proof, &entries[0], None, Some("log-B"))
            .unwrap_err();
        assert!(matches!(err, AuditError::UnexpectedLogId { .. }));
    }

    #[test]
    fn rejects_size_mismatch() {
        let log = TransparencyLog::new();
        log.append([0u8; 32], b"a", 1).unwrap();
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        let head = TreeHead {
            size: 2, // wrong
            root_hex: hex::encode(root),
            issued_at_unix: 1,
            log_id: "ullm-test-log".into(),
        };
        let logger = SigningKey::generate(&mut OsRng);
        let sth = SignedTreeHead::sign(head, &logger);
        let proof = InclusionProof::build(&entries, 0).unwrap();
        assert!(verify_inclusion_against_head(&sth, &proof, &entries[0], None, None).is_err());
    }
}
