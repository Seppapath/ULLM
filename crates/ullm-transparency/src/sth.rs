// SPDX-License-Identifier: Apache-2.0
//! Signed Tree Head: the logger commits to `(size, root, timestamp)`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeHead {
    pub size: u64,
    pub root_hex: String,
    pub issued_at_unix: u64,
    /// Stable identifier of the log this head was issued against. Bound
    /// into the canonical signature payload so an STH from log A cannot be
    /// replayed as evidence for a different log B (P2-6). Typical values
    /// are the hex-encoded logger verifying key or a deployment UUID; the
    /// only requirement is that auditors agree on it out-of-band.
    #[serde(default)]
    pub log_id: String,
}

impl TreeHead {
    /// Canonical bytes that get signed. P7 audit (P7-5/6/7) replaced the
    /// previous `serde_json::json!({...})` macro form with an explicit
    /// `BTreeMap<&'static str, serde_json::Value>` so the key ordering
    /// is *guaranteed* alphabetical regardless of what `serde_json`'s
    /// internals do across versions — the previous form happened to
    /// produce the right bytes because `serde_json` used `BTreeMap`
    /// under the hood, but newer releases switched to `IndexMap` which
    /// preserves insertion order. With the explicit `BTreeMap` here,
    /// every signed/verified TreeHead round-trips byte-for-byte through
    /// any future serde_json release.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut m: std::collections::BTreeMap<&'static str, serde_json::Value> =
            std::collections::BTreeMap::new();
        m.insert("issued_at_unix", serde_json::json!(self.issued_at_unix));
        m.insert("log_id", serde_json::json!(self.log_id));
        m.insert("root_hex", serde_json::json!(self.root_hex));
        m.insert("size", serde_json::json!(self.size));
        serde_json::to_vec(&m).expect("json")
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub head: TreeHead,
    pub logger_pk: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl SignedTreeHead {
    pub fn sign(head: TreeHead, key: &SigningKey) -> Self {
        let bytes = head.canonical_bytes();
        let sig: Signature = key.sign(&bytes);
        Self {
            head,
            logger_pk: *key.verifying_key().as_bytes(),
            signature: sig.to_bytes(),
        }
    }

    pub fn verify(&self) -> bool {
        let vk = match VerifyingKey::from_bytes(&self.logger_pk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let bytes = self.head.canonical_bytes();
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&bytes, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_then_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let head = TreeHead {
            size: 42,
            root_hex: "deadbeef".into(),
            issued_at_unix: 1_700_000_000,
            log_id: "test-log-a".into(),
        };
        let signed = SignedTreeHead::sign(head, &key);
        assert!(signed.verify());
    }

    #[test]
    fn tampered_head_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let head = TreeHead {
            size: 1,
            root_hex: "00".into(),
            issued_at_unix: 0,
            log_id: "test-log-a".into(),
        };
        let mut signed = SignedTreeHead::sign(head, &key);
        signed.head.size += 1;
        assert!(!signed.verify());
    }

    /// Regression for P2-6: tampering with the log_id after signing must
    /// invalidate the STH — otherwise an attacker can lift a signature
    /// from log A and present it as evidence for log B.
    #[test]
    fn tampered_log_id_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let head = TreeHead {
            size: 1,
            root_hex: "00".into(),
            issued_at_unix: 0,
            log_id: "log-A".into(),
        };
        let mut signed = SignedTreeHead::sign(head, &key);
        signed.head.log_id = "log-B".into();
        assert!(!signed.verify());
    }

    /// Regression for P7-7: every TreeHead field must be covered by the
    /// canonical-bytes payload that gets signed. A future refactor that
    /// drops a field from `canonical_bytes` (or accidentally renames a
    /// key) would still produce a valid-looking signature on one shape
    /// but fail to detect tampering on the dropped/renamed field. This
    /// test enumerates every field and asserts mutation breaks
    /// verification.
    #[test]
    fn every_field_breaks_signature_when_tampered() {
        let key = SigningKey::generate(&mut OsRng);
        let original = TreeHead {
            size: 42,
            root_hex: "deadbeef".into(),
            issued_at_unix: 1_700_000_000,
            log_id: "ullm-test".into(),
        };
        let signed = SignedTreeHead::sign(original.clone(), &key);
        let sig = signed.signature;
        let pk = signed.logger_pk;

        // Helper that lifts the original signature onto a mutated head
        // and asserts the verifier rejects it.
        let assert_field_covered = |mutated: TreeHead, label: &str| {
            let attacker = SignedTreeHead {
                head: mutated,
                logger_pk: pk,
                signature: sig,
            };
            assert!(
                !attacker.verify(),
                "tampering field {label} must invalidate STH signature"
            );
        };

        let mut m = original.clone();
        m.size = 99;
        assert_field_covered(m, "size");

        let mut m = original.clone();
        m.root_hex = "cafebabe".into();
        assert_field_covered(m, "root_hex");

        let mut m = original.clone();
        m.issued_at_unix = 1;
        assert_field_covered(m, "issued_at_unix");

        let mut m = original.clone();
        m.log_id = "other".into();
        assert_field_covered(m, "log_id");
    }

    /// Regression for P7-5/6: canonical bytes must be deterministic and
    /// independent of the in-memory field ordering — two TreeHeads with
    /// the same field values produce identical canonical bytes byte-for-byte.
    #[test]
    fn canonical_bytes_are_deterministic() {
        let a = TreeHead {
            size: 7,
            root_hex: "abcd".into(),
            issued_at_unix: 100,
            log_id: "ullm-test".into(),
        };
        let b = TreeHead {
            log_id: "ullm-test".into(),
            issued_at_unix: 100,
            root_hex: "abcd".into(),
            size: 7,
        };
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }
}
