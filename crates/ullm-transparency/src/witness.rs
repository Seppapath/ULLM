// SPDX-License-Identifier: Apache-2.0
//! Witness cosignatures over an STH.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::sth::SignedTreeHead;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCosignature {
    pub witness_pk: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl WitnessCosignature {
    /// A witness cosigns the bytes of the logger's STH `signature` —
    /// concretely the 64-byte signature, so the witness endorses the exact
    /// (head, logger_signature) tuple the logger published.
    pub fn cosign(sth: &SignedTreeHead, key: &SigningKey) -> Self {
        let bytes = Self::message(sth);
        let sig: Signature = key.sign(&bytes);
        Self {
            witness_pk: *key.verifying_key().as_bytes(),
            signature: sig.to_bytes(),
        }
    }

    pub fn verify(&self, sth: &SignedTreeHead) -> bool {
        let vk = match VerifyingKey::from_bytes(&self.witness_pk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let bytes = Self::message(sth);
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&bytes, &sig).is_ok()
    }

    fn message(sth: &SignedTreeHead) -> [u8; 64] {
        sth.signature
    }
}

/// Caller-supplied list of trusted witness keys plus a `threshold` count.
#[derive(Clone, Debug)]
pub struct WitnessKeyset {
    pub witnesses: Vec<VerifyingKey>,
    pub threshold: usize,
}

impl WitnessKeyset {
    /// Counts how many of `cosigs` verify against an entry in `witnesses`.
    pub fn count_valid(&self, sth: &SignedTreeHead, cosigs: &[WitnessCosignature]) -> usize {
        let mut counted: HashSet<[u8; 32]> = HashSet::new();
        for c in cosigs {
            if !self.witnesses.iter().any(|w| w.as_bytes() == &c.witness_pk) {
                continue;
            }
            if c.verify(sth) {
                counted.insert(c.witness_pk);
            }
        }
        counted.len()
    }

    pub fn satisfies(&self, sth: &SignedTreeHead, cosigs: &[WitnessCosignature]) -> bool {
        self.count_valid(sth, cosigs) >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sth::TreeHead;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn fixture() -> (SignedTreeHead, Vec<SigningKey>) {
        let mut rng = OsRng;
        let logger = SigningKey::generate(&mut rng);
        let head = TreeHead {
            size: 7,
            root_hex: "abcd".into(),
            issued_at_unix: 100,
            log_id: "ullm-test-log".into(),
        };
        let sth = SignedTreeHead::sign(head, &logger);
        let witnesses: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut rng)).collect();
        (sth, witnesses)
    }

    #[test]
    fn cosign_verifies() {
        let (sth, ws) = fixture();
        let c = WitnessCosignature::cosign(&sth, &ws[0]);
        assert!(c.verify(&sth));
    }

    #[test]
    fn keyset_threshold_satisfied_by_t_witnesses() {
        let (sth, ws) = fixture();
        let keyset = WitnessKeyset {
            witnesses: ws.iter().map(|s| s.verifying_key()).collect(),
            threshold: 2,
        };
        let cosigs: Vec<WitnessCosignature> = ws
            .iter()
            .take(2)
            .map(|w| WitnessCosignature::cosign(&sth, w))
            .collect();
        assert!(keyset.satisfies(&sth, &cosigs));
    }

    #[test]
    fn keyset_threshold_unsatisfied_below() {
        let (sth, ws) = fixture();
        let keyset = WitnessKeyset {
            witnesses: ws.iter().map(|s| s.verifying_key()).collect(),
            threshold: 2,
        };
        let cosigs = vec![WitnessCosignature::cosign(&sth, &ws[0])];
        assert!(!keyset.satisfies(&sth, &cosigs));
    }

    #[test]
    fn unknown_witness_does_not_count() {
        let (sth, _ws) = fixture();
        let stranger = SigningKey::generate(&mut OsRng);
        let cosig = WitnessCosignature::cosign(&sth, &stranger);
        let keyset = WitnessKeyset {
            witnesses: vec![],
            threshold: 0,
        };
        assert_eq!(keyset.count_valid(&sth, &[cosig]), 0);
    }

    #[test]
    fn duplicate_cosigs_count_once() {
        let (sth, ws) = fixture();
        let keyset = WitnessKeyset {
            witnesses: ws.iter().map(|s| s.verifying_key()).collect(),
            threshold: 2,
        };
        let one = WitnessCosignature::cosign(&sth, &ws[0]);
        let cosigs = vec![one.clone(), one];
        assert_eq!(keyset.count_valid(&sth, &cosigs), 1);
    }
}
