// SPDX-License-Identifier: Apache-2.0
//! Inclusion (audit-path) proofs.

use serde::{Deserialize, Serialize};

use crate::log::LogEntry;
use crate::merkle::{leaf_hash, node_hash};

/// Path-based inclusion proof. `siblings[i]` is the sibling hash at level `i`
/// when walking from the leaf up to the root. `direction[i]` is `true` iff
/// the current node is the **left** child at level `i` (so the sibling is
/// on the right). `tree_size` is the leaf count when the proof was issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub seq: u64,
    pub tree_size: u64,
    pub leaf_hash_hex: String,
    pub siblings_hex: Vec<String>,
    pub directions: Vec<bool>,
}

impl InclusionProof {
    pub fn build(entries: &[LogEntry], seq: u64) -> Option<Self> {
        if seq as usize >= entries.len() {
            return None;
        }
        let leaves: Vec<[u8; 32]> = entries.iter().map(leaf_hash).collect();
        let mut siblings: Vec<[u8; 32]> = Vec::new();
        let mut directions: Vec<bool> = Vec::new();

        let mut level = leaves.clone();
        let mut idx = seq as usize;
        while level.len() > 1 {
            let is_left = idx % 2 == 0;
            let sibling_idx = if is_left { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                // Odd-leaf duplication.
                level[idx]
            };
            siblings.push(sibling);
            directions.push(is_left);

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut j = 0;
            while j < level.len() {
                let l = level[j];
                let r = if j + 1 < level.len() {
                    level[j + 1]
                } else {
                    level[j]
                };
                next.push(node_hash(&l, &r));
                j += 2;
            }
            level = next;
            idx /= 2;
        }

        Some(Self {
            seq,
            tree_size: entries.len() as u64,
            leaf_hash_hex: hex::encode(leaves[seq as usize]),
            siblings_hex: siblings.iter().map(hex::encode).collect(),
            directions,
        })
    }

    /// Verify the audit path reconstructs `expected_root` **and** that the
    /// leaf the path opens to is exactly `leaf_hash(expected_entry)`.
    ///
    /// Taking the entry (rather than letting the caller trust `self.leaf_hash_hex`)
    /// closes the P2-4 API trap: the previous version returned `true` for any
    /// well-formed path whose claimed leaf hash equaled the root, regardless
    /// of which entry was being attested. Auditors that forgot to verify
    /// `leaf_hash_hex == leaf_hash(my_entry)` separately could be fooled by
    /// a tautological size-1 proof.
    pub fn verify(&self, expected_root: [u8; 32], expected_entry: &LogEntry) -> bool {
        if self.siblings_hex.len() != self.directions.len() {
            return false;
        }
        // Bind the proof to the caller's entry: the path *must* open to
        // exactly `leaf_hash(expected_entry)`, not to the attacker-supplied
        // `leaf_hash_hex`.
        let expected_leaf = leaf_hash(expected_entry);
        let claimed_leaf = match decode32(&self.leaf_hash_hex) {
            Some(v) => v,
            None => return false,
        };
        if claimed_leaf != expected_leaf {
            return false;
        }
        let mut current = expected_leaf;
        for (sib_hex, is_left) in self.siblings_hex.iter().zip(self.directions.iter()) {
            let sibling = match decode32(sib_hex) {
                Some(v) => v,
                None => return false,
            };
            current = if *is_left {
                node_hash(&current, &sibling)
            } else {
                node_hash(&sibling, &current)
            };
        }
        current == expected_root
    }
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

    #[test]
    fn inclusion_proof_verifies() {
        let log = TransparencyLog::new();
        for i in 0..7 {
            log.append([i; 32], format!("e{i}").as_bytes(), 100 + i as u64)
                .unwrap();
        }
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        for seq in 0..entries.len() as u64 {
            let proof = InclusionProof::build(&entries, seq).unwrap();
            assert!(
                proof.verify(root, &entries[seq as usize]),
                "proof for seq {seq} failed to verify"
            );
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let log = TransparencyLog::new();
        for i in 0..4 {
            log.append([i; 32], &[i], 100 + i as u64).unwrap();
        }
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        let mut proof = InclusionProof::build(&entries, 1).unwrap();
        // Flip a single hex character in the leaf hash.
        let mut chars: Vec<char> = proof.leaf_hash_hex.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        proof.leaf_hash_hex = chars.into_iter().collect();
        assert!(!proof.verify(root, &entries[1]));
    }

    /// Regression for P2-4: a proof whose path is internally consistent
    /// but whose leaf belongs to a *different* entry must be rejected.
    /// The previous API trusted `leaf_hash_hex` and would accept a proof
    /// for seq 1 as if it attested to entry-at-seq-2.
    #[test]
    fn proof_rejected_when_unbound_entry_doesnt_match() {
        let log = TransparencyLog::new();
        for i in 0..4 {
            log.append([i; 32], &[i], 100 + i as u64).unwrap();
        }
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        // Valid proof for seq 1, but we present it as if it attests entry 2.
        let proof = InclusionProof::build(&entries, 1).unwrap();
        assert!(!proof.verify(root, &entries[2]));
        // And vice-versa: the same proof against its own entry verifies fine.
        assert!(proof.verify(root, &entries[1]));
    }

    /// Regression for P2-4 + P2-5: a single-entry tree, where the root
    /// equals the leaf hash, must still bind the verifier to the actual
    /// entry — not just "any string whose hash happens to equal the root."
    #[test]
    fn size_one_proof_still_requires_entry_binding() {
        let log = TransparencyLog::new();
        log.append([7; 32], b"only", 1).unwrap();
        let entries = log.snapshot();
        let root = merkle_root(&entries);
        let proof = InclusionProof::build(&entries, 0).unwrap();
        // Real entry → ok.
        assert!(proof.verify(root, &entries[0]));
        // Fabricated entry with the same shape but different bytes → rejected.
        let mut forged = entries[0].clone();
        forged.evidence_sha256_hex = "ff".repeat(32);
        assert!(!proof.verify(root, &forged));
    }
}
