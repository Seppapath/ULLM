// SPDX-License-Identifier: Apache-2.0
//! SHA-256 Merkle tree primitive. Domain-separated against entry leaves
//! and internal nodes; odd-leaf duplication at each level.

use sha2::{Digest, Sha256};

use crate::log::LogEntry;

pub const LEAF_DOMAIN: &[u8] = b"ULLM-transparency-v1 leaf";
pub const NODE_DOMAIN: &[u8] = b"ULLM-transparency-v1 node";
pub const EMPTY_DOMAIN: &[u8] = b"ULLM-transparency-v1 empty";

/// Root hash advertised for a tree with zero entries. Domain-separated so
/// it can never collide with a legitimate `leaf_hash(...)` or `node_hash(..)`
/// output, eliminating the "size 0 vs size 1 with all-zero leaf"
/// indistinguishability that the previous `[0u8; 32]` sentinel admitted.
pub fn empty_root() -> [u8; 32] {
    Sha256::digest(EMPTY_DOMAIN).into()
}

pub fn leaf_hash(entry: &LogEntry) -> [u8; 32] {
    let canonical = entry.canonical_bytes();
    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN);
    h.update(canonical);
    h.finalize().into()
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NODE_DOMAIN);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn merkle_root(entries: &[LogEntry]) -> [u8; 32] {
    if entries.is_empty() {
        return empty_root();
    }
    let leaves: Vec<[u8; 32]> = entries.iter().map(leaf_hash).collect();
    root_of_leaves(&leaves)
}

pub fn root_of_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            next.push(node_hash(&left, &right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for P2-5: the empty-tree root must be domain-separated
    /// from any honest leaf or node hash, so an attacker can't craft a
    /// "size 1, leaf=all-zeros" log that's indistinguishable from "size 0".
    #[test]
    fn empty_root_is_domain_separated() {
        let root = empty_root();
        assert_ne!(root, [0u8; 32], "must not be the zero sentinel");
        // Any honest leaf is `SHA256(LEAF_DOMAIN || canonical)` which differs
        // from `SHA256(EMPTY_DOMAIN)` with overwhelming probability —
        // structural inequality is enough here.
        assert_ne!(root, Sha256::digest(LEAF_DOMAIN).as_slice());
    }
}
