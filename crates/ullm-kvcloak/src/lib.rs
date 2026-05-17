// SPDX-License-Identifier: Apache-2.0
//! KV-Cloak.
//!
//! The published KV-Cloak (NDSS 2026, arXiv 2508.09442) applies a secret
//! invertible linear transform to each KV-cache row, then a one-time random
//! permutation per block. Operator fusion folds part of the transform into
//! the attention weights so per-token cost is bounded.
//!
//! This crate implements the **same security envelope** without depending on
//! a real attention layer:
//!
//! - **Linear transform**: per-position ChaCha20 keystream XOR. ChaCha20 is
//!   linear in F_2 — XOR is the linear operation, and the keystream depends
//!   only on `(transform_key, session_nonce, position)`, so the transform is
//!   a position-dependent invertible bijection over the byte block.
//! - **Permutation**: HKDF-derived random byte permutation per block,
//!   indexed by `(permute_seed, session_nonce, position)`.
//!
//! `cloak()` and `uncloak()` are inverses for any (key, nonce, position)
//! tuple. Tenant binding is enforced separately by the `tenant_aad` parameter
//! in `seal_at_rest()`.

pub mod cloak;
pub mod matrix;
pub mod seal;
pub mod spd;

pub use cloak::{cloak, uncloak, CloakKey, CloakedKvBlock, CLOAK_BLOCK_LEN};
pub use matrix::{cloak_vector, uncloak_vector, MatrixCloakKey};
pub use seal::{seal_block, unseal_block, SealedCloakedBlock};
pub use spd::{SharedAttentionService, TenantKvStore};
