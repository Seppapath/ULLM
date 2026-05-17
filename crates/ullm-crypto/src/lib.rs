// SPDX-License-Identifier: Apache-2.0
//! Cryptographic primitives for the ullm record layer.
//!
//! Everything that touches secret material lives here. The crate has no I/O
//! and no async; callers thread bytes in and bytes out.

pub mod aead;
pub mod kdf;
pub mod kex;
pub mod ratchet;
pub mod seal;

pub use aead::{aead_open, aead_seal, AeadKey};
pub use kdf::{derive_root, expand, extract, RootKey, INFO_CHAIN, INFO_MSG, INFO_NONCE_SALT, INFO_RECORD_C2S, INFO_RECORD_S2C};
pub use kex::{hybrid_decap, hybrid_encap, ml_kem_ct_bytes, ml_kem_ct_from_bytes, ml_kem_keypair, ml_kem_pk_bytes, ml_kem_pk_from_bytes, HybridSecret, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, X25519PublicKey, X25519SecretKey};
pub use ratchet::{
    derive_initial_keys, frame_nonce, ChainKey, DhRatchet, InitialKeys, MessageKey, NonceSalt,
    SymRatchet, TripleRatchet, TurnPayload,
};
pub use seal::{seal, unseal, SealError, SealedKek};
