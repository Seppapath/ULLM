// SPDX-License-Identifier: Apache-2.0
//! Signal-style symmetric (chain) and X25519 DH (turn) ratchets.
//!
//! Phase 1 layering:
//! - **Per-chunk symmetric ratchet** advances `ChainKey -> ChainKey'` and emits
//!   `MessageKey` for one frame. Forward secrecy at chunk granularity.
//! - **Per-turn DH ratchet** mixes a fresh X25519 ECDH into the root key,
//!   producing new chain keys + nonce salt for the next epoch. Post-compromise
//!   security at turn granularity.
//!
//! Phase 2 will mix ML-KEM-768 encapsulation into the per-turn ratchet
//! (SPQR pattern); the API here is shaped to accept that addition.

use crate::aead::AeadKey;
use crate::kdf::{
    expand, extract, RootKey, INFO_CHAIN, INFO_MSG, INFO_NONCE_SALT, INFO_RECORD_C2S,
    INFO_RECORD_S2C, INFO_TURN_RATCHET,
};
use crate::kex::{
    hybrid_decap, hybrid_encap, HybridSecret, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
    X25519PublicKey, X25519SecretKey,
};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NonceSalt(pub [u8; 24]);

impl ChainKey {
    /// Symmetric ratchet step. Returns `(next_chain, message_key)`.
    pub fn ratchet(&self) -> (ChainKey, MessageKey) {
        let mk = expand(&self.0, INFO_MSG, 32);
        let nk = expand(&self.0, INFO_CHAIN, 32);
        let mut mk_arr = [0u8; 32];
        mk_arr.copy_from_slice(&mk);
        let mut nk_arr = [0u8; 32];
        nk_arr.copy_from_slice(&nk);
        (ChainKey(nk_arr), MessageKey(mk_arr))
    }
}

impl From<MessageKey> for AeadKey {
    fn from(mk: MessageKey) -> AeadKey {
        let k = AeadKey(mk.0);
        // mk is moved + dropped, zeroized.
        k
    }
}

/// Per-direction ratchet state held by one endpoint.
pub struct SymRatchet {
    pub chain: ChainKey,
}

impl SymRatchet {
    pub fn new(chain: ChainKey) -> Self {
        Self { chain }
    }

    /// Advance the chain and return a one-shot AEAD key for the next frame.
    pub fn next_key(&mut self) -> AeadKey {
        let (next, mk) = self.chain.ratchet();
        self.chain = next;
        mk.into()
    }
}

/// Initial keys derived from the root key after the handshake.
pub struct InitialKeys {
    pub c2s_chain: ChainKey,
    pub s2c_chain: ChainKey,
    pub nonce_salt: NonceSalt,
}

/// Expand the root key into per-direction chain keys plus a 24-B nonce salt.
pub fn derive_initial_keys(root: &RootKey) -> InitialKeys {
    let c2s = expand(&root.0, INFO_RECORD_C2S, 32);
    let s2c = expand(&root.0, INFO_RECORD_S2C, 32);
    let ns = expand(&root.0, INFO_NONCE_SALT, 24);

    let mut c2s_arr = [0u8; 32];
    c2s_arr.copy_from_slice(&c2s);
    let mut s2c_arr = [0u8; 32];
    s2c_arr.copy_from_slice(&s2c);
    let mut ns_arr = [0u8; 24];
    ns_arr.copy_from_slice(&ns);

    InitialKeys {
        c2s_chain: ChainKey(c2s_arr),
        s2c_chain: ChainKey(s2c_arr),
        nonce_salt: NonceSalt(ns_arr),
    }
}

/// Derive the per-frame AEAD nonce by XORing the 24-byte salt with
/// the (epoch, seq) counter laid out in the low 12 bytes.
pub fn frame_nonce(salt: &NonceSalt, epoch: u32, seq: u64) -> [u8; 24] {
    let mut out = salt.0;
    let counter = ((epoch as u128) << 64) | (seq as u128);
    let counter_bytes = counter.to_be_bytes(); // 16 bytes
    for i in 0..16 {
        out[i + 8] ^= counter_bytes[i];
    }
    out
}

/// One step of the per-turn DH ratchet (X25519 only). Kept for callers that
/// don't want a PQ encapsulation per turn.
pub struct DhRatchet;

impl DhRatchet {
    pub fn step(
        prev_root: &RootKey,
        our_sk: &X25519SecretKey,
        peer_pk: &X25519PublicKey,
    ) -> (RootKey, InitialKeys) {
        let ss = our_sk.diffie_hellman(peer_pk);
        let mut ikm = Vec::with_capacity(32 + INFO_TURN_RATCHET.len());
        ikm.extend_from_slice(ss.as_bytes());
        ikm.extend_from_slice(INFO_TURN_RATCHET);
        let prk = extract(&prev_root.0, &ikm);
        let new_root = RootKey(prk);
        let keys = derive_initial_keys(&new_root);
        (new_root, keys)
    }
}

/// Triple-ratchet step: mix BOTH a fresh X25519 ECDH AND a fresh ML-KEM-768
/// encapsulation into the root key. Inspired by Signal SPQR (Oct 2025):
/// classical DH and the PQ KEM are combined via HKDF so a future quantum
/// adversary must break BOTH to recover the new chain.
///
/// The initiator role does encapsulation (against the responder's KEM pk).
/// The responder role does decapsulation. Both sides also mix a fresh X25519
/// ECDH using their own ratchet secret keys and the peer's ratchet pk.
pub struct TripleRatchet;

/// What the initiator emits to the responder so the responder can derive
/// the same new root.
pub struct TurnPayload {
    pub mlkem_ct: MlKemCiphertext,
    pub initiator_x25519_pk: X25519PublicKey,
}

impl TripleRatchet {
    /// Initiator side: produce a new root + the payload to send to the responder.
    pub fn initiate<R: CryptoRngCore>(
        rng: &mut R,
        prev_root: &RootKey,
        responder_mlkem_pk: &MlKemPublicKey,
        responder_x25519_pk: &X25519PublicKey,
    ) -> (RootKey, InitialKeys, TurnPayload) {
        let (mlkem_ct, initiator_x25519_pk, hybrid) =
            hybrid_encap(rng, responder_mlkem_pk, responder_x25519_pk);
        let (root, keys) = derive_turn_root(prev_root, &hybrid);
        (
            root,
            keys,
            TurnPayload {
                mlkem_ct,
                initiator_x25519_pk,
            },
        )
    }

    /// Responder side: consume the initiator's payload + own static secrets,
    /// derive the same new root.
    ///
    /// Returns an error if the attacker-supplied ML-KEM ciphertext is
    /// malformed. With FIPS 203 implicit rejection this is practically
    /// unreachable for valid-length ciphertexts; we surface it anyway
    /// rather than panic.
    pub fn respond(
        prev_root: &RootKey,
        responder_mlkem_sk: &MlKemSecretKey,
        responder_x25519_sk: &X25519SecretKey,
        payload: &TurnPayload,
    ) -> Result<(RootKey, InitialKeys), ullm_core::Error> {
        let hybrid = hybrid_decap(
            responder_mlkem_sk,
            responder_x25519_sk,
            &payload.mlkem_ct,
            &payload.initiator_x25519_pk,
        )?;
        Ok(derive_turn_root(prev_root, &hybrid))
    }
}

fn derive_turn_root(prev_root: &RootKey, hybrid: &HybridSecret) -> (RootKey, InitialKeys) {
    let mut ikm = Vec::with_capacity(64 + INFO_TURN_RATCHET.len());
    ikm.extend_from_slice(&hybrid.0);
    ikm.extend_from_slice(INFO_TURN_RATCHET);
    let prk = extract(&prev_root.0, &ikm);
    let root = RootKey(prk);
    let keys = derive_initial_keys(&root);
    (root, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn symmetric_ratchet_diverges() {
        let ck0 = ChainKey([0u8; 32]);
        let (ck1, mk1) = ck0.ratchet();
        let (_ck2, mk2) = ck1.ratchet();
        assert_ne!(mk1.0, mk2.0);
    }

    #[test]
    fn initial_keys_differ_per_direction() {
        let root = RootKey([42u8; 32]);
        let k = derive_initial_keys(&root);
        assert_ne!(k.c2s_chain.0, k.s2c_chain.0);
    }

    #[test]
    fn frame_nonce_changes_with_seq_and_epoch() {
        let salt = NonceSalt([0u8; 24]);
        let n00 = frame_nonce(&salt, 0, 0);
        let n01 = frame_nonce(&salt, 0, 1);
        let n10 = frame_nonce(&salt, 1, 0);
        assert_ne!(n00, n01);
        assert_ne!(n00, n10);
        assert_ne!(n01, n10);
    }

    #[test]
    fn dh_ratchet_yields_matching_keys_for_both_sides() {
        let mut rng = OsRng;
        let alice_sk = X25519SecretKey::random_from_rng(&mut rng);
        let bob_sk = X25519SecretKey::random_from_rng(&mut rng);
        let alice_pk = X25519PublicKey::from(&alice_sk);
        let bob_pk = X25519PublicKey::from(&bob_sk);

        let prev = RootKey([7u8; 32]);
        let (alice_root, alice_keys) = DhRatchet::step(&prev, &alice_sk, &bob_pk);
        let (bob_root, bob_keys) = DhRatchet::step(&prev, &bob_sk, &alice_pk);
        assert_eq!(alice_root.0, bob_root.0);
        assert_eq!(alice_keys.c2s_chain.0, bob_keys.c2s_chain.0);
        assert_eq!(alice_keys.s2c_chain.0, bob_keys.s2c_chain.0);
    }

    #[test]
    fn triple_ratchet_initiator_and_responder_agree() {
        use crate::kex::ml_kem_keypair;
        let mut rng = OsRng;
        let (responder_kem_sk, responder_kem_pk) = ml_kem_keypair(&mut rng);
        let responder_x25519_sk = X25519SecretKey::random_from_rng(&mut rng);
        let responder_x25519_pk = X25519PublicKey::from(&responder_x25519_sk);

        let prev_root = RootKey([0xAB; 32]);
        let (init_root, init_keys, payload) = TripleRatchet::initiate(
            &mut rng,
            &prev_root,
            &responder_kem_pk,
            &responder_x25519_pk,
        );
        let (resp_root, resp_keys) = TripleRatchet::respond(
            &prev_root,
            &responder_kem_sk,
            &responder_x25519_sk,
            &payload,
        )
        .expect("respond");
        assert_eq!(init_root.0, resp_root.0);
        assert_eq!(init_keys.c2s_chain.0, resp_keys.c2s_chain.0);
        assert_eq!(init_keys.s2c_chain.0, resp_keys.s2c_chain.0);
        assert_eq!(init_keys.nonce_salt.0, resp_keys.nonce_salt.0);
    }
}
