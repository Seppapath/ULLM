// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use ullm_core::{Error, Result};

pub const ATTESTATION_NONCE_LEN: usize = 32;
pub const RANDOM_LEN: usize = 32;
pub const REPORT_DATA_LEN: usize = 64;

/// Domain-separation prefix prepended to the byte string the TEE identity
/// key signs over for the `PreKeyBundle` (P4-1). Distinct from the
/// handshake-signature prefix so a bundle signature cannot be transferred
/// to satisfy a handshake-signature verification, and vice versa.
pub const SIG_DOMAIN_BUNDLE: &[u8] = b"ULLM-v1 bundle-sig\0";

/// Domain-separation prefix prepended to the `pre_sig_hash` the TEE
/// identity key signs over during `ServerHandshake::respond` (P4-1).
pub const SIG_DOMAIN_HANDSHAKE: &[u8] = b"ULLM-v1 handshake-sig\0";

/// Pre-key bundle published by the server. Attestation evidence is an
/// opaque byte blob: the `ullm-attest` crate defines and verifies its content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Long-term Ed25519 identity public key (32 B).
    pub id_pk: [u8; 32],
    /// Signed X25519 pre-key — feeds the initial X25519 ECDH.
    pub spk_pk_x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 B, serialized as bytes).
    pub pq_pk_mlkem: Vec<u8>,
    /// Opaque CPU + GPU attestation evidence, freshness-bound to a server nonce.
    pub attestation_evidence: Vec<u8>,
    /// Ed25519 signature over the canonical serialization of the bundle fields
    /// (excluding this field) by `id_pk`.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl PreKeyBundle {
    /// Structural validation. Called immediately after deserialization on
    /// every ingress path so an attacker can't push the codec deeper into
    /// the protocol with malformed length fields.
    pub fn validate_structural(&self) -> Result<()> {
        if self.pq_pk_mlkem.len() != ullm_core::ML_KEM_768_EK_LEN {
            return Err(Error::BadCipherSuite);
        }
        if self.attestation_evidence.len() > ullm_core::MAX_ATTESTATION_EVIDENCE_LEN {
            return Err(Error::Other(format!(
                "attestation_evidence exceeds cap: {} > {}",
                self.attestation_evidence.len(),
                ullm_core::MAX_ATTESTATION_EVIDENCE_LEN
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub client_random: [u8; RANDOM_LEN],
    pub attestation_nonce: [u8; ATTESTATION_NONCE_LEN],
    pub client_x25519_pk: [u8; 32],
    pub client_mlkem_ct: Vec<u8>, // ~1088 B
    /// Long-session X25519 public key used for the bidirectional DH ratchet
    /// (mid-stream `KeyUpdate` and per-turn rotation). Distinct from
    /// `client_x25519_pk`, which is consumed by the handshake encap.
    pub client_ratchet_pk: [u8; 32],
    pub cipher_suite: CipherSuite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u8,
    pub server_random: [u8; RANDOM_LEN],
    /// Ephemeral X25519 public key for the per-turn ratchet.
    pub server_x25519_pk: [u8; 32],
    /// Fresh attestation evidence binding `client_random || attestation_nonce ||
    /// server_x25519_pk || hash(hybrid_ss)`.
    pub attestation_evidence: Vec<u8>,
    /// Signature over the transcript hash by the TEE identity key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSuite {
    pub kem: u16,
    pub aead: u8,
    pub hash: u8,
}

impl CipherSuite {
    pub fn default_phase1() -> Self {
        Self {
            kem: ullm_core::KemId::X25519MlKem768 as u16,
            aead: ullm_core::AeadId::XChaCha20Poly1305 as u8,
            hash: ullm_core::HashId::Sha256 as u8,
        }
    }

    /// Validate that every field encodes a supported algorithm. Phase 1
    /// only wires up X25519-ML-KEM-768 + XChaCha20-Poly1305 + SHA-256 in
    /// the record layer; the `AeadId::Aes256GcmSiv` / `HashId::Sha384`
    /// variants exist in the enum for future protocol versions but the
    /// record codec doesn't dispatch on them. P4-2/P4-3 audit: silently
    /// accepting them was a downgrade trap — the peer would advertise
    /// AES-GCM-SIV, both sides would proceed with hardcoded XChaCha, and
    /// the protocol's "negotiated cipher suite" was effectively a lie.
    /// Now we reject anything we don't actually implement.
    pub fn validate(self) -> Result<()> {
        if ullm_core::KemId::from_u16(self.kem).is_none() {
            return Err(Error::BadCipherSuite);
        }
        // P4-2: explicit HashId validation; previously the `hash` byte
        // was completely unchecked.
        if ullm_core::HashId::from_u8(self.hash).is_none() {
            return Err(Error::BadCipherSuite);
        }
        // P4-3: reject AEAD algorithms whose record-layer dispatch isn't
        // implemented. Currently that's everything except XChaCha20-Poly1305.
        match ullm_core::AeadId::from_u8(self.aead) {
            Some(ullm_core::AeadId::XChaCha20Poly1305) => {}
            Some(_) | None => return Err(Error::BadCipherSuite),
        }
        // Phase 1 hardcodes SHA-256 in the transcript + HKDF; reject any
        // other hash for the same reason — otherwise the negotiated value
        // is unverifiable.
        if ullm_core::HashId::from_u8(self.hash) != Some(ullm_core::HashId::Sha256) {
            return Err(Error::BadCipherSuite);
        }
        Ok(())
    }
}

/// Wire serialization helpers (postcard, deterministic).
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|e| Error::Serde(e.to_string()))
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    postcard::from_bytes(bytes).map_err(|e| Error::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_phase1_validates() {
        CipherSuite::default_phase1().validate().expect("default OK");
    }

    /// Regression for P4-3: `AeadId::Aes256GcmSiv` (= 0x02) is a defined
    /// enum variant, but the Phase 1 record layer doesn't implement it.
    /// The handshake validation must reject it explicitly rather than
    /// pass-through, otherwise a peer can advertise the unimplemented
    /// suite, both sides hardcode XChaCha, and the negotiation field is
    /// a silent lie.
    #[test]
    fn rejects_unimplemented_aead_aes_gcm_siv() {
        let mut s = CipherSuite::default_phase1();
        s.aead = ullm_core::AeadId::Aes256GcmSiv as u8;
        assert!(s.validate().is_err());
    }

    /// Regression for P4-3: an `aead` byte that doesn't decode to any
    /// known `AeadId` must be rejected (it always was) — guard against
    /// future regressions.
    #[test]
    fn rejects_unknown_aead_byte() {
        let mut s = CipherSuite::default_phase1();
        s.aead = 0xFF;
        assert!(s.validate().is_err());
    }

    /// Regression for P4-2: the `hash` byte was previously accepted as
    /// any u8; an attacker could set it to garbage. Now an unknown hash
    /// id is rejected.
    #[test]
    fn rejects_unknown_hash_byte() {
        let mut s = CipherSuite::default_phase1();
        s.hash = 0x42;
        assert!(s.validate().is_err());
    }

    /// Regression for P4-2: even a *known* HashId other than SHA-256 is
    /// rejected, because Phase 1 hardcodes SHA-256 everywhere — silently
    /// accepting SHA-384 here would be a downgrade trap of the same shape
    /// as the AES-GCM-SIV one.
    #[test]
    fn rejects_known_but_unimplemented_hash() {
        let mut s = CipherSuite::default_phase1();
        s.hash = ullm_core::HashId::Sha384 as u8;
        assert!(s.validate().is_err());
    }
}
