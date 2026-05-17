// SPDX-License-Identifier: Apache-2.0
//! Onion layer cryptography.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use ullm_core::{Error, Result};
use x25519_dalek::{PublicKey, StaticSecret};

/// One relay's identity: a long-lived X25519 keypair + a routing label.
pub struct Relay {
    pub label: String,
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Relay {
    pub fn random<R: CryptoRngCore>(label: impl Into<String>, rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self {
            label: label.into(),
            secret,
            public,
        }
    }
}

/// One on-the-wire layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    pub ephemeral_pk: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Inside the AEAD, each layer reveals: (next hop label or None for terminal,
/// inner bytes which are either the next OnionLayer or the final payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LayerInner {
    next_hop: Option<String>,
    inner: Vec<u8>,
}

const AEAD_INFO: &[u8] = b"ULLM-overlay-v1";
const AEAD_NONCE: [u8; 12] = *b"ULLMonion-v1";

/// Wrap a destination payload in `relay_chain.len()` nested onion layers.
/// The first relay in `relay_chain` is the entry hop; the last is the exit.
pub fn wrap_layers<R: CryptoRngCore>(
    rng: &mut R,
    relay_chain: &[(String, PublicKey)],
    destination_payload: &[u8],
) -> Result<Vec<u8>> {
    if relay_chain.is_empty() {
        return Err(Error::Other("onion needs at least one relay".into()));
    }
    // Build from the innermost layer outward.
    let mut current = destination_payload.to_vec();
    let mut next_hop_label: Option<String> = None;
    for (label, relay_pk) in relay_chain.iter().rev() {
        let ephemeral = StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_pk = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(relay_pk);
        let key = derive_aead_key(shared.as_bytes(), ephemeral_pk.as_bytes());

        let inner = LayerInner {
            next_hop: next_hop_label.clone(),
            inner: current,
        };
        let plaintext = postcard::to_allocvec(&inner).map_err(|e| Error::Serde(e.to_string()))?;
        let aead = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(&AEAD_NONCE);
        let ct = aead
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: ephemeral_pk.as_bytes(),
                },
            )
            .map_err(|_| Error::Other("AEAD seal failed".into()))?;
        let layer = OnionLayer {
            ephemeral_pk: *ephemeral_pk.as_bytes(),
            ciphertext: ct,
        };
        current = postcard::to_allocvec(&layer).map_err(|e| Error::Serde(e.to_string()))?;
        next_hop_label = Some(label.clone());
    }
    Ok(current)
}

/// Peel one layer. Returns `(next_hop_label_or_terminal, inner_bytes)`.
/// `inner_bytes` is either the next `OnionLayer` serialization or the final
/// destination payload when `next_hop_label_or_terminal` is `None`.
pub fn peel_layer(relay_secret: &StaticSecret, layer_bytes: &[u8]) -> Result<(Option<String>, Vec<u8>)> {
    let layer: OnionLayer =
        postcard::from_bytes(layer_bytes).map_err(|e| Error::Serde(e.to_string()))?;
    let ephemeral_pk = PublicKey::from(layer.ephemeral_pk);
    let shared = relay_secret.diffie_hellman(&ephemeral_pk);
    let key = derive_aead_key(shared.as_bytes(), ephemeral_pk.as_bytes());

    let aead = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&AEAD_NONCE);
    let plaintext = aead
        .decrypt(
            nonce,
            Payload {
                msg: &layer.ciphertext,
                aad: &layer.ephemeral_pk,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    let inner: LayerInner =
        postcard::from_bytes(&plaintext).map_err(|e| Error::Serde(e.to_string()))?;
    Ok((inner.next_hop, inner.inner))
}

fn derive_aead_key(shared: &[u8], ephemeral_pk: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pk), shared);
    let mut out = [0u8; 32];
    hk.expand(AEAD_INFO, &mut out)
        .expect("32 bytes within HKDF-SHA256 budget");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn one_hop_roundtrip() {
        let mut rng = OsRng;
        let r = Relay::random("exit", &mut rng);
        let chain = [(r.label.clone(), r.public)];
        let wrapped = wrap_layers(&mut rng, &chain, b"hello").unwrap();
        let (next, inner) = peel_layer(&r.secret, &wrapped).unwrap();
        assert!(next.is_none(), "single-relay chain peels to terminal");
        assert_eq!(inner, b"hello");
    }

    #[test]
    fn three_hop_peels_in_order() {
        let mut rng = OsRng;
        let r1 = Relay::random("guard", &mut rng);
        let r2 = Relay::random("middle", &mut rng);
        let r3 = Relay::random("exit", &mut rng);
        let chain = [
            (r1.label.clone(), r1.public),
            (r2.label.clone(), r2.public),
            (r3.label.clone(), r3.public),
        ];
        let wrapped = wrap_layers(&mut rng, &chain, b"payload").unwrap();

        let (n1, inner1) = peel_layer(&r1.secret, &wrapped).unwrap();
        assert_eq!(n1.as_deref(), Some("middle"));
        let (n2, inner2) = peel_layer(&r2.secret, &inner1).unwrap();
        assert_eq!(n2.as_deref(), Some("exit"));
        let (n3, inner3) = peel_layer(&r3.secret, &inner2).unwrap();
        assert!(n3.is_none());
        assert_eq!(inner3, b"payload");
    }

    #[test]
    fn wrong_relay_cannot_peel() {
        let mut rng = OsRng;
        let real = Relay::random("real", &mut rng);
        let foreign = Relay::random("foreign", &mut rng);
        let wrapped = wrap_layers(&mut rng, &[(real.label.clone(), real.public)], b"x").unwrap();
        assert!(peel_layer(&foreign.secret, &wrapped).is_err());
    }

    #[test]
    fn middle_relay_sees_neither_origin_nor_destination() {
        // The middle relay's peel yields (Some("exit"), <next layer bytes>).
        // It learns the next hop name but nothing about the payload content
        // (which is encrypted to the exit relay) or about who originated the
        // request (lost two hops back).
        let mut rng = OsRng;
        let r1 = Relay::random("guard", &mut rng);
        let r2 = Relay::random("middle", &mut rng);
        let r3 = Relay::random("exit", &mut rng);
        let chain = [
            (r1.label.clone(), r1.public),
            (r2.label.clone(), r2.public),
            (r3.label.clone(), r3.public),
        ];
        let wrapped = wrap_layers(&mut rng, &chain, b"top-secret").unwrap();
        let (_, after_guard) = peel_layer(&r1.secret, &wrapped).unwrap();
        let (next_from_middle, after_middle) = peel_layer(&r2.secret, &after_guard).unwrap();

        // Middle knows about the exit by label but the payload bytes contain
        // ciphertext (an OnionLayer encrypted to r3), not plaintext.
        assert_eq!(next_from_middle.as_deref(), Some("exit"));
        assert!(!after_middle.windows(b"top-secret".len()).any(|w| w == b"top-secret"));
    }
}
