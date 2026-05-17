// SPDX-License-Identifier: Apache-2.0
//! XChaCha20-Poly1305 AEAD wrapper. The 192-bit nonce survives VM snapshot/restore.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ullm_core::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte AEAD key. Always one-shot per frame — never reuse across frames.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub [u8; 32]);

/// Seal `plaintext` under `key` with `nonce` and additional authenticated data `aad`.
///
/// Returns `ciphertext || tag` (Poly1305 tag is 16 B; included in the returned `Vec`).
pub fn aead_seal(key: &AeadKey, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encrypt is infallible for valid lengths")
}

/// Open `ciphertext` (which includes the Poly1305 tag at the end).
pub fn aead_open(key: &AeadKey, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(xnonce, Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = AeadKey([7u8; 32]);
        let nonce = [3u8; 24];
        let aad = b"header";
        let pt = b"hello world";
        let ct = aead_seal(&key, &nonce, aad, pt);
        let pt2 = aead_open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, pt2.as_slice());
    }

    #[test]
    fn aad_tampering_rejected() {
        let key = AeadKey([7u8; 32]);
        let nonce = [3u8; 24];
        let ct = aead_seal(&key, &nonce, b"good", b"data");
        assert!(aead_open(&key, &nonce, b"bad", &ct).is_err());
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let key = AeadKey([7u8; 32]);
        let ct = aead_seal(&key, &[1u8; 24], b"", b"data");
        assert!(aead_open(&key, &[2u8; 24], b"", &ct).is_err());
    }
}
