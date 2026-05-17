// SPDX-License-Identifier: Apache-2.0
//! Handshake transcript hash.

use sha2::{Digest, Sha256};

/// Append-only hasher used to bind handshake messages to the derived keys.
///
/// The transcript begins with the protocol-id label and is updated with
/// `ClientHello` bytes then `ServerHello` bytes. The final 32-byte digest
/// becomes the salt for `HKDF-Extract`.
#[derive(Default)]
pub struct Transcript(Sha256);

impl Transcript {
    pub fn new() -> Self {
        let mut h = Sha256::new();
        h.update(ullm_core::PROTOCOL_ID.as_bytes());
        Self(h)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn hash(&self) -> [u8; 32] {
        let h = self.0.clone();
        h.finalize().into()
    }
}
