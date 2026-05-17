// SPDX-License-Identifier: Apache-2.0
//! HMAC-signed session tokens for stateless sticky routing.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub replica_id: String,
    pub epoch: u32,
    pub expiry_unix: u64,
}

pub struct SessionTokenSigner {
    key: [u8; 32],
}

impl SessionTokenSigner {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn sign(&self, token: &SessionToken) -> String {
        let body = format!("{}.{}.{}", token.replica_id, token.epoch, token.expiry_unix);
        let mac = self.mac(body.as_bytes());
        format!("{body}.{}", hex::encode(mac))
    }

    pub fn verify(&self, encoded: &str) -> Option<SessionToken> {
        let last_dot = encoded.rfind('.')?;
        let (body, tag_hex) = encoded.split_at(last_dot);
        let tag_hex = &tag_hex[1..];
        let expected = hex::encode(self.mac(body.as_bytes()));
        // P12-FIX-B: constant-time MAC compare via `subtle::ct_eq`.
        // The previous hand-rolled `subtle_compare` was a plain
        // `diff |= x ^ y` loop with no compiler-fence — under the
        // workspace's `lto = "fat"` + `codegen-units = 1` profile,
        // LLVM could legally optimize the OR-accumulation into a
        // SIMD-vectorized early-exit on the first non-zero lane,
        // turning the check into a timing oracle on the HMAC tag.
        // `subtle::ct_eq` uses `core::hint::black_box` to fence the
        // optimizer and survives fat LTO across crate boundaries.
        let eq: bool = expected.as_bytes().ct_eq(tag_hex.as_bytes()).into();
        if !eq {
            return None;
        }
        let mut parts = body.splitn(3, '.');
        let replica = parts.next()?.to_string();
        let epoch: u32 = parts.next()?.parse().ok()?;
        let expiry: u64 = parts.next()?.parse().ok()?;
        Some(SessionToken {
            replica_id: replica,
            epoch,
            expiry_unix: expiry,
        })
    }

    fn mac(&self, body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let signer = SessionTokenSigner::new([7u8; 32]);
        let tok = SessionToken {
            replica_id: "tee-001".into(),
            epoch: 3,
            expiry_unix: 1_700_000_000,
        };
        let encoded = signer.sign(&tok);
        let decoded = signer.verify(&encoded).unwrap();
        assert_eq!(tok, decoded);
    }

    #[test]
    fn tampered_token_rejected() {
        let signer = SessionTokenSigner::new([7u8; 32]);
        let tok = SessionToken {
            replica_id: "tee-001".into(),
            epoch: 3,
            expiry_unix: 1_700_000_000,
        };
        let mut encoded = signer.sign(&tok);
        encoded.replace_range(0..1, "x");
        assert!(signer.verify(&encoded).is_none());
    }

    #[test]
    fn wrong_key_rejected() {
        let signer = SessionTokenSigner::new([7u8; 32]);
        let other = SessionTokenSigner::new([8u8; 32]);
        let tok = SessionToken {
            replica_id: "tee-001".into(),
            epoch: 0,
            expiry_unix: 0,
        };
        let encoded = signer.sign(&tok);
        assert!(other.verify(&encoded).is_none());
    }
}
