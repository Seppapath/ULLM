// SPDX-License-Identifier: Apache-2.0
//! Signed usage receipts.
//!
//! Each response emitted by the TEE is accompanied by a `Receipt` signed with
//! a TEE-resident Ed25519 key. The gateway aggregates receipts for billing
//! without ever seeing plaintext. A receipt is bound to its session, model,
//! token counts, and the AEAD epoch that produced it.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use ullm_core::{Error, Result, SessionId, TenantId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub tenant: TenantId,
    pub session: SessionId,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub epoch: u32,
    pub issued_at_unix: u64,
    /// Phase 2: count of KV-cache rows that were KV-Cloak'd during the session.
    pub kv_blocks_cloaked: u32,
    /// Phase 2 / P13-FIX-D: hex-encoded 32-byte canonical digest binding the
    /// **token-id stream** the engine actually emitted. The stream is encoded
    /// as `u32-LE(count)` followed by `count` × `u32-LE(id)` and hashed
    /// alongside `input_hash` under a domain-separated SHA-256.
    ///
    /// Binding token IDs (rather than the decoded UTF-8 the user sees)
    /// closes a collision: two distinct BPE token sequences can decode to
    /// the same string under byte-fallback merges, and a decode-failure
    /// silently drops a token from the user-visible stream. The token-id
    /// digest pins the canonical sequence the inference engine produced.
    pub output_digest_hex: String,
    /// P13-FIX-D: hex-encoded 32-byte digest over the decoded UTF-8 output.
    /// Computed as SHA-256 of `("ULLM-v1 string-digest", input_hash, utf8_bytes)`.
    /// Useful for UI/debug surfaces that want to bind the *displayed* output
    /// — distinct from `output_digest_hex` because two different token
    /// sequences can decode to the same string.
    pub output_string_digest_hex: String,
    /// Phase 3: hex-encoded 32-byte commitment to the verifiable model's weights.
    /// Must match the binding in the TEE's attestation `report_data`.
    pub weight_commit_hex: String,
    /// Phase 3: hex-encoded 32-byte Poseidon commitments to each activation
    /// vector in the verifiable forward pass. Length = NUM_LAYERS + 1
    /// (input + each layer's output).
    pub activation_commits_hex: Vec<String>,
}

impl Receipt {
    /// Structural sanity check: every field that downstream verifiers rely
    /// on must be present and well-formed. Phase 3 audit (P3-7) made the
    /// Phase 3 fields non-`serde(default)` so a wire receipt missing them
    /// no longer silently deserialises to an empty string — but at the API
    /// surface we still validate that the in-memory shape is what we sign.
    pub fn validate_structural(&self) -> Result<()> {
        if self.weight_commit_hex.len() != 64 {
            return Err(Error::BadReceipt);
        }
        if !self.weight_commit_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::BadReceipt);
        }
        for c in &self.activation_commits_hex {
            if c.len() != 64 || !c.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::BadReceipt);
            }
        }
        if self.output_digest_hex.len() != 64
            || !self
                .output_digest_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::BadReceipt);
        }
        // P13-FIX-D: the decoded-UTF-8 digest is required and shares the
        // same shape constraint as `output_digest_hex` (32-byte SHA-256,
        // hex-encoded).
        if self.output_string_digest_hex.len() != 64
            || !self
                .output_string_digest_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::BadReceipt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Envelope delivered at end-of-turn. The receipt is independently signed;
/// the ZK proofs are optional, and (when present) one per model layer opens
/// `(activation_commits_hex[i], activation_commits_hex[i+1])` as public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    pub signed_receipt: SignedReceipt,
    /// Per-layer ZK proofs. Length = 0 for optimistic mode, NUM_LAYERS for full ZK mode.
    #[serde(default)]
    pub zk_layer_proofs: Vec<Vec<u8>>,
}

pub struct ReceiptSigner {
    key: SigningKey,
}

impl ReceiptSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign a structurally-valid receipt. P5-7 audit: previously this
    /// would happily sign a `Receipt` whose `weight_commit_hex` (or
    /// other Phase 3 fields) was empty, malformed, or wrong length —
    /// `verify()` would later reject it, but only on the receiving
    /// side. Now we gate the sign path on the same `validate_structural`
    /// check so a programming error at the TEE is caught immediately
    /// instead of producing a "valid signature, malformed payload"
    /// receipt that ships to the client.
    pub fn sign(&self, receipt: Receipt) -> Result<SignedReceipt> {
        receipt.validate_structural()?;
        let bytes = canonical_bytes(&receipt);
        let sig: Signature = self.key.sign(&bytes);
        Ok(SignedReceipt {
            receipt,
            signature: sig.to_bytes(),
        })
    }
}

pub fn verify(signed: &SignedReceipt, tee_pk: &VerifyingKey) -> Result<()> {
    // P3-7: gate every verify on structural sanity. A receipt that
    // deserialises but has a malformed `weight_commit_hex` (empty,
    // wrong length, non-hex) is rejected here before we even check the
    // signature — closing the "lenient parse + lax downstream check"
    // foot-gun.
    signed.receipt.validate_structural()?;
    let bytes = canonical_bytes(&signed.receipt);
    let sig = Signature::from_bytes(&signed.signature);
    tee_pk
        .verify(&bytes, &sig)
        .map_err(|_| Error::BadReceipt)
}

fn canonical_bytes(r: &Receipt) -> Vec<u8> {
    // postcard is deterministic — the canonical form for signing.
    postcard::to_allocvec(r).expect("postcard serialization is infallible for valid types")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn receipt() -> Receipt {
        Receipt {
            tenant: TenantId("acme".into()),
            session: SessionId([1u8; 16]),
            model: "llama-3.1-70b".into(),
            input_tokens: 42,
            output_tokens: 128,
            epoch: 0,
            issued_at_unix: 1_700_000_000,
            kv_blocks_cloaked: 0,
            output_digest_hex: "00".repeat(32),
            output_string_digest_hex: "33".repeat(32),
            weight_commit_hex: "11".repeat(32),
            activation_commits_hex: vec!["22".repeat(32); 9],
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = key.verifying_key();
        let signer = ReceiptSigner::new(key);
        let signed = signer.sign(receipt()).unwrap();
        verify(&signed, &pk).unwrap();
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = key.verifying_key();
        let signer = ReceiptSigner::new(key);
        let mut signed = signer.sign(receipt()).unwrap();
        signed.receipt.output_tokens += 1;
        assert!(verify(&signed, &pk).is_err());
    }

    /// Regression for P5-9: a receipt that's tampered in *any* field —
    /// not just the obvious ones — must break verification. This is the
    /// signature-payload-coverage assertion: every Receipt field must be
    /// covered by the postcard canonical bytes that get signed.
    #[test]
    fn tampered_any_field_breaks_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = key.verifying_key();
        let signer = ReceiptSigner::new(key);
        let original = signer.sign(receipt()).unwrap();
        let sig_bytes = original.signature;

        // For each tampered receipt we lift the original 64-byte signature
        // onto it; if the field was actually covered by the signed bytes,
        // verify() must fail.
        let mutations: Vec<(&str, Box<dyn Fn() -> Receipt>)> = vec![
            ("tenant", Box::new(|| {
                let mut r = receipt();
                r.tenant = TenantId("evil".into());
                r
            })),
            ("session", Box::new(|| {
                let mut r = receipt();
                r.session = SessionId([2u8; 16]);
                r
            })),
            ("model", Box::new(|| {
                let mut r = receipt();
                r.model = "attacker-model".into();
                r
            })),
            ("input_tokens", Box::new(|| {
                let mut r = receipt();
                r.input_tokens = 9_999;
                r
            })),
            ("epoch", Box::new(|| {
                let mut r = receipt();
                r.epoch = 99;
                r
            })),
            ("issued_at_unix", Box::new(|| {
                let mut r = receipt();
                r.issued_at_unix = 99_999;
                r
            })),
            ("kv_blocks_cloaked", Box::new(|| {
                let mut r = receipt();
                r.kv_blocks_cloaked = 42;
                r
            })),
        ];
        for (field, mutate) in mutations {
            let tampered = SignedReceipt {
                receipt: mutate(),
                signature: sig_bytes,
            };
            assert!(
                verify(&tampered, &pk).is_err(),
                "tampering field {field} must invalidate signature"
            );
        }
    }

    #[test]
    fn wrong_key_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other_pk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let signer = ReceiptSigner::new(key);
        let signed = signer.sign(receipt()).unwrap();
        assert!(verify(&signed, &other_pk).is_err());
    }

    /// Regression for P3-7 / P5-7: a malformed `weight_commit_hex` is
    /// rejected by the *sign* path now too — previously only the verify
    /// side caught it, so a buggy TEE could ship corrupt receipts to
    /// clients.
    #[test]
    fn empty_weight_commit_rejected_at_sign() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let _pk = key.verifying_key();
        let signer = ReceiptSigner::new(key);
        let mut r = receipt();
        r.weight_commit_hex = String::new();
        assert!(signer.sign(r).is_err());
    }

    /// Regression for P3-7 / P5-7: a malformed activation commit hex is
    /// rejected by the sign path. Sender-side gating.
    #[test]
    fn malformed_activation_commit_rejected_at_sign() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let _pk = key.verifying_key();
        let signer = ReceiptSigner::new(key);
        let mut r = receipt();
        r.activation_commits_hex[0] = "ZZ".repeat(32);
        assert!(signer.sign(r).is_err());
    }
}
