// SPDX-License-Identifier: Apache-2.0
//! WebAssembly bindings.
//!
//! The browser owns the WebSocket transport — this module exposes the
//! protocol primitives needed to drive it: bundle verification, the PQXDH
//! handshake state machine, the AEAD record codec, and receipt verification.
//!
//! Typical JS flow:
//!   1. `fetch(/v1/attest?nonce=…)` → bundle bytes
//!   2. `client = ClientSession.start(bundle, attestation_nonce, trust_root, now_unix)`
//!   3. send `client.client_hello_bytes()` over the WebSocket
//!   4. receive the ServerHello bytes; `client.complete(server_hello_bytes, now_unix)`
//!   5. encrypt prompts with `client.encrypt(plaintext)` and decrypt tokens with
//!      `client.decrypt(frame_bytes)`
//!   6. when END_OF_TURN flag is observed, call `client.verify_receipt(bytes)`

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use ullm_attest::{evidence::decode_evidence, MockVerifier, VerificationContext, Verifier};
use ullm_crypto::{NonceSalt, SymRatchet};
use ullm_handshake::{ClientHandshake, PreKeyBundle};
use ullm_receipts::SignedReceipt;
use ullm_wire::{decode_frame, encode_frame, FrameFlags, FrameType, ReplayWindow};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ClientSession {
    state: SessionInner,
}

enum SessionInner {
    /// Transient state used only during the `Pending → Open` transition
    /// inside `complete()`. Avoids the older pattern of constructing a
    /// placeholder `VerifyingKey::from_bytes(&[0; 32])` which the dalek
    /// crate rejects as not-on-curve and which therefore could panic.
    Replacing,
    /// Terminal failure state. A session that errored partway through
    /// `complete()` lands here so subsequent calls return a clear
    /// "session poisoned: <reason>" instead of the misleading
    /// "session is mid-transition" the bare `Replacing` placeholder would
    /// otherwise leak (P2-11). The string is the original error message.
    Poisoned(String),
    Pending {
        handshake: ClientHandshake,
        client_hello: Vec<u8>,
        attestation_nonce: [u8; 32],
        trust_root: VerifyingKey,
        tee_id_pk: VerifyingKey,
        tee_receipt_pk: VerifyingKey,
        now_unix: u64,
    },
    Open {
        c2s: SymRatchet,
        s2c: SymRatchet,
        nonce_salt: NonceSalt,
        epoch: ullm_core::Epoch,
        c2s_seq: u64,
        s2c_replay: ReplayWindow,
        tee_receipt_pk: VerifyingKey,
        /// Per-turn DH ratchet state. Updated in-place when the server sends
        /// a `Control::KeyUpdate`, so long streams + mid-stream rotations
        /// stay correct.
        current_root: ullm_crypto::RootKey,
        client_ratchet_sk: ullm_crypto::X25519SecretKey,
    },
}

#[wasm_bindgen]
impl ClientSession {
    /// Initialize: verify the bundle, build a `ClientHello`. The returned
    /// bytes are sent over the WebSocket as the first message.
    #[wasm_bindgen(js_name = start)]
    pub fn start(
        bundle_bytes: &[u8],
        attestation_nonce: &[u8],
        trust_root_bytes: &[u8],
        tee_receipt_pk_bytes: &[u8],
        expected_weight_commit: &[u8],
        now_unix: u64,
    ) -> Result<ClientSession, JsError> {
        let bundle: PreKeyBundle =
            postcard::from_bytes(bundle_bytes).map_err(|e| JsError::new(&e.to_string()))?;
        // P2-9: reject malformed-length bundles before any further parsing
        // touches the ML-KEM ek or the attestation evidence.
        bundle
            .validate_structural()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let attestation_nonce: [u8; 32] = attestation_nonce
            .try_into()
            .map_err(|_| JsError::new("attestation_nonce must be 32 bytes"))?;
        let weight_commit: [u8; 32] = expected_weight_commit
            .try_into()
            .map_err(|_| JsError::new("expected_weight_commit must be 32 bytes"))?;
        let trust_root = pk_from_bytes(trust_root_bytes)?;
        let tee_receipt_pk = pk_from_bytes(tee_receipt_pk_bytes)?;
        let tee_id_pk = verify_bundle(
            &bundle,
            &attestation_nonce,
            &weight_commit,
            &trust_root,
            now_unix,
            60,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;

        let mut rng = OsRng;
        let (handshake, client_hello) = ClientHandshake::initiate(&mut rng, &bundle)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(ClientSession {
            state: SessionInner::Pending {
                handshake,
                client_hello,
                attestation_nonce,
                trust_root,
                tee_id_pk,
                tee_receipt_pk,
                now_unix,
            },
        })
    }

    /// The bytes to send as the first WebSocket message.
    #[wasm_bindgen(js_name = clientHelloBytes)]
    pub fn client_hello_bytes(&self) -> Result<Vec<u8>, JsError> {
        match &self.state {
            SessionInner::Pending { client_hello, .. } => Ok(client_hello.clone()),
            _ => Err(JsError::new("session is not in Pending state")),
        }
    }

    /// Consume the server's `ServerHello`; the session is then `Open` and
    /// ready for `encrypt`/`decrypt`.
    ///
    /// On any failure the session is permanently poisoned (P2-11): all
    /// subsequent calls return a clear "session poisoned" error rather
    /// than the previous behaviour of getting stuck in `Replacing` and
    /// reporting the misleading "session is mid-transition" on every op.
    pub fn complete(&mut self, server_hello: &[u8]) -> Result<(), JsError> {
        // Helper that poisons the state with `msg` and returns the same
        // error to JS. Used at every failure point inside `complete()` so
        // the state machine is total — there is no path that leaves the
        // session in `Replacing` once we return.
        fn poison(slot: &mut SessionInner, msg: String) -> JsError {
            let e = JsError::new(&msg);
            *slot = SessionInner::Poisoned(msg);
            e
        }

        // Move data out of `Pending` while the slot temporarily holds
        // `Replacing`. Any subsequent error path swaps it to `Poisoned`.
        let prev = std::mem::replace(&mut self.state, SessionInner::Replacing);
        let (handshake, attestation_nonce, trust_root, tee_id_pk, tee_receipt_pk, now_unix) =
            match prev {
                SessionInner::Pending {
                    handshake,
                    attestation_nonce,
                    trust_root,
                    tee_id_pk,
                    tee_receipt_pk,
                    now_unix,
                    ..
                } => (handshake, attestation_nonce, trust_root, tee_id_pk, tee_receipt_pk, now_unix),
                SessionInner::Poisoned(reason) => {
                    let msg = format!("session poisoned: {reason}");
                    return Err(poison(&mut self.state, msg));
                }
                SessionInner::Replacing => {
                    return Err(poison(
                        &mut self.state,
                        "complete() called concurrently with itself".into(),
                    ));
                }
                _ => {
                    return Err(poison(
                        &mut self.state,
                        "complete() called when session was not Pending".into(),
                    ));
                }
            };
        let _ = attestation_nonce;
        let _ = trust_root;
        // Snapshot the client's ratchet sk bytes BEFORE `complete()` consumes
        // the handshake struct — we need to keep it client-side to drive the
        // per-turn DH ratchet on every server-initiated KeyUpdate.
        let client_ratchet_sk_bytes: [u8; 32] =
            *handshake.client_ratchet_sk().as_bytes();
        let keys = match handshake.complete(server_hello, |pre_hash, sig| {
            // P4-1: mirror `ullm-tee::service`'s domain-separation prefix.
            let sig = Signature::from_bytes(sig);
            let mut payload = Vec::with_capacity(
                ullm_handshake::SIG_DOMAIN_HANDSHAKE.len() + pre_hash.len(),
            );
            payload.extend_from_slice(ullm_handshake::SIG_DOMAIN_HANDSHAKE);
            payload.extend_from_slice(pre_hash);
            tee_id_pk
                .verify(&payload, &sig)
                .map_err(|_| ullm_core::Error::AttestationFailed("bad ServerHello sig".into()))
        }) {
            Ok(k) => k,
            Err(e) => return Err(poison(&mut self.state, e.to_string())),
        };

        let evidence = match decode_evidence(&keys.server_attestation_evidence) {
            Ok(e) => e,
            Err(e) => return Err(poison(&mut self.state, e.to_string())),
        };
        let verifier = MockVerifier::new(trust_root);
        if let Err(e) = verifier.verify(
            &evidence,
            &VerificationContext {
                expected_report_data: &keys.report_data,
                now_unix,
                max_age_sec: 60,
            },
        ) {
            return Err(poison(&mut self.state, e.to_string()));
        }

        let client_ratchet_sk =
            ullm_crypto::X25519SecretKey::from(client_ratchet_sk_bytes);

        self.state = SessionInner::Open {
            c2s: SymRatchet::new(keys.c2s_chain),
            s2c: SymRatchet::new(keys.s2c_chain),
            nonce_salt: keys.nonce_salt,
            epoch: ullm_core::Epoch(0),
            c2s_seq: 0,
            s2c_replay: ReplayWindow::new(),
            tee_receipt_pk,
            current_root: keys.root,
            client_ratchet_sk,
        };
        Ok(())
    }

    /// Encrypt a plaintext prompt; the result is one DATA frame ready for the
    /// WebSocket.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let SessionInner::Open {
            c2s,
            nonce_salt,
            epoch,
            c2s_seq,
            ..
        } = &mut self.state
        else {
            return Err(JsError::new("session not Open"));
        };
        let key = c2s.next_key();
        let out = encode_frame(
            &key,
            nonce_salt,
            FrameType::Data,
            FrameFlags::empty(),
            *epoch,
            ullm_core::Seq(*c2s_seq),
            plaintext,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
        *c2s_seq = c2s_seq.checked_add(1).ok_or_else(|| JsError::new("seq overflow"))?;
        Ok(out.wire)
    }

    /// Decrypt one inbound frame.
    ///
    /// Returns `DecryptResult { text, endOfTurn }`. **Control frames**
    /// (specifically `Control::KeyUpdate`) are handled transparently: the
    /// session advances its per-turn DH ratchet in place and the call
    /// returns an empty `text` with `endOfTurn=false`, telling the JS host
    /// "frame consumed, ask for the next one".
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<DecryptResult, JsError> {
        let SessionInner::Open {
            c2s,
            s2c,
            nonce_salt,
            epoch,
            c2s_seq,
            s2c_replay,
            current_root,
            client_ratchet_sk,
            ..
        } = &mut self.state
        else {
            return Err(JsError::new("session not Open"));
        };
        let key = s2c.next_key();
        let (header, plaintext) =
            decode_frame(&key, nonce_salt, frame).map_err(|e| JsError::new(&e.to_string()))?;
        s2c_replay
            .check_and_update(header.seq)
            .map_err(|e| JsError::new(&e.to_string()))?;
        match header.frame_type {
            FrameType::Data => Ok(DecryptResult {
                text: String::from_utf8(plaintext)
                    .map_err(|_| JsError::new("non-utf8 token chunk"))?,
                end_of_turn: header.flags.contains(FrameFlags::END_OF_TURN),
            }),
            FrameType::Control => {
                let ctrl = ullm_wire::Control::decode(&plaintext)
                    .map_err(|e| JsError::new(&e.to_string()))?;
                match ctrl {
                    ullm_wire::Control::KeyUpdate { new_pk } => {
                        let new_server_pk = ullm_crypto::X25519PublicKey::from(new_pk);
                        let (new_root, new_keys) = ullm_crypto::DhRatchet::step(
                            current_root,
                            client_ratchet_sk,
                            &new_server_pk,
                        );
                        *current_root = new_root;
                        *c2s = SymRatchet::new(new_keys.c2s_chain);
                        *s2c = SymRatchet::new(new_keys.s2c_chain);
                        *nonce_salt = new_keys.nonce_salt;
                        *epoch = ullm_core::Epoch(epoch.0.wrapping_add(1));
                        *c2s_seq = 0;
                        *s2c_replay = ReplayWindow::new();
                        Ok(DecryptResult {
                            text: String::new(),
                            end_of_turn: false,
                        })
                    }
                    other => Err(JsError::new(&format!(
                        "unsupported control frame: {:?}",
                        other
                    ))),
                }
            }
            other => Err(JsError::new(&format!("unexpected frame type {:?}", other))),
        }
    }

    /// Verify the trailing signed-receipt envelope.
    #[wasm_bindgen(js_name = verifyReceipt)]
    pub fn verify_receipt(&self, raw: &[u8]) -> Result<ReceiptJs, JsError> {
        let SessionInner::Open { tee_receipt_pk, .. } = &self.state else {
            return Err(JsError::new("session not Open"));
        };
        let signed: SignedReceipt =
            postcard::from_bytes(raw).map_err(|e| JsError::new(&e.to_string()))?;
        ullm_receipts::verify(&signed, tee_receipt_pk)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ReceiptJs {
            model: signed.receipt.model,
            input_tokens: signed.receipt.input_tokens,
            output_tokens: signed.receipt.output_tokens,
            epoch: signed.receipt.epoch,
            issued_at_unix: signed.receipt.issued_at_unix,
            session_id_hex: hex::encode(signed.receipt.session.0),
        })
    }
}

#[wasm_bindgen]
pub struct DecryptResult {
    text: String,
    end_of_turn: bool,
}

#[wasm_bindgen]
impl DecryptResult {
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.text.clone()
    }

    #[wasm_bindgen(getter, js_name = endOfTurn)]
    pub fn end_of_turn(&self) -> bool {
        self.end_of_turn
    }
}

#[wasm_bindgen]
pub struct ReceiptJs {
    model: String,
    input_tokens: u32,
    output_tokens: u32,
    epoch: u32,
    issued_at_unix: u64,
    session_id_hex: String,
}

#[wasm_bindgen]
impl ReceiptJs {
    #[wasm_bindgen(getter)]
    pub fn model(&self) -> String {
        self.model.clone()
    }
    #[wasm_bindgen(getter, js_name = inputTokens)]
    pub fn input_tokens(&self) -> u32 {
        self.input_tokens
    }
    #[wasm_bindgen(getter, js_name = outputTokens)]
    pub fn output_tokens(&self) -> u32 {
        self.output_tokens
    }
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    #[wasm_bindgen(getter, js_name = issuedAtUnix)]
    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }
    #[wasm_bindgen(getter, js_name = sessionIdHex)]
    pub fn session_id_hex(&self) -> String {
        self.session_id_hex.clone()
    }
}

fn pk_from_bytes(b: &[u8]) -> Result<VerifyingKey, JsError> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| JsError::new(&e.to_string()))
}

/// Mirror of `ullm_client::verify_bundle` without ed25519 / tokio depends.
/// Cross-binds `expected_weight_commit` into the report_data check.
fn verify_bundle(
    bundle: &PreKeyBundle,
    expected_nonce: &[u8; 32],
    expected_weight_commit: &[u8; 32],
    trust_root: &VerifyingKey,
    now_unix: u64,
    max_age_sec: u64,
) -> Result<VerifyingKey, ullm_core::Error> {
    let id_pk = VerifyingKey::from_bytes(&bundle.id_pk)
        .map_err(|_| ullm_core::Error::AttestationFailed("invalid id_pk".into()))?;
    // P4-1: must match the TEE-side prefix in
    // `ullm-tee::identity::TeeIdentity::build_bundle`. The native
    // verifier in `ullm-client::attest_check::verify_bundle` already
    // does this; this WASM mirror needs to do the same or every
    // browser session fails with "bad bundle signature".
    let mut buf = Vec::new();
    buf.extend_from_slice(ullm_handshake::SIG_DOMAIN_BUNDLE);
    buf.extend_from_slice(&bundle.id_pk);
    buf.extend_from_slice(&bundle.spk_pk_x25519);
    buf.extend_from_slice(&bundle.pq_pk_mlkem);
    buf.extend_from_slice(&bundle.attestation_evidence);
    let sig = Signature::from_bytes(&bundle.signature);
    id_pk
        .verify(&buf, &sig)
        .map_err(|_| ullm_core::Error::AttestationFailed("bad bundle signature".into()))?;
    let evidence = decode_evidence(&bundle.attestation_evidence)?;
    let expected_report_data = {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(b"ULLM-v1 bundle-attest");
        h.update(bundle.id_pk);
        h.update(bundle.spk_pk_x25519);
        h.update(&bundle.pq_pk_mlkem);
        h.update(expected_nonce);
        h.update(expected_weight_commit);
        let arr: [u8; 64] = h.finalize().into();
        arr
    };
    let verifier = MockVerifier::new(*trust_root);
    verifier.verify(
        &evidence,
        &VerificationContext {
            expected_report_data: &expected_report_data,
            now_unix,
            max_age_sec,
        },
    )?;
    Ok(id_pk)
}
