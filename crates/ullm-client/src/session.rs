// SPDX-License-Identifier: Apache-2.0
//! High-level `Session` API and streaming response.
//!
//! Supports plaintext (`http://`) and TLS (`https://`) gateways. When TLS is
//! used, the caller pins the gateway cert by SHA-256 fingerprint — see
//! `ullm_tls::SelfSignedCert::fingerprint`.

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use ullm_attest::{evidence::decode_evidence, MockVerifier, VerificationContext, Verifier as _};
use ullm_core::{Epoch, Error, Result, Seq};
use ullm_crypto::{DhRatchet, NonceSalt, RootKey, SymRatchet, X25519PublicKey, X25519SecretKey};
use ullm_handshake::{ClientHandshake, PreKeyBundle};
use ullm_receipts::{ReceiptEnvelope, SignedReceipt};
use ullm_wire::{decode_frame, encode_frame, Control, FrameFlags, FrameType, ReplayWindow};

use crate::attest_check::verify_bundle;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Optional TLS configuration. When `None`, the session uses plaintext HTTP/WS
/// (only acceptable for loopback dev).
#[derive(Clone)]
pub struct TlsPinning {
    pub config: Arc<ClientConfig>,
    pub server_name: String,
}

impl TlsPinning {
    /// Build a TLS pinning config from a SHA-256 fingerprint. The pin is
    /// bound to a single `server_name` (P2-7) — the cert MUST also list
    /// that name in its SANs or the handshake fails.
    pub fn pin(server_name: impl Into<String>, fingerprint: [u8; 32]) -> Self {
        ullm_tls::install_default_crypto_provider();
        let server_name = server_name.into();
        let sans = vec![server_name.clone()];
        Self {
            config: ullm_tls::client_config_pinned(fingerprint, sans)
                .expect("PQ-hybrid client config build is infallible for valid pinning"),
            server_name,
        }
    }

    /// Pin a fingerprint that's valid for multiple names. Useful when the
    /// server cert lists both `localhost` and `127.0.0.1`, for instance.
    pub fn pin_multi(
        server_name: impl Into<String>,
        fingerprint: [u8; 32],
        allowed_sans: Vec<String>,
    ) -> Self {
        ullm_tls::install_default_crypto_provider();
        Self {
            config: ullm_tls::client_config_pinned(fingerprint, allowed_sans)
                .expect("PQ-hybrid client config build is infallible for valid pinning"),
            server_name: server_name.into(),
        }
    }

    /// P13-FIX-A: build a *strict* PQ-hybrid pinned config. Identical
    /// fingerprint + SAN semantics to [`Self::pin`], but the rustls
    /// `kx_groups` are restricted to `X25519MLKEM768` only — there is no
    /// classical X25519 / secp256r1 fallback. A MITM that strips the
    /// PQ-hybrid named group from the server's `supported_groups` (or a
    /// non-PQ gateway) fails the handshake instead of silently
    /// negotiating classical-only key exchange.
    ///
    /// Use this in deployments where post-quantum confidentiality is a
    /// hard requirement rather than a preference; the peer **must** speak
    /// `X25519MLKEM768` or the connection is refused.
    pub fn pin_strict_pq(server_name: impl Into<String>, fingerprint: [u8; 32]) -> Self {
        ullm_tls::install_default_crypto_provider();
        let server_name = server_name.into();
        let sans = vec![server_name.clone()];
        Self {
            config: ullm_tls::client_config_pinned_strict_pq(fingerprint, sans)
                .expect("strict PQ-hybrid client config build is infallible for valid pinning"),
            server_name,
        }
    }

    /// P13-FIX-A: strict-PQ multi-SAN variant of [`Self::pin_multi`]. See
    /// [`Self::pin_strict_pq`] for the security tradeoff.
    pub fn pin_multi_strict_pq(
        server_name: impl Into<String>,
        fingerprint: [u8; 32],
        allowed_sans: Vec<String>,
    ) -> Self {
        ullm_tls::install_default_crypto_provider();
        Self {
            config: ullm_tls::client_config_pinned_strict_pq(fingerprint, allowed_sans)
                .expect("strict PQ-hybrid client config build is infallible for valid pinning"),
            server_name: server_name.into(),
        }
    }
}

pub struct Session {
    ws: Ws,
    s2c: SymRatchet,
    nonce_salt: NonceSalt,
    epoch: Epoch,
    s2c_replay: ReplayWindow,
    c2s: SymRatchet,
    c2s_seq: u64,
    current_root: RootKey,
    server_ratchet_pk: X25519PublicKey,
    client_ratchet_sk: X25519SecretKey,
    tee_id_pk: VerifyingKey,
    tee_receipt_pk: VerifyingKey,
    /// Optional per-layer ZK verifier. When set, `finalize()` requires that
    /// the envelope carry `NUM_LAYERS` proofs and verifies each one against
    /// the receipt's `activation_commits_hex`.
    layer_verifier: Option<Arc<dyn LayerVerifier>>,
    /// Expected weight commitment — cross-checked against
    /// `receipt.weight_commit_hex`. The attestation evidence binds this in
    /// `report_data`, but verifying twice catches a TEE that issues a
    /// well-formed attestation but emits a tampered receipt.
    expected_weight_commit: [u8; 32],
}

/// Pluggable verifier for Phase 3's per-layer ZK proofs.
///
/// Given the (N+1)-vector of activation commitments and the N proofs, verify
/// that each proof `proofs[i]` opens `(commits[i], commits[i+1])`.
///
/// P13-FIX-C: the verifier also receives the `session_id` and the model's
/// `weight_commit`. These flow into each per-layer instance vector and
/// a mismatch (e.g. a proof captured from another session, or a proof
/// minted under a different model) makes the underlying Halo2 verify
/// reject. The verifier implementation is responsible for indexing the
/// layer it's verifying (`i` of `0..N`) and supplying `(session_id,
/// weight_commit, layer_idx=i)` to the underlying
/// `LayerVerifier::verify`.
pub trait LayerVerifier: Send + Sync + 'static {
    fn verify_layers(
        &self,
        activation_commits: &[[u8; 32]],
        proofs: &[Vec<u8>],
        session_id: &ullm_core::SessionId,
        weight_commit: &[u8; 32],
    ) -> Result<()>;
}

impl Session {
    /// Open a session: fetch the attestation bundle (cross-binding the
    /// expected weight commitment), verify it, run the PQXDH handshake,
    /// return the live session.
    pub async fn connect(
        base_url: &str,
        trust_root: &VerifyingKey,
        tee_receipt_pk: &VerifyingKey,
        expected_weight_commit: [u8; 32],
        tls: Option<TlsPinning>,
    ) -> Result<Self> {
        Self::connect_with(
            base_url,
            trust_root,
            tee_receipt_pk,
            expected_weight_commit,
            tls,
            None,
        )
        .await
    }

    /// Open a session with an optional Phase 3 per-layer ZK verifier.
    pub async fn connect_with(
        base_url: &str,
        trust_root: &VerifyingKey,
        tee_receipt_pk: &VerifyingKey,
        expected_weight_commit: [u8; 32],
        tls: Option<TlsPinning>,
        layer_verifier: Option<Arc<dyn LayerVerifier>>,
    ) -> Result<Self> {
        let attestation_nonce = random_nonce();
        let bundle = fetch_bundle(base_url, &attestation_nonce, tls.as_ref()).await?;
        // P3-2: capture wall-clock *after* the bundle fetch (network IO can
        // take hundreds of ms). Re-read it again before every subsequent
        // freshness check so the attestation's effective TTL window is the
        // actual TTL — not "TTL plus however long the bundle took to fetch".
        let now_bundle = now_unix()?;
        let tee_id_pk = verify_bundle(
            &bundle,
            &attestation_nonce,
            &expected_weight_commit,
            trust_root,
            now_bundle,
            ullm_core::NONCE_TTL_DEFAULT_SEC,
        )?;

        let mut rng = OsRng;
        let (client_state, client_hello_bytes) = ClientHandshake::initiate(&mut rng, &bundle)?;
        let client_ratchet_sk = X25519SecretKey::from(*client_state.client_ratchet_sk().as_bytes());

        let ws_url = ws_stream_url(base_url, tls.is_some());
        let connector = match &tls {
            Some(t) => Some(tokio_tungstenite::Connector::Rustls(t.config.clone())),
            None => None,
        };
        let (mut ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            ws_url,
            None,
            false,
            connector,
        )
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
        ws.send(Message::Binary(client_hello_bytes))
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let server_hello_bytes = read_binary(&mut ws).await?;

        let keys = client_state.complete(&server_hello_bytes, |pre_hash, sig| {
            // P4-1: must mirror the TEE-side prefix in
            // `ullm-tee::service::handle_session`. Mismatch → verify fails.
            let sig = Signature::from_bytes(sig);
            let mut payload = Vec::with_capacity(
                ullm_handshake::SIG_DOMAIN_HANDSHAKE.len() + pre_hash.len(),
            );
            payload.extend_from_slice(ullm_handshake::SIG_DOMAIN_HANDSHAKE);
            payload.extend_from_slice(pre_hash);
            tee_id_pk
                .verify(&payload, &sig)
                .map_err(|_| Error::AttestationFailed("bad ServerHello signature".into()))
        })?;

        let evidence = decode_evidence(&keys.server_attestation_evidence)?;
        let verifier = MockVerifier::new(*trust_root);
        // P3-2: re-read the clock right before verifying the ServerHello's
        // attestation evidence. The handshake itself may take another round
        // trip; using the earlier `now_bundle` would silently stretch the
        // freshness window across both fetch and handshake latencies.
        let now_handshake = now_unix()?;
        verifier.verify(
            &evidence,
            &VerificationContext {
                expected_report_data: &keys.report_data,
                now_unix: now_handshake,
                max_age_sec: ullm_core::NONCE_TTL_DEFAULT_SEC,
            },
        )?;

        let server_ratchet_pk = keys.server_ratchet_pk;
        let current_root = keys.root.clone();
        Ok(Self {
            ws,
            s2c: SymRatchet::new(keys.s2c_chain),
            nonce_salt: keys.nonce_salt,
            epoch: Epoch(0),
            s2c_replay: ReplayWindow::new(),
            c2s: SymRatchet::new(keys.c2s_chain),
            c2s_seq: 0,
            current_root,
            server_ratchet_pk,
            client_ratchet_sk,
            tee_id_pk,
            tee_receipt_pk: *tee_receipt_pk,
            layer_verifier,
            expected_weight_commit,
        })
    }

    pub fn tee_id_pk(&self) -> VerifyingKey {
        self.tee_id_pk
    }

    /// Advance the bidirectional DH ratchet in response to a server
    /// `KeyUpdate`. Both sides land on the same new root + chain keys.
    fn apply_key_update(&mut self, new_server_pk_bytes: [u8; 32]) -> Result<()> {
        let new_server_pk = X25519PublicKey::from(new_server_pk_bytes);
        let (new_root, new_keys) =
            DhRatchet::step(&self.current_root, &self.client_ratchet_sk, &new_server_pk);
        self.current_root = new_root;
        self.s2c = SymRatchet::new(new_keys.s2c_chain);
        self.c2s = SymRatchet::new(new_keys.c2s_chain);
        self.nonce_salt = new_keys.nonce_salt;
        self.server_ratchet_pk = new_server_pk;
        self.epoch = Epoch(self.epoch.0.wrapping_add(1));
        self.c2s_seq = 0;
        self.s2c_replay = ReplayWindow::new();
        Ok(())
    }

    /// Send a prompt; receive a stream of decrypted token chunks.
    pub async fn send(&mut self, prompt: &str) -> Result<TokenStream<'_>> {
        let key = self.c2s.next_key();
        let frame = encode_frame(
            &key,
            &self.nonce_salt,
            FrameType::Data,
            FrameFlags::empty(),
            self.epoch,
            Seq(self.c2s_seq),
            prompt.as_bytes(),
        )?;
        self.ws
            .send(Message::Binary(frame.wire))
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        self.c2s_seq = self
            .c2s_seq
            .checked_add(1)
            .ok_or_else(|| Error::Other("c2s seq overflow".into()))?;
        Ok(TokenStream { session: self, ended: false })
    }
}

pub struct TokenStream<'a> {
    session: &'a mut Session,
    ended: bool,
}

impl<'a> TokenStream<'a> {
    /// Next decrypted token chunk. `Ok(None)` after END_OF_TURN; call
    /// `finalize()` next to read and verify the signed receipt.
    ///
    /// Transparently absorbs server-initiated `KeyUpdate` control frames:
    /// when one arrives, the DH ratchet advances and the next loop iteration
    /// uses the new chain keys.
    pub async fn next_token(&mut self) -> Result<Option<String>> {
        loop {
            if self.ended {
                return Ok(None);
            }
            let bytes = read_binary(&mut self.session.ws).await?;
            let key = self.session.s2c.next_key();
            let (header, plaintext) = decode_frame(&key, &self.session.nonce_salt, &bytes)?;
            if header.epoch != self.session.epoch {
                return Err(Error::Other(format!(
                    "unexpected epoch transition: got {:?}, have {:?}",
                    header.epoch, self.session.epoch
                )));
            }
            self.session.s2c_replay.check_and_update(header.seq)?;
            match header.frame_type {
                FrameType::Data => {
                    if header.flags.contains(FrameFlags::END_OF_TURN) {
                        self.ended = true;
                        if plaintext.is_empty() {
                            return Ok(None);
                        }
                    }
                    let s = String::from_utf8(plaintext)
                        .map_err(|_| Error::Other("non-utf8 token chunk".into()))?;
                    return Ok(Some(s));
                }
                FrameType::Control => {
                    let ctrl = Control::decode(&plaintext)?;
                    if let Control::KeyUpdate { new_pk } = ctrl {
                        self.session.apply_key_update(new_pk)?;
                    } else {
                        return Err(Error::Other(format!(
                            "unexpected control frame: {:?}",
                            ctrl
                        )));
                    }
                }
                other => {
                    return Err(Error::Other(format!("unexpected frame type {:?}", other)));
                }
            }
        }
    }

    /// Read + verify the signed usage receipt (and the optional Phase 3
    /// per-layer ZK proofs) that follows END_OF_TURN.
    pub async fn finalize(self) -> Result<SignedReceipt> {
        let session = self.session;
        let raw = read_binary(&mut session.ws).await?;
        let envelope: ReceiptEnvelope =
            postcard::from_bytes(&raw).map_err(|e| Error::Serde(e.to_string()))?;
        ullm_receipts::verify(&envelope.signed_receipt, &session.tee_receipt_pk)?;

        // Weight commit cross-check: also verified via attestation; this is the
        // belt-and-suspenders check on the receipt itself.
        let receipt_weight_commit_bytes = hex::decode(
            &envelope.signed_receipt.receipt.weight_commit_hex,
        )
        .map_err(|e| Error::Other(format!("bad weight_commit_hex: {e}")))?;
        let receipt_weight_commit: [u8; 32] = receipt_weight_commit_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Other("weight_commit_hex is not 32 bytes".into()))?;
        if receipt_weight_commit != session.expected_weight_commit {
            return Err(Error::AttestationFailed(
                "receipt weight commit does not match expected".into(),
            ));
        }

        if let Some(verifier) = &session.layer_verifier {
            let receipt = &envelope.signed_receipt.receipt;
            let mut commits = Vec::with_capacity(receipt.activation_commits_hex.len());
            for h in &receipt.activation_commits_hex {
                let b = hex::decode(h)
                    .map_err(|e| Error::Other(format!("bad activation commit hex: {e}")))?;
                let arr: [u8; 32] = b
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Other("activation commit not 32 bytes".into()))?;
                commits.push(arr);
            }
            // P13-FIX-C: pass session id and weight commit through so each
            // per-layer proof's instance vector can be reconstructed
            // identically to the prover. The receipt's own `session`
            // field is the source of truth for the session id — it's
            // signed end-to-end by the TEE, so a forged commit list
            // can't smuggle a stale session in.
            let session_id = envelope.signed_receipt.receipt.session;
            verifier.verify_layers(
                &commits,
                &envelope.zk_layer_proofs,
                &session_id,
                &session.expected_weight_commit,
            )?;
        }

        Ok(envelope.signed_receipt)
    }
}

/// Hard cap on how long a single `read_binary` call may block waiting for
/// the *next* WebSocket message. P4-8: without this, a stalled or
/// malicious gateway that keeps the WS alive but stops forwarding can
/// cause `next_token()` or `finalize()` to hang indefinitely. 60 s is
/// well above any honest server's per-token latency while still capping
/// the worst-case wait.
const WS_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn read_binary(ws: &mut Ws) -> Result<Vec<u8>> {
    loop {
        let next = match tokio::time::timeout(WS_READ_TIMEOUT, ws.next()).await {
            Ok(n) => n,
            Err(_) => {
                return Err(Error::Transport(format!(
                    "ws idle for {}s — peer stalled (P4-8)",
                    WS_READ_TIMEOUT.as_secs()
                )));
            }
        };
        match next {
            Some(Ok(Message::Binary(b))) => return Ok(b),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => return Err(Error::Transport("ws closed".into())),
            Some(Ok(other)) => {
                return Err(Error::Transport(format!("unexpected ws msg: {:?}", other)))
            }
            Some(Err(e)) => return Err(Error::Transport(e.to_string())),
            None => return Err(Error::Transport("ws ended unexpectedly".into())),
        }
    }
}

async fn fetch_bundle(
    base_url: &str,
    nonce: &[u8; 32],
    tls: Option<&TlsPinning>,
) -> Result<PreKeyBundle> {
    let url = format!(
        "{}/v1/attest?nonce={}",
        base_url.trim_end_matches('/'),
        hex::encode(nonce)
    );
    let bytes = http_get(&url, tls).await?;
    let bundle: PreKeyBundle =
        postcard::from_bytes(&bytes).map_err(|e| Error::Serde(e.to_string()))?;
    // P2-9: structural validation gates every wire-derived bundle before
    // signatures or attestation evidence get parsed downstream.
    bundle.validate_structural()?;
    Ok(bundle)
}

/// Minimal HTTP/1.1 GET over TCP, optionally TLS-wrapped via rustls.
async fn http_get(url: &str, tls: Option<&TlsPinning>) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let parsed = parse_http_url(url, tls.is_some())?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host
    );
    let tcp = TcpStream::connect((parsed.host.as_str(), parsed.port))
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;

    let buf = if let Some(t) = tls {
        let server_name = ServerName::try_from(t.server_name.clone())
            .map_err(|e| Error::Transport(format!("bad server_name: {e}")))?;
        let connector = TlsConnector::from(t.config.clone());
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        stream.write_all(req.as_bytes()).await.map_err(|e| Error::Transport(e.to_string()))?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.map_err(|e| Error::Transport(e.to_string()))?;
        buf
    } else {
        let mut stream = tcp;
        stream.write_all(req.as_bytes()).await.map_err(|e| Error::Transport(e.to_string()))?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.map_err(|e| Error::Transport(e.to_string()))?;
        buf
    };

    let body_idx = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Transport("bad HTTP response".into()))?;
    let head = &buf[..body_idx];
    let status_line = std::str::from_utf8(head)
        .map_err(|_| Error::Transport("non-utf8 HTTP header".into()))?
        .lines()
        .next()
        .unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err(Error::Transport(format!("HTTP status: {status_line}")));
    }
    Ok(buf[body_idx + 4..].to_vec())
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str, expect_tls: bool) -> Result<ParsedUrl> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::Transport(format!("bad url: {url}")))?;
    let want_https = expect_tls;
    match (scheme, want_https) {
        ("http", false) | ("https", true) => (),
        _ => {
            return Err(Error::Transport(format!(
                "scheme {scheme} does not match TLS mode {want_https}"
            )))
        }
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| Error::Transport("bad port".into()))?,
        ),
        None => (
            host_port.to_string(),
            if scheme == "https" { 443 } else { 80 },
        ),
    };
    Ok(ParsedUrl { host, port, path })
}

fn ws_stream_url(base: &str, tls: bool) -> String {
    let base = base.trim_end_matches('/');
    let (scheme, rest) = match base.split_once("://") {
        Some(x) => x,
        None => return format!("ws://{base}/v1/stream"),
    };
    let ws_scheme = match (scheme, tls) {
        ("http", false) | ("ws", false) => "ws",
        ("https", true) | ("wss", true) => "wss",
        _ => {
            if tls {
                "wss"
            } else {
                "ws"
            }
        }
    };
    format!("{ws_scheme}://{rest}/v1/stream")
}

fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

/// Read wall-clock seconds since UNIX epoch. P6 audit: was previously
/// `unwrap_or(0)`, which silently passed a pre-1970 clock through as
/// `now = 0`, making every `saturating_sub(now, issued_at)` collapse to
/// `0` and every freshness check trivially pass. Now we fail closed —
/// if the system clock is set before 1970, refuse to verify rather
/// than treat the attestation as eternally fresh.
fn now_unix() -> Result<u64> {
    ullm_core::clock::now_unix()
}

// Suppress unused-import warnings on platforms that don't need both:
#[allow(dead_code)]
fn _unused<T: AsyncRead + AsyncWrite>(_: T) {}
