// SPDX-License-Identifier: Apache-2.0
//! Axum service exposing the TEE protocol.
//!
//! Endpoints:
//! - `GET /v1/attest?nonce=<hex32>` — returns a postcard-encoded `PreKeyBundle`.
//! - `GET /v1/healthz` — liveness.
//! - `GET /v1/stream` — WebSocket upgrade; runs the handshake then streams tokens.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::{ed25519::signature::Signer, Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use ullm_core::{Epoch, Seq, SessionId, TenantId};
use ullm_crypto::{DhRatchet, RootKey, SymRatchet, X25519PublicKey, X25519SecretKey};
use ullm_handshake::ServerHandshake;
use ullm_kvcloak::CLOAK_BLOCK_LEN;
use ullm_model::{Model, VEC_DIM};
use ullm_receipts::{Receipt, ReceiptEnvelope, ReceiptSigner};
use ullm_wire::{decode_frame, encode_frame, Control, FrameFlags, FrameType};
use ullm_zk::Fp;

/// Hard cap on how long the TEE will block waiting for a single
/// WebSocket message to flush out. P5-2 audit: without this, a slow
/// client (or a malicious gateway that reads at 1 byte/sec) holds the
/// TEE task in `sender.send().await` indefinitely. Mirrors the
/// client's `WS_READ_TIMEOUT`; an honest peer drains far faster.
const WS_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Wrap a single WS `send().await` in a timeout. Surfaces a clean error
/// instead of letting the calling task block forever — the
/// `InferenceTaskGuard` below then aborts the inference task on early
/// return.
async fn send_ws<S>(sender: &mut S, msg: Message) -> anyhow::Result<()>
where
    S: SinkExt<Message, Error = axum::Error> + Unpin,
{
    match tokio::time::timeout(WS_SEND_TIMEOUT, sender.send(msg)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow::anyhow!("ws send: {e}")),
        Err(_) => Err(anyhow::anyhow!(
            "ws send timeout after {}s — peer not draining",
            WS_SEND_TIMEOUT.as_secs()
        )),
    }
}

/// RAII guard for the spawned inference task. P5-3 audit: previously a
/// `?` early-return from the streaming loop would leave the
/// `tokio::spawn`ed `engine.run` task orphaned — running until the LLM
/// finished (or forever) while the WS was already gone. The guard
/// `abort()`s on drop unless `finish()` is explicitly called on the
/// success path.
struct InferenceTaskGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl InferenceTaskGuard {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Success-path consumer: lets the inference task finish naturally.
    async fn finish(mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for InferenceTaskGuard {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Insert a `key_update` after this many output DATA frames. Set to 0 to
/// disable mid-stream key rotation entirely.
const KEY_UPDATE_EVERY_N_CHUNKS: u32 = 2;

use crate::identity::TeeIdentity;
use crate::inference::{InferenceEngine, TokenChunk};
use crate::nonce_registry::NonceRegistry;
use crate::tenant::TenantPool;

#[derive(Clone)]
pub struct AppState {
    pub identity: Arc<TeeIdentity>,
    pub engine: Arc<dyn InferenceEngine>,
    pub receipt_signer: Arc<ReceiptSigner>,
    pub model_name: String,
    pub tenants: Arc<TenantPool>,
    /// Phase 3: the verifiable synthetic model. Runs in parallel with the
    /// inference engine to produce committed activation traces.
    pub verifiable_model: Arc<Model>,
    /// Optional Phase 3 per-layer ZK prover. When set, the TEE attaches one
    /// proof per layer to the `ReceiptEnvelope`.
    pub layer_prover: Option<Arc<dyn LayerProver>>,
    /// P4-5: per-TEE registry that rejects re-use of attestation nonces.
    /// Defaults to a fresh registry shared across all sessions hosted by
    /// this `AppState` clone (it's an `Arc` so all clones see the same
    /// table).
    pub nonce_registry: Arc<NonceRegistry>,
}

/// Pluggable per-layer ZK prover.
///
/// Given the activation trace through the verifiable model, produce one
/// proof per layer opening `(activation_commit[i], activation_commit[i+1])`
/// as public inputs.
///
/// P13-FIX-C: the trait now passes the **session id** and the model's
/// **weight commit** through to the prover so each per-layer proof can
/// bind them into its public-input vector. Together with `layer_idx`
/// (the prover knows this from its own index in the loop), this
/// prevents a proof minted for `(session_a, layer_i)` from being
/// presented as evidence for `(session_b, *)` or for layer `j ≠ i`.
pub trait LayerProver: Send + Sync + 'static {
    fn prove_trace(
        &self,
        trace: &ullm_model::Trace,
        session_id: &SessionId,
        weight_commit: &[u8; 32],
    ) -> anyhow::Result<Vec<Vec<u8>>>;
}

impl AppState {
    pub fn tee_verifying_key(&self) -> VerifyingKey {
        self.receipt_signer.verifying_key()
    }
}

pub fn router(state: AppState) -> Router {
    // `mut` is only needed when the dev-keys feature is on, since the prod
    // build doesn't reassign `router`. Annotated to keep both builds
    // warning-clean instead of paying a cfg_attr or splitting the function.
    #[cfg_attr(not(feature = "dev-keys"), allow(unused_mut))]
    let mut router = Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/attest", get(attest))
        .route("/v1/stream", get(stream));
    #[cfg(feature = "dev-keys")]
    {
        router = router.route("/v1/devkeys", get(devkeys));
    }
    router.with_state(state)
}

/// P9-FIX-C: management router for `/metrics`. The gateway is the only
/// thing that should ever reach this — exposing `ullm_tee_*` gauges
/// outside the trust boundary would leak per-tenant pool size at
/// scrape granularity (a session-fingerprinting side channel). Bound
/// to `ULLM_TEE_METRICS_ADDR` (default `127.0.0.1:9101`) — separate
/// from the protocol port so a misconfigured `ULLM_TEE_ADDR=0.0.0.0`
/// doesn't accidentally publish metrics.
pub fn metrics_router(state: AppState) -> Router {
    let token = std::env::var("ULLM_METRICS_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    // P11-FIX-D: gate only `/metrics` via `route_layer` — `/v1/healthz`
    // stays unauthenticated so a mgmt-side LB probe can succeed
    // without the token. Empty-body 404 on auth-fail matches axum's
    // unknown-route default exactly, defeating response-length
    // fingerprinting.
    let metrics_route = if let Some(expected) = token {
        let expected = Arc::new(expected);
        get(metrics).route_layer(axum::middleware::from_fn(move |req, next| {
            let expected = expected.clone();
            async move { metrics_auth_gate(expected, req, next).await }
        }))
    } else {
        get(metrics).route_layer(axum::middleware::from_fn(
            |req, next: axum::middleware::Next| async move { next.run(req).await },
        ))
    };
    Router::new()
        .route("/metrics", metrics_route)
        .route("/v1/healthz", get(healthz))
        .with_state(state)
}

/// P10-FIX-D + P11-FIX-D middleware: constant-time bearer-token check.
/// Case-insensitive scheme parse per RFC 7235 §2.1; empty-body 404 on
/// miss so the response is byte-for-byte axum's default 404.
async fn metrics_auth_gate(
    expected: Arc<String>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use subtle::ConstantTimeEq;
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_bearer_credential)
        .unwrap_or("");
    let ok: bool = presented.as_bytes().ct_eq(expected.as_bytes()).into();
    if ok {
        next.run(req).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// RFC 7235 §2.1: auth-scheme matching MUST be case-insensitive;
/// `1*SP` is allowed between scheme and credential.
fn parse_bearer_credential(s: &str) -> Option<&str> {
    let trimmed = s.trim_start();
    let mut parts = trimmed.splitn(2, |c: char| c.is_ascii_whitespace());
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let cred = parts.next()?.trim_start();
    Some(cred)
}

/// Prometheus text-format `/metrics` endpoint. Mirrors the gateway's
/// — exposes the bounded-table sizes (nonce registry, tenant pool)
/// against their compile-time caps so an operator can alert before the
/// table starts evicting working entries under sustained load.
async fn metrics(State(state): State<AppState>) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    let nonce_count = state.nonce_registry.len();
    let tenant_count = state.tenants.tenant_count();
    let body = format!(
        "\
# HELP ullm_tee_protocol_version Wire protocol version this binary speaks.
# TYPE ullm_tee_protocol_version gauge
ullm_tee_protocol_version {protocol}
# HELP ullm_tee_nonce_registry_size Live attestation-nonce-replay tracker size.
# TYPE ullm_tee_nonce_registry_size gauge
ullm_tee_nonce_registry_size {nonce_count}
# HELP ullm_tee_tenant_pool_size Live tenant-state count.
# TYPE ullm_tee_tenant_pool_size gauge
ullm_tee_tenant_pool_size {tenant_count}
",
        protocol = ullm_core::PROTOCOL_VERSION,
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn healthz() -> &'static str {
    "ok"
}

/// **Dev-only** convenience endpoint that exposes the public keys the
/// WASM/Python clients need to bootstrap a session against a mock TEE:
///
/// - `trust_root_hex`: the `MockIssuer`'s verifying key. In a real
///   deployment this is replaced by Intel / AMD / NVIDIA vendor PKI roots
///   pre-configured in the client.
/// - `tee_receipt_pk_hex`: the `ReceiptSigner`'s verifying key. In a real
///   deployment the gateway publishes a signed list of approved TEE keys
///   and the client verifies the receipt against that list.
/// - `weight_commit_hex`: the verifiable model's weight commitment.
///
/// Compiled out in production via `--no-default-features` (or
/// `--features prod`). When the `dev-keys` Cargo feature is OFF, the
/// route is not registered and any incoming request gets a 404.
#[cfg(feature = "dev-keys")]
async fn devkeys(State(state): State<AppState>) -> axum::Json<serde_json::Value> {
    let trust_root = state.identity.attest_issuer.verifying_key();
    let receipt_pk = state.receipt_signer.verifying_key();
    axum::Json(serde_json::json!({
        "trust_root_hex": hex::encode(trust_root.as_bytes()),
        "tee_receipt_pk_hex": hex::encode(receipt_pk.as_bytes()),
        "weight_commit_hex": hex::encode(state.identity.weight_commit),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestQuery {
    nonce: String,
}

async fn attest(
    State(state): State<AppState>,
    Query(q): Query<AttestQuery>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let nonce_bytes = hex::decode(&q.nonce)
        .map_err(|_| (StatusCode::BAD_REQUEST, "nonce is not hex".to_string()))?;
    let nonce: [u8; 32] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "nonce must be 32 bytes".to_string()))?;
    // P4-5: refuse to issue evidence for a nonce we've already attested.
    // A client that replays a captured nonce against this TEE (or against
    // a sibling TEE pointed at the same registry) used to receive a
    // freshly-signed bundle, enabling cross-instance identity linkage.
    state
        .nonce_registry
        .observe(nonce)
        .map_err(|_| (StatusCode::CONFLICT, "attestation_nonce replay".to_string()))?;
    // P6 clock-skew: fail closed if the system clock is pre-1970. The
    // freshness timestamp gets stamped into the attestation evidence,
    // so silently zeroing it would make every freshly-issued bundle
    // look eternally fresh to the verifier (saturating_sub to zero
    // wins every TTL comparison).
    let now = ullm_core::clock::now_unix().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("system clock unusable: {e}"),
        )
    })?;
    let bundle = state.identity.build_bundle(&nonce, now);
    let bytes = ullm_handshake::messages::encode(&bundle)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(bytes)
}

async fn stream(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant = sanitized_tenant(&headers);
    // P2-2: mirror the gateway's WS size cap so a peer that connects
    // directly to the TEE (e.g. via the in-process demo or sidecar) hits the
    // same ceiling. Without this the TEE is a fatter target than the
    // gateway it sits behind.
    ws.max_message_size(ullm_core::MAX_WS_MESSAGE_BYTES)
        .max_frame_size(ullm_core::MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            if let Err(e) = handle_session(socket, state, TenantId(tenant)).await {
                warn!(error = %e, "session terminated with error");
            }
        })
}

/// SECURITY: clamp the `x-ullm-tenant` header to a safe charset. Without
/// this, an attacker could embed CRLF in the tenant string and inject log
/// lines into structured-tracing output. Same policy as the gateway.
fn sanitized_tenant(h: &HeaderMap) -> String {
    let raw = h
        .get("x-ullm-tenant")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous");
    if raw.is_empty() || raw.len() > 128 {
        return "anonymous".to_string();
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return "anonymous".to_string();
    }
    raw.to_string()
}

/// One session = one WS connection.
async fn handle_session(
    socket: WebSocket,
    state: AppState,
    tenant: TenantId,
) -> anyhow::Result<()> {
    let (mut sender, mut receiver) = socket.split();
    let session_id = SessionId::random();
    let mut slot = state.tenants.allocate(&tenant, session_id);
    info!(session = %session_id, tenant = %tenant.0, "session opened");

    // 1) ClientHello.
    let hello_msg = match receiver.next().await {
        Some(Ok(Message::Binary(b))) => b,
        _ => return Err(anyhow::anyhow!("expected ClientHello binary frame")),
    };

    let server = ServerHandshake {
        spk_sk_x25519: &state.identity.spk_sk_x25519,
        pq_sk_mlkem: &state.identity.pq_sk_mlkem,
    };

    let mut rng = OsRng;
    let ratchet_sk = X25519SecretKey::random_from_rng(&mut rng);

    let id_sk = &state.identity.id_sk;
    let attest_issuer = state.identity.attest_issuer.clone();
    // P6 clock-skew: the handshake-time evidence is the freshness
    // anchor; fail closed if the clock is pre-1970 rather than zeroing
    // the timestamp (which would mark the evidence as eternally fresh).
    let now = ullm_core::clock::now_unix()
        .map_err(|e| anyhow::anyhow!("system clock unusable: {e}"))?;

    let (server_hello, keys) = server.respond(
        &mut rng,
        &hello_msg,
        &ratchet_sk,
        |report_data, pre_sig_hash| {
            let evidence = attest_issuer.issue(report_data, now);
            let evidence_bytes = ullm_attest::evidence::encode_evidence(&evidence)?;
            // P4-1: domain-separate this signature from the bundle
            // signature (also produced by `id_sk`). The verifier
            // prepends the same constant; without the prefix on both
            // sides a bundle signature could be transferred to satisfy
            // a handshake verification on a colliding payload.
            let mut payload = Vec::with_capacity(
                ullm_handshake::SIG_DOMAIN_HANDSHAKE.len() + pre_sig_hash.len(),
            );
            payload.extend_from_slice(ullm_handshake::SIG_DOMAIN_HANDSHAKE);
            payload.extend_from_slice(pre_sig_hash);
            let sig: Signature = id_sk.sign(&payload);
            Ok((evidence_bytes, sig.to_bytes()))
        },
    )?;

    send_ws(&mut sender, Message::Binary(server_hello)).await?;

    // 2) Per-direction symmetric ratchet state + tracking for the DH ratchet.
    let mut c2s = SymRatchet::new(keys.c2s_chain.clone());
    let mut s2c = SymRatchet::new(keys.s2c_chain.clone());
    let mut nonce_salt = keys.nonce_salt.clone();
    let mut current_root: RootKey = keys.root.clone();
    let mut server_ratchet_sk: X25519SecretKey = ratchet_sk;
    let client_ratchet_pk: X25519PublicKey = keys.client_ratchet_pk;
    let mut c2s_seq: u64 = 0;
    let mut s2c_seq: u64 = 0;
    let mut epoch = Epoch(0);

    // 3) ClientHello-then-prompt: receive one DATA frame containing the prompt.
    let prompt_frame = match receiver.next().await {
        Some(Ok(Message::Binary(b))) => b,
        _ => return Err(anyhow::anyhow!("expected encrypted prompt frame")),
    };

    let key = c2s.next_key();
    let (header, prompt_bytes) = decode_frame(&key, &nonce_salt, &prompt_frame)?;
    if header.frame_type != FrameType::Data {
        return Err(anyhow::anyhow!("unexpected frame type for prompt"));
    }
    if header.seq.0 != c2s_seq {
        return Err(anyhow::anyhow!("client sent out-of-order frame seq={}", header.seq.0));
    }
    c2s_seq = c2s_seq.checked_add(1).ok_or_else(|| anyhow::anyhow!("seq overflow"))?;
    let _ = c2s_seq; // c2s flow ends after the one prompt frame in Phase 1.
    let input_tokens = approx_token_count(&prompt_bytes);
    let input_hash: [u8; 32] = Sha256::digest(&prompt_bytes).into();
    let prompt = String::from_utf8(prompt_bytes)
        .map_err(|_| anyhow::anyhow!("prompt is not utf-8"))?;
    debug!(input_tokens, "decrypted prompt");

    // 4) Run inference; stream tokens back as DATA frames.
    let (tok_tx, mut tok_rx) = mpsc::channel::<TokenChunk>(32);
    let engine = state.engine.clone();
    // P5-3: wrap the spawned task in an RAII guard so any early return
    // from the streaming loop (`?` propagation, ws send timeout, ...)
    // aborts the inference task on drop instead of leaving it running
    // orphaned. Success path calls `.finish()` to let it complete.
    let inf_task = InferenceTaskGuard::new(tokio::spawn(async move {
        engine.run(prompt, tok_tx).await;
    }));

    let mut output_token_total = 0u32;
    // P3-6: the plaintext output accumulator is zeroized on drop so a
    // post-session heap dump can't recover the LLM tokens the TEE just
    // emitted. The plaintext is public from the *client's* perspective
    // (they receive every token) but the server has no business keeping
    // it around — defense-in-depth against memory-residency attacks.
    let mut output_bytes: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(Vec::new());
    // P13-FIX-D: parallel accumulator for the canonical token-id stream.
    // The receipt's `output_digest_hex` is computed over this, not the
    // decoded UTF-8 bytes. Two distinct id sequences that decode to the
    // same string therefore commit to distinct receipt digests.
    let mut output_token_ids: zeroize::Zeroizing<Vec<u32>> = zeroize::Zeroizing::new(Vec::new());
    let mut kv_position: u64 = 0;
    let mut chunks_since_update: u32 = 0;
    while let Some(chunk) = tok_rx.recv().await {
        let text_bytes = chunk.text.as_bytes();
        // Token count is now the real model-emitted id count, not a
        // 4-byte-per-token proxy.
        output_token_total = output_token_total.saturating_add(chunk.ids.len() as u32);
        output_bytes.extend_from_slice(text_bytes);
        output_token_ids.extend_from_slice(&chunk.ids);

        let kv_row = synthesize_kv_row(text_bytes, kv_position);
        slot.record_kv(kv_position, &kv_row);
        kv_position += 1;

        let key = s2c.next_key();
        let frame = encode_frame(
            &key,
            &nonce_salt,
            FrameType::Data,
            FrameFlags::empty(),
            epoch,
            Seq(s2c_seq),
            text_bytes,
        )?;
        send_ws(&mut sender, Message::Binary(frame.wire)).await?;
        s2c_seq = s2c_seq.checked_add(1).ok_or_else(|| anyhow::anyhow!("seq overflow"))?;
        chunks_since_update += 1;

        if KEY_UPDATE_EVERY_N_CHUNKS > 0 && chunks_since_update >= KEY_UPDATE_EVERY_N_CHUNKS {
            // 1) Generate a fresh server ratchet key.
            let new_sk = X25519SecretKey::random_from_rng(&mut OsRng);
            let new_pk = X25519PublicKey::from(&new_sk);
            // 2) Advance DH ratchet against the client's ratchet pk.
            let (new_root, new_keys) =
                DhRatchet::step(&current_root, &new_sk, &client_ratchet_pk);
            // 3) Send the control frame under the CURRENT s2c chain — the
            //    receiver decrypts it before it learns about the new keys.
            let body = Control::KeyUpdate {
                new_pk: *new_pk.as_bytes(),
            }
            .encode();
            let key = s2c.next_key();
            let ctrl_frame = encode_frame(
                &key,
                &nonce_salt,
                FrameType::Control,
                FrameFlags::empty(),
                epoch,
                Seq(s2c_seq),
                &body,
            )?;
            send_ws(&mut sender, Message::Binary(ctrl_frame.wire)).await?;
            // 4) Adopt the new keys for subsequent frames.
            current_root = new_root;
            s2c = SymRatchet::new(new_keys.s2c_chain);
            c2s = SymRatchet::new(new_keys.c2s_chain);
            nonce_salt = new_keys.nonce_salt;
            server_ratchet_sk = new_sk;
            epoch = Epoch(epoch.0.wrapping_add(1));
            s2c_seq = 0;
            c2s_seq = 0;
            let _ = c2s_seq; // suppress unused-assign warning
            chunks_since_update = 0;
            debug!(epoch = epoch.0, "server initiated key_update");
        }
    }
    // P5-3: success path — let the inference task drain naturally.
    // Anything that returned early via `?` above instead dropped the
    // guard, which aborted the task.
    inf_task.finish().await;
    let _ = (server_ratchet_sk, c2s); // suppress unused-after-loop warnings (Phase 1 is single-turn)

    // Demonstrate the at-rest wrap path: seal cloaked blocks under the
    // tenant KEK. The sealed blob doesn't leave the TEE; this exercises the
    // sealing API end-to-end.
    let _sealed = slot.finalize_seal();

    // 5) End-of-turn marker.
    let key = s2c.next_key();
    let eot = encode_frame(
        &key,
        &nonce_salt,
        FrameType::Data,
        FrameFlags::END_OF_TURN,
        epoch,
        Seq(s2c_seq),
        &[],
    )?;
    send_ws(&mut sender, Message::Binary(eot.wire)).await?;

    // 6) Run the verifiable model on a deterministic encoding of the prompt
    //    bytes. Commit each activation; optionally produce per-layer proofs.
    let model_input = encode_prompt_to_fp(&input_hash);
    let trace = state.verifiable_model.run(model_input);
    let activation_commits = trace.commits();
    let activation_commits_hex: Vec<String> = activation_commits
        .bytes
        .iter()
        .map(hex::encode)
        .collect();

    let zk_layer_proofs = match &state.layer_prover {
        // P13-FIX-C: pass the session id and the model's weight commit
        // through to the prover so each proof is bound to this specific
        // session + model identity (in addition to the per-layer
        // `(x_commit, y_commit)` pair). A proof captured from session A
        // cannot be presented as evidence in session B.
        Some(p) => match p.prove_trace(&trace, &session_id, &state.identity.weight_commit) {
            Ok(proofs) => proofs,
            Err(e) => {
                warn!(error = %e, "layer prover failed; envelope ships in optimistic mode");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let output_hash: [u8; 32] = Sha256::digest(&output_bytes).into();
    // P13-FIX-D: the canonical receipt-bound digest is over the
    // token-id stream, not the decoded UTF-8. Keep the UTF-8 digest as
    // a separate field for UI/debug surfaces.
    let token_digest = compute_token_id_digest(&input_hash, &output_token_ids);
    let string_digest = compute_output_string_digest(&input_hash, &output_bytes);

    // 7) Signed usage receipt.
    let receipt = Receipt {
        tenant: tenant.clone(),
        session: session_id,
        model: state.model_name.clone(),
        input_tokens,
        output_tokens: output_token_total,
        epoch: epoch.0,
        issued_at_unix: now,
        kv_blocks_cloaked: slot.cloaked_count() as u32,
        output_digest_hex: hex::encode(token_digest),
        output_string_digest_hex: hex::encode(string_digest),
        weight_commit_hex: hex::encode(state.identity.weight_commit),
        activation_commits_hex,
    };
    let _ = output_hash; // kept available for future use
    // P5-7: `sign()` now returns Result and gates on `validate_structural`.
    // Any malformed Receipt (empty hex, wrong length, non-hex) is a TEE
    // programming error — surface it as a session-terminating error rather
    // than emitting a corrupt receipt to the client.
    let signed = state.receipt_signer.sign(receipt)?;

    let envelope = ReceiptEnvelope {
        signed_receipt: signed,
        zk_layer_proofs,
    };
    let envelope_bytes = postcard::to_allocvec(&envelope)?;
    send_ws(&mut sender, Message::Binary(envelope_bytes)).await?;

    info!(
        session = %session_id,
        output_token_total,
        kv_blocks = slot.cloaked_count(),
        "session complete"
    );
    Ok(())
}

/// Synthetic KV row: HKDF-expanded chunk bytes. Real attention layers would
/// emit real keys/values here; we only need a fixed-shape byte block for the
/// cloak machinery to operate on.
fn synthesize_kv_row(chunk: &[u8], position: u64) -> [u8; CLOAK_BLOCK_LEN] {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(&position.to_be_bytes()), chunk);
    let mut out = [0u8; CLOAK_BLOCK_LEN];
    hk.expand(b"ULLM-v1 synth-kv", &mut out)
        .expect("CLOAK_BLOCK_LEN <= 255*HashLen");
    out
}

/// Canonical token-id digest the receipt binds. SHA-256 over the
/// domain-separated tuple
/// `("ULLM-v1 token-id-digest", input_hash, u32-LE(count), id_0, …, id_{n-1})`
/// with every token id encoded little-endian.
///
/// P13-FIX-D: distinct token-id sequences that *decode to the same UTF-8
/// string* (BPE byte-fallback edge cases, ambiguous merges) commit to
/// different digests here, closing the collision the previous
/// decoded-bytes digest had. A decoder failure that drops a token from
/// the user-visible stream still changes the id-stream length prefix,
/// so the digest also diverges.
pub fn compute_token_id_digest(input_hash: &[u8; 32], ids: &[u32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ULLM-v1 token-id-digest");
    h.update(input_hash);
    // Length-prefix the id stream so `[1, 2] || []` and `[1] || [2]`
    // (concatenation ambiguity) cannot collide. Bounded by `u32::MAX`
    // tokens per session, comfortably above any realistic context.
    let count: u32 = ids.len().try_into().unwrap_or(u32::MAX);
    h.update(count.to_le_bytes());
    for id in ids {
        h.update(id.to_le_bytes());
    }
    h.finalize().into()
}

/// Companion digest over the decoded UTF-8 output. Bound to the
/// receipt's `output_string_digest_hex` field — useful for UI/debug
/// surfaces that want to commit to what the user actually saw, distinct
/// from what the model produced. Domain-separated from the token-id
/// digest so the two cannot be confused.
pub fn compute_output_string_digest(input_hash: &[u8; 32], output_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ULLM-v1 string-digest");
    h.update(input_hash);
    h.update(output_bytes);
    h.finalize().into()
}

/// Backwards-compatible alias of `compute_output_string_digest`. The
/// pre-P13 ZK circuit opens the SHA-256-of-output-bytes commitment; the
/// alias preserves the legacy `compute_output_digest` symbol for any
/// out-of-tree caller while signalling that *the receipt no longer
/// binds this digest as `output_digest_hex`*.
pub fn compute_output_digest(input_hash: &[u8; 32], output_bytes: &[u8]) -> [u8; 32] {
    compute_output_string_digest(input_hash, output_bytes)
}

/// Deterministic mapping from the SHA-256 hash of the prompt to a fixed-size
/// `Fp` input vector. Splits the 32-byte hash into 4-byte chunks; reads each
/// as a little-endian `u32`; lifts into `Fp`. Same hash → same input.
pub fn encode_prompt_to_fp(input_hash: &[u8; 32]) -> [Fp; VEC_DIM] {
    let mut out = [Fp::zero(); VEC_DIM];
    for i in 0..VEC_DIM {
        let off = i * 4;
        let v = u32::from_le_bytes([
            input_hash[off],
            input_hash[off + 1],
            input_hash[off + 2],
            input_hash[off + 3],
        ]);
        out[i] = Fp::from(v as u64);
    }
    out
}

fn approx_token_count(bytes: &[u8]) -> u32 {
    // Rough proxy: 4 bytes per token (English ASCII average).
    (bytes.len() as u32).div_ceil(4)
}

// Re-export the established-keys type for integration tests.
pub use ullm_handshake::EstablishedKeys;

#[cfg(test)]
mod digest_tests {
    use super::*;

    /// P13-FIX-D regression: two distinct token-id streams that *decode
    /// to the same UTF-8 string* must produce different
    /// `output_digest_hex` values. This is the BPE byte-fallback /
    /// ambiguous-merge collision the audit flagged: under the old
    /// scheme `extend_from_slice(chunk.as_bytes())` only saw the
    /// decoded string and the two sequences hashed identically.
    #[test]
    fn distinct_token_streams_with_same_decoded_text_diverge() {
        let input_hash = [9u8; 32];
        let same_text = b"hello world";

        // Two distinct id sequences. Real BPE example: a tokenizer
        // could merge `hello` as either `[123]` or `[10, 23, 45, …]`
        // depending on merge order; both decode to `"hello"`. We model
        // the divergence with concrete distinct id vectors.
        let ids_a: Vec<u32> = vec![100, 200, 300, 400];
        let ids_b: Vec<u32> = vec![500, 600];

        let digest_a = compute_token_id_digest(&input_hash, &ids_a);
        let digest_b = compute_token_id_digest(&input_hash, &ids_b);
        assert_ne!(
            digest_a, digest_b,
            "distinct token-id sequences must hash to distinct receipt digests"
        );

        // Conversely the decoded-string digest IS identical for both —
        // which is precisely why the previous `output_digest_hex`
        // (binding only the bytes) was unsafe.
        let str_digest_a = compute_output_string_digest(&input_hash, same_text);
        let str_digest_b = compute_output_string_digest(&input_hash, same_text);
        assert_eq!(
            str_digest_a, str_digest_b,
            "same decoded text must hash identically under the string digest"
        );
    }

    /// Domain separation: token-id digest and string digest must not
    /// collide for any same-shape input.
    #[test]
    fn token_and_string_digests_are_domain_separated() {
        let input_hash = [0u8; 32];
        // An id stream of `[0x68, 0x69]` ("hi") and the UTF-8 bytes
        // `b"hi"` — the underlying material the hashers see differs
        // only in the domain-separation prefix and the LE-length
        // framing.
        let token_digest = compute_token_id_digest(&input_hash, &[0x68, 0x69]);
        let string_digest = compute_output_string_digest(&input_hash, b"hi");
        assert_ne!(
            token_digest, string_digest,
            "token-id and string digests must use disjoint domain separators"
        );
    }

    /// Concatenation ambiguity: `[1, 2] || []` and `[1] || [2]` must
    /// not collide. The length prefix is what defends against this.
    #[test]
    fn id_stream_length_prefix_prevents_concat_collision() {
        let input_hash = [0u8; 32];
        let a = compute_token_id_digest(&input_hash, &[1, 2]);
        let b = compute_token_id_digest(&input_hash, &[1]);
        assert_ne!(a, b);
    }

    /// Empty-stream determinism: a session that emitted zero tokens
    /// must still produce a well-defined digest.
    #[test]
    fn empty_id_stream_hashes_deterministically() {
        let input_hash = [7u8; 32];
        let a = compute_token_id_digest(&input_hash, &[]);
        let b = compute_token_id_digest(&input_hash, &[]);
        assert_eq!(a, b);
    }
}
