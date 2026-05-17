// SPDX-License-Identifier: Apache-2.0
//! Slice 9: long-stream test that drives many `key_update` rotations through
//! the live client/gateway/TEE pipeline.
//!
//! The TEE service rotates the chain after every `KEY_UPDATE_EVERY_N_CHUNKS`
//! emitted data frames; with a fixed-chunk MockEngine we can pin the total
//! number of rotations the test exercises.

use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::net::TcpListener;
use ullm_client::{Session, TlsPinning};
use ullm_gateway::{
    router as gw_router, GatewayState, RateLimiter, RateLimiterConfig, TransparencyLog,
};
use ullm_model::Model;
use ullm_receipts::ReceiptSigner;
use ullm_tee::{router as tee_router, AppState, MockEngine, TeeIdentity, TenantPool};
use ullm_tls::{install_default_crypto_provider, SelfSignedCert};

/// Number of data chunks we ask the engine to emit. With the service-side
/// `KEY_UPDATE_EVERY_N_CHUNKS = 2` setting this drives `chunks / 2`
/// rotations, plus the END_OF_TURN frame at the very end.
const STREAM_CHUNKS: usize = 32;
const CHUNK_SIZE: usize = 64;

async fn spawn_stack_with(
    engine: Arc<MockEngine>,
) -> (
    String,
    [u8; 32],
    Vec<String>,
    ed25519_dalek::VerifyingKey,
    ed25519_dalek::VerifyingKey,
    [u8; 32],
) {
    install_default_crypto_provider();
    let mut rng = OsRng;
    let model = Arc::new(Model::from_seed(&[0u8; 32]));
    let weight_commit = model.weight_commit();

    let identity = Arc::new(TeeIdentity::random(&mut rng, weight_commit));
    let trust_root = identity.attest_issuer.verifying_key();
    let receipt_signer = Arc::new(ReceiptSigner::new(SigningKey::generate(&mut rng)));
    let tee_pk = receipt_signer.verifying_key();

    let tee_state = AppState {
        identity: identity.clone(),
        engine,
        receipt_signer,
        model_name: "mock".into(),
        tenants: Arc::new(TenantPool::random(&mut rng)),
        verifiable_model: model.clone(),
        layer_prover: None, // optimistic mode is enough for this test
        nonce_registry: Arc::new(ullm_tee::NonceRegistry::new()),
    };

    let tee_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tee_addr = tee_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(tee_listener, tee_router(tee_state)).await.unwrap();
    });

    let cert = SelfSignedCert::generate(&["localhost", "127.0.0.1"]).unwrap();
    let fingerprint = cert.fingerprint;
    let cert_sans = cert.sans.clone();
    let gw_state = GatewayState {
        tee_base_url: format!("http://{tee_addr}"),
        rate_limiter: Arc::new(RateLimiter::new(RateLimiterConfig::default())),
        transparency: Arc::new(TransparencyLog::new()),
        logger_signing_key: Arc::new(SigningKey::generate(&mut rng)),
        log_id: "ullm-test-log".into(),
        sth_cache: Arc::new(ullm_gateway::SthCache::default()),
    };
    let rustls_cfg = RustlsConfig::from_der(
        vec![cert.cert_der.clone()],
        cert.key_der_pkcs8.clone(),
    )
    .await
    .unwrap();
    let handle = axum_server::Handle::new();
    let h2 = handle.clone();
    tokio::spawn(async move {
        axum_server::bind_rustls(
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            rustls_cfg,
        )
        .handle(h2)
        .serve(gw_router(gw_state).into_make_service())
        .await
        .unwrap();
    });
    let bound = handle.listening().await.unwrap();
    let gw_url = format!("https://{bound}");
    (gw_url, fingerprint, cert_sans, trust_root, tee_pk, weight_commit)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_stream_survives_many_key_updates() {
    let engine = Arc::new(MockEngine::with_fixed_chunk_count(CHUNK_SIZE, STREAM_CHUNKS));
    let (gw_url, fp, cert_sans, trust_root, tee_pk, weight_commit) =
        spawn_stack_with(engine).await;

    let tls = Some(TlsPinning::pin_multi("localhost", fp, cert_sans));
    let mut session = Session::connect(&gw_url, &trust_root, &tee_pk, weight_commit, tls)
        .await
        .unwrap();
    let mut stream = session.send("ratchet me up").await.unwrap();

    let mut received_chunks = 0usize;
    let mut total_bytes = 0usize;
    while let Some(tok) = stream.next_token().await.unwrap() {
        received_chunks += 1;
        total_bytes += tok.len();
    }

    // We expect exactly STREAM_CHUNKS data frames followed by an empty
    // END_OF_TURN frame. The TokenStream surfaces non-empty data frames as
    // chunks and returns Ok(None) on the empty END_OF_TURN.
    assert_eq!(
        received_chunks, STREAM_CHUNKS,
        "expected {STREAM_CHUNKS} chunks, got {received_chunks}"
    );
    assert_eq!(total_bytes, STREAM_CHUNKS * CHUNK_SIZE);

    let signed = stream.finalize().await.unwrap();
    // ~ STREAM_CHUNKS * CHUNK_SIZE / 4 tokens (rough byte→token proxy used
    // inside the TEE service).
    assert!(signed.receipt.output_tokens as usize >= STREAM_CHUNKS);
}
