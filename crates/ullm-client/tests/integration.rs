// SPDX-License-Identifier: Apache-2.0
//! Phase 3 end-to-end integration tests.

use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::net::TcpListener;
use ullm_client::{LayerVerifier, Session, TlsPinning};
use ullm_core::{Error, Result};
use ullm_gateway::{
    router as gw_router, GatewayState, RateLimiter, RateLimiterConfig, TransparencyLog,
};
use ullm_model::{Model, NUM_LAYERS};
use ullm_receipts::ReceiptSigner;
use ullm_tee::{router as tee_router, AppState, LayerProver, MockEngine, TeeIdentity, TenantPool};
use ullm_tls::{install_default_crypto_provider, SelfSignedCert};
use ullm_core::SessionId;
use ullm_zk::{
    fp_from_bytes,
    layer::{vector_hash_native, LayerProof},
    setup_layer, LayerProver as ZkLayerProver, LayerProverParams,
    LayerVerifier as ZkLayerVerifier, LayerVerifierParams,
};

struct PerLayerProverAdapter {
    model: Arc<Model>,
    params: Vec<Arc<LayerProverParams>>,
}

impl LayerProver for PerLayerProverAdapter {
    fn prove_trace(
        &self,
        trace: &ullm_model::Trace,
        session_id: &SessionId,
        weight_commit: &[u8; 32],
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(NUM_LAYERS);
        for i in 0..NUM_LAYERS {
            let x = trace.activations[i];
            let y = trace.activations[i + 1];
            let xc = vector_hash_native(&x);
            let yc = vector_hash_native(&y);
            let layer = &self.model.layers[i];
            let p = ZkLayerProver(&self.params[i]).prove(
                x,
                y,
                xc,
                yc,
                layer.w,
                layer.b,
                i,
                &session_id.0,
                weight_commit,
            );
            out.push(p.0);
        }
        Ok(out)
    }
}

struct PerLayerVerifierAdapter {
    params: Vec<Arc<LayerVerifierParams>>,
}

impl LayerVerifier for PerLayerVerifierAdapter {
    fn verify_layers(
        &self,
        commits: &[[u8; 32]],
        proofs: &[Vec<u8>],
        session_id: &SessionId,
        weight_commit: &[u8; 32],
    ) -> Result<()> {
        if commits.len() != NUM_LAYERS + 1 || proofs.len() != NUM_LAYERS {
            return Err(Error::Other("commit/proof count mismatch".into()));
        }
        for i in 0..NUM_LAYERS {
            let xc = fp_from_bytes(commits[i])
                .map_err(|e| Error::Other(format!("layer {i} input commit: {e}")))?;
            let yc = fp_from_bytes(commits[i + 1])
                .map_err(|e| Error::Other(format!("layer {i} output commit: {e}")))?;
            ZkLayerVerifier(&self.params[i])
                .verify(
                    xc,
                    yc,
                    i,
                    &session_id.0,
                    weight_commit,
                    &LayerProof(proofs[i].clone()),
                )
                .map_err(|_| Error::Other(format!("layer {i} failed")))?;
        }
        Ok(())
    }
}

struct Stack {
    gw_url: String,
    fingerprint: [u8; 32],
    cert_sans: Vec<String>,
    trust_root: ed25519_dalek::VerifyingKey,
    tee_pk: ed25519_dalek::VerifyingKey,
    transparency: Arc<TransparencyLog>,
    weight_commit: [u8; 32],
    model: Arc<Model>,
    verifier_params: Vec<Arc<LayerVerifierParams>>,
}

async fn spawn_stack() -> Stack {
    install_default_crypto_provider();
    let mut rng = OsRng;

    let model = Arc::new(Model::from_seed(&[0u8; 32]));
    let weight_commit = model.weight_commit();

    let mut pp = Vec::with_capacity(NUM_LAYERS);
    let mut vp = Vec::with_capacity(NUM_LAYERS);
    for i in 0..NUM_LAYERS {
        let layer = &model.layers[i];
        let (p, v) = setup_layer(i, layer.w, layer.b);
        pp.push(Arc::new(p));
        vp.push(Arc::new(v));
    }

    let identity = Arc::new(TeeIdentity::random(&mut rng, weight_commit));
    let trust_root = identity.attest_issuer.verifying_key();
    let receipt_signer = Arc::new(ReceiptSigner::new(SigningKey::generate(&mut rng)));
    let tee_pk = receipt_signer.verifying_key();

    let tee_state = AppState {
        identity: identity.clone(),
        engine: Arc::new(MockEngine::default()),
        receipt_signer,
        model_name: "mock".into(),
        tenants: Arc::new(TenantPool::random(&mut rng)),
        verifiable_model: model.clone(),
        layer_prover: Some(Arc::new(PerLayerProverAdapter {
            model: model.clone(),
            params: pp,
        })),
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
    let transparency = Arc::new(TransparencyLog::new());
    let gw_state = GatewayState {
        tee_base_url: format!("http://{tee_addr}"),
        rate_limiter: Arc::new(RateLimiter::new(RateLimiterConfig::default())),
        transparency: transparency.clone(),
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
    Stack {
        gw_url,
        fingerprint,
        cert_sans,
        trust_root,
        tee_pk,
        transparency,
        weight_commit,
        model,
        verifier_params: vp,
    }
}

#[tokio::test]
async fn honest_session_with_per_layer_zk() {
    let s = spawn_stack().await;
    let tls = Some(TlsPinning::pin_multi("localhost", s.fingerprint, s.cert_sans.clone()));
    let zk: Arc<dyn LayerVerifier> = Arc::new(PerLayerVerifierAdapter {
        params: s.verifier_params.clone(),
    });
    let mut session = Session::connect_with(
        &s.gw_url,
        &s.trust_root,
        &s.tee_pk,
        s.weight_commit,
        tls,
        Some(zk),
    )
    .await
    .unwrap();
    let mut stream = session.send("hello").await.unwrap();
    let mut out = String::new();
    while let Some(t) = stream.next_token().await.unwrap() {
        out.push_str(&t);
    }
    assert_eq!(out, "echo: hello");
    let signed = stream.finalize().await.unwrap();
    assert_eq!(signed.receipt.activation_commits_hex.len(), NUM_LAYERS + 1);
    assert_eq!(signed.receipt.weight_commit_hex, hex::encode(s.weight_commit));
    assert_eq!(s.transparency.status().size, 1);
}

#[tokio::test]
async fn wrong_expected_weight_commit_rejected_at_handshake() {
    let s = spawn_stack().await;
    let tls = Some(TlsPinning::pin_multi("localhost", s.fingerprint, s.cert_sans.clone()));
    let mut bogus = s.weight_commit;
    bogus[0] ^= 0xFF;
    let res = Session::connect(&s.gw_url, &s.trust_root, &s.tee_pk, bogus, tls).await;
    assert!(res.is_err(), "wrong expected weight commit should fail attestation cross-binding");
}

// P13-FIX-B (in flight): the test asserts a `Partial` verdict for a
// bare `audit()` call with no supplementary inputs, but `ullm-watcher`
// itself still returns `Honest` for the legacy two-check audit.
// Re-enable when the watcher's verdict computation is updated (out of
// scope for P13-FIX-A; tracked by task #144).
#[tokio::test]
async fn watcher_says_honest_for_honest_session() {
    let s = spawn_stack().await;
    let tls = Some(TlsPinning::pin_multi("localhost", s.fingerprint, s.cert_sans.clone()));
    let mut session = Session::connect(&s.gw_url, &s.trust_root, &s.tee_pk, s.weight_commit, tls)
        .await
        .unwrap();
    let prompt = "hello";
    let mut stream = session.send(prompt).await.unwrap();
    while let Some(_) = stream.next_token().await.unwrap() {}
    let signed = stream.finalize().await.unwrap();

    let report =
        ullm_watcher::audit(&[0u8; 32], &s.tee_pk, prompt.as_bytes(), &signed).unwrap();
    // P13-FIX-B: the bare `audit()` API skips attestation chain, log
    // inclusion, STH freshness, and the pinning checks — so an honest
    // session that supplies no supplementary inputs now returns
    // `Partial`, not `Honest`. The per-flag asserts make the intent
    // explicit: the watcher proved (a) the receipt signature and (b)
    // the local activation recompute matches the TEE's claim.
    assert!(
        matches!(report.verdict, ullm_watcher::Verdict::Partial),
        "expected Partial (basic audit, no optional inputs); got {:?}",
        report.verdict
    );
    assert!(report.activations_consistent);
    assert!(report.receipt_signature_verified);
    assert!(!ullm_watcher::Verdict::is_fully_verified(&report));
}

#[tokio::test]
async fn watcher_catches_tampered_activation_commit() {
    let s = spawn_stack().await;
    let tls = Some(TlsPinning::pin_multi("localhost", s.fingerprint, s.cert_sans.clone()));
    let mut session = Session::connect(&s.gw_url, &s.trust_root, &s.tee_pk, s.weight_commit, tls)
        .await
        .unwrap();
    let prompt = "hello";
    let mut stream = session.send(prompt).await.unwrap();
    while let Some(_) = stream.next_token().await.unwrap() {}
    let signed_honest = stream.finalize().await.unwrap();

    // Simulate a tampered TEE that overwrote layer-3's commit. The receipt's
    // signature would normally cover this — so we re-sign as a "malicious TEE"
    // with the *same* signing key we have access to, mirroring a worst case
    // where the TEE key itself is dishonest but the model output is forged.
    let mut tampered = signed_honest.clone();
    tampered.receipt.activation_commits_hex[3] = "00".repeat(32);
    let tee_sk_bytes = include_tee_signing_key_bytes_for_test();
    let _ = tee_sk_bytes;
    // We can't actually re-sign without the TEE's secret; instead, simulate by
    // bypassing receipt-signature verification through the watcher's own check.
    // For the audit-only path, we re-construct a Receipt and re-sign with a
    // throwaway key just to satisfy `ullm_receipts::verify`.
    use ed25519_dalek::SigningKey;
    let throwaway_sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let throwaway_pk = throwaway_sk.verifying_key();
    let resigned = ullm_receipts::ReceiptSigner::new(throwaway_sk)
        .sign(tampered.receipt.clone())
        .expect("tampered receipt retains structural validity");

    let report =
        ullm_watcher::audit(&[0u8; 32], &throwaway_pk, prompt.as_bytes(), &resigned).unwrap();
    match report.verdict {
        ullm_watcher::Verdict::Fraudulent { divergent_layer } => {
            assert_eq!(divergent_layer, 3);
        }
        ullm_watcher::Verdict::Honest => panic!("watcher missed tampered commit"),
        // P13-FIX-B added a `Partial` verdict for cases where some but
        // not all per-layer evidence was conclusive. The tampered-layer
        // case here must be classified as `Fraudulent`; a `Partial`
        // verdict for an unambiguously divergent commit is itself a
        // watcher regression.
        ullm_watcher::Verdict::Partial => {
            panic!("watcher returned Partial for an unambiguously tampered commit")
        }
    }
    let _ = s.model; // keep alive
}

fn include_tee_signing_key_bytes_for_test() -> [u8; 32] {
    [0u8; 32]
}
