// SPDX-License-Identifier: Apache-2.0
//! End-to-end Phase 3 demo: TEE + gateway + verifiable model + per-layer ZK.

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
use ullm_model::{Model, NUM_LAYERS, VEC_DIM};
use ullm_receipts::ReceiptSigner;
use ullm_tee::{router as tee_router, AppState, LayerProver, MockEngine, TeeIdentity, TenantPool};
use ullm_tls::{install_default_crypto_provider, SelfSignedCert};
use ullm_zk::{
    layer::{vector_hash_native, LayerProof},
    setup_layer, Fp, LayerProver as ZkLayerProver, LayerProverParams, LayerVerifier as ZkLayerVerifier,
    LayerVerifierParams,
};

/// Adapter: drive the per-layer Halo2 prover from a `Trace`.
struct PerLayerProverAdapter {
    model: Arc<Model>,
    params: Vec<Arc<LayerProverParams>>,
}

impl LayerProver for PerLayerProverAdapter {
    fn prove_trace(
        &self,
        trace: &ullm_model::Trace,
        session_id: &ullm_core::SessionId,
        weight_commit: &[u8; 32],
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        // P13-FIX-C: each layer proof binds `(layer_idx, session_id,
        // weight_commit)` into its public inputs. The verifier reads
        // the session id off the signed receipt and the weight commit
        // off its expected-model state — a proof minted for one session
        // can't be replayed against another.
        let mut proofs = Vec::with_capacity(NUM_LAYERS);
        for layer_idx in 0..NUM_LAYERS {
            let x = trace.activations[layer_idx];
            let y = trace.activations[layer_idx + 1];
            let xc = vector_hash_native(&x);
            let yc = vector_hash_native(&y);
            let layer = &self.model.layers[layer_idx];
            let proof = ZkLayerProver(&self.params[layer_idx]).prove(
                x,
                y,
                xc,
                yc,
                layer.w,
                layer.b,
                layer_idx,
                &session_id.0,
                weight_commit,
            );
            proofs.push(proof.0);
        }
        Ok(proofs)
    }
}

struct PerLayerVerifierAdapter {
    params: Vec<Arc<LayerVerifierParams>>,
    /// P13-FIX-C: bound into each layer proof's public inputs alongside
    /// `(layer_idx, session_id)`. Must match the prover-side
    /// `self.model.weight_commit()`.
    weight_commit: [u8; 32],
}

impl LayerVerifier for PerLayerVerifierAdapter {
    fn verify_layers(
        &self,
        activation_commits: &[[u8; 32]],
        proofs: &[Vec<u8>],
        session_id: &ullm_core::SessionId,
        weight_commit: &[u8; 32],
    ) -> Result<()> {
        if activation_commits.len() != NUM_LAYERS + 1 {
            return Err(Error::Other(format!(
                "expected {} activation commits, got {}",
                NUM_LAYERS + 1,
                activation_commits.len()
            )));
        }
        if proofs.len() != NUM_LAYERS {
            return Err(Error::Other(format!(
                "expected {} layer proofs, got {}",
                NUM_LAYERS,
                proofs.len()
            )));
        }
        // Cross-check that the receipt-supplied weight commit matches
        // the model we expected — defense in depth on top of the
        // attestation-bound commit the session already verified.
        if weight_commit != &self.weight_commit {
            return Err(Error::Other(
                "layer-verifier weight_commit does not match expected".into(),
            ));
        }
        for i in 0..NUM_LAYERS {
            let xc = ullm_zk::fp_from_bytes(activation_commits[i])
                .map_err(|e| Error::Other(format!("layer {i} input commit: {e}")))?;
            let yc = ullm_zk::fp_from_bytes(activation_commits[i + 1])
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
                .map_err(|_| Error::Other(format!("layer {i} proof failed")))?;
        }
        Ok(())
    }
}

/// Demo mode. `Full` runs the bundled in-process client + signed-receipt
/// roundtrip, `ServerOnly` parks the same TEE + gateway processes and
/// prints the runtime trust roots so external clients (WASM/Python/curl)
/// can drive them. Same code path either way — the only difference is
/// whether we also run the in-proc client.
#[derive(Copy, Clone)]
enum Mode {
    Full,
    ServerOnly,
}

fn parse_mode() -> Mode {
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--server-only" => return Mode::ServerOnly,
            "--full" => return Mode::Full,
            "-h" | "--help" => {
                eprintln!(
                    "usage: ullm-demo [--full | --server-only]\n  \
                     --full         (default) full one-shot end-to-end demo\n  \
                     --server-only  start TEE+gateway, print devkeys to stdout,\n                 \
                                    then park until ctrl-c"
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
    Mode::Full
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("ullm=info".parse()?))
        .init();
    install_default_crypto_provider();

    let mode = parse_mode();
    let mut rng = OsRng;

    let model_seed = [0u8; 32];
    let model = Arc::new(Model::from_seed(&model_seed));
    let weight_commit = model.weight_commit();
    tracing::info!(weight_commit = %hex::encode(weight_commit), "verifiable model loaded");

    tracing::info!("running Halo2 per-layer keygen ({} layers)…", NUM_LAYERS);
    let mut prover_params = Vec::with_capacity(NUM_LAYERS);
    let mut verifier_params = Vec::with_capacity(NUM_LAYERS);
    for layer_idx in 0..NUM_LAYERS {
        let layer = &model.layers[layer_idx];
        let (pp, vp) = setup_layer(layer_idx, layer.w, layer.b);
        prover_params.push(Arc::new(pp));
        verifier_params.push(Arc::new(vp));
    }

    let identity = Arc::new(TeeIdentity::random(&mut rng, weight_commit));
    let trust_root = identity.attest_issuer.verifying_key();
    let receipt_signer = Arc::new(ReceiptSigner::new(SigningKey::generate(&mut rng)));
    let tee_receipt_pk = receipt_signer.verifying_key();

    let layer_prover_adapter = Arc::new(PerLayerProverAdapter {
        model: model.clone(),
        params: prover_params,
    });

    let tee_state = AppState {
        identity: identity.clone(),
        engine: Arc::new(MockEngine::default()),
        receipt_signer,
        model_name: "mock-llama-3.1-70b".into(),
        tenants: Arc::new(TenantPool::random(&mut rng)),
        verifiable_model: model.clone(),
        layer_prover: Some(layer_prover_adapter),
        nonce_registry: Arc::new(ullm_tee::NonceRegistry::new()),
    };

    let tee_listener = TcpListener::bind("127.0.0.1:0").await?;
    let tee_addr = tee_listener.local_addr()?;
    let tee_url = format!("http://{tee_addr}");
    tokio::spawn(async move {
        axum::serve(tee_listener, tee_router(tee_state))
            .await
            .expect("tee server")
    });

    let cert = SelfSignedCert::generate(&["localhost", "127.0.0.1"])?;
    let fp = cert.fingerprint;
    let transparency_log = Arc::new(TransparencyLog::new());
    let logger_signing_key = Arc::new(SigningKey::generate(&mut rng));
    let _logger_pk = logger_signing_key.verifying_key();
    let gateway_state = GatewayState {
        tee_base_url: tee_url.clone(),
        rate_limiter: Arc::new(RateLimiter::new(RateLimiterConfig::default())),
        transparency: transparency_log.clone(),
        logger_signing_key: logger_signing_key.clone(),
        // P2-6: bind STHs to a deployment-stable log_id. For the in-process
        // demo we use the logger's public key — canonical and unambiguous.
        log_id: hex::encode(logger_signing_key.verifying_key().as_bytes()),
        sth_cache: Arc::new(ullm_gateway::SthCache::default()),
    };
    let rustls_cfg = RustlsConfig::from_der(
        vec![cert.cert_der.clone()],
        cert.key_der_pkcs8.clone(),
    )
    .await?;

    let handle = axum_server::Handle::new();
    let h2 = handle.clone();
    let gw_listen_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    tokio::spawn(async move {
        axum_server::bind_rustls(gw_listen_addr, rustls_cfg)
            .handle(h2)
            .serve(gw_router(gateway_state).into_make_service())
            .await
            .expect("gateway server")
    });
    let bound = handle
        .listening()
        .await
        .ok_or_else(|| anyhow::anyhow!("gateway failed to bind"))?;
    let gw_url = format!("https://{bound}");

    tracing::info!(
        %tee_url, %gw_url,
        fingerprint = %hex::encode(fp),
        "demo services listening"
    );

    if matches!(mode, Mode::ServerOnly) {
        // Print the exact runtime keys the gateway's `/v1/devkeys` endpoint
        // serves, in a machine-readable single line so headless drivers can
        // parse it with one regex (or just consume the JSON object directly).
        let trust_root_hex = hex::encode(trust_root.as_bytes());
        let tee_pk_hex = hex::encode(tee_receipt_pk.as_bytes());
        let weight_commit_hex = hex::encode(weight_commit);
        println!(
            "{{\"gateway_url\":\"{gw_url}\",\"fingerprint_hex\":\"{}\",\"trust_root_hex\":\"{trust_root_hex}\",\"tee_receipt_pk_hex\":\"{tee_pk_hex}\",\"weight_commit_hex\":\"{weight_commit_hex}\"}}",
            hex::encode(fp)
        );
        println!("✓ server-only mode — ctrl-c to exit");
        // Park forever; signal handling is left to the runtime default.
        std::future::pending::<()>().await;
        unreachable!();
    }

    // The cert lists both `localhost` and `127.0.0.1`; the in-process demo
    // dials the bound socket address (an IP), so the pin has to allow both
    // SANs or the SNI check in `FingerprintVerifier` (P2-7) rejects it.
    let tls = Some(TlsPinning::pin_multi(
        "localhost",
        fp,
        cert.sans.clone(),
    ));
    let layer_verifier: Arc<dyn LayerVerifier> = Arc::new(PerLayerVerifierAdapter {
        params: verifier_params,
        weight_commit,
    });
    let mut session = Session::connect_with(
        &gw_url,
        &trust_root,
        &tee_receipt_pk,
        weight_commit,
        tls,
        Some(layer_verifier),
    )
    .await?;
    println!(
        "session established with TEE id_pk = {}",
        hex::encode(session.tee_id_pk().as_bytes())
    );
    println!(
        "  weight commit cross-bound in attestation: {}",
        hex::encode(weight_commit)
    );

    let prompt = "say hi to the world";
    println!("→ {prompt}");
    let mut stream = session.send(prompt).await?;
    print!("← ");
    while let Some(tok) = stream.next_token().await? {
        print!("{tok}");
    }
    println!();
    let receipt = stream.finalize().await?;
    println!(
        "✓ signed receipt: model={} input={} output={} kv_blocks_cloaked={}",
        receipt.receipt.model,
        receipt.receipt.input_tokens,
        receipt.receipt.output_tokens,
        receipt.receipt.kv_blocks_cloaked,
    );
    println!(
        "✓ verifiable model: {} activation commits, weight_commit={}",
        receipt.receipt.activation_commits_hex.len(),
        receipt.receipt.weight_commit_hex,
    );
    println!("✓ Halo2 per-layer ZK proofs verified for all {NUM_LAYERS} layers");

    let log = transparency_log.status();
    println!(
        "✓ transparency log: size={} root={}",
        log.size, log.root_hex
    );

    // Silence unused VEC_DIM/Fp warnings — they show up only on cfg variants.
    let _ = (VEC_DIM, Fp::zero);

    Ok(())
}
