// SPDX-License-Identifier: Apache-2.0
//! `ullm-tee` server binary.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::net::TcpListener;
use ullm_model::Model;
use ullm_receipts::ReceiptSigner;
use ullm_tee::{metrics_router, router, AppState, MockEngine, NonceRegistry, TeeIdentity, TenantPool};

/// P9-FIX-E: hard cap on how long the TEE may spend draining
/// in-flight handlers after a SIGTERM/SIGINT. Without this cap,
/// `axum::serve(...).with_graceful_shutdown(...)` waits *indefinitely*
/// for every existing connection to close — a slowloris WebSocket
/// that sends one byte every 59s pins the binary until the
/// orchestrator's `TimeoutStopSec` ultimately SIGKILLs it, defeating
/// the careful drain path entirely. 30s mirrors the gateway's
/// `axum_server::Handle::graceful_shutdown(Some(30s))` deadline.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("ullm_tee=info".parse()?))
        .init();

    let addr = std::env::var("ULLM_TEE_ADDR").unwrap_or_else(|_| "127.0.0.1:9001".into());
    // P9-FIX-C: management listener for `/metrics` + `/v1/healthz`.
    // Separate from `ULLM_TEE_ADDR` so a misconfigured `0.0.0.0` on
    // the protocol port can't leak operator-internal gauges. Default
    // loopback; never bind this to a public interface in prod.
    let metrics_addr: std::net::SocketAddr = std::env::var("ULLM_TEE_METRICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9101".into())
        .parse()?;
    // P10-FIX-D: refuse a non-loopback metrics bind unless explicitly
    // opted into via `ULLM_METRICS_ALLOW_PUBLIC=1`.
    let metrics_addr = ullm_core::validate_metrics_addr(metrics_addr, "ULLM_TEE_METRICS_ADDR")
        .map_err(anyhow::Error::msg)?;
    let model_seed = std::env::var("ULLM_MODEL_SEED")
        .ok()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .unwrap_or([0u8; 32]);
    let model = Arc::new(Model::from_seed(&model_seed));
    let weight_commit = model.weight_commit();

    let mut rng = OsRng;
    let state = AppState {
        identity: Arc::new(TeeIdentity::random(&mut rng, weight_commit)),
        engine: Arc::new(MockEngine::default()),
        receipt_signer: Arc::new(ReceiptSigner::new(SigningKey::generate(&mut rng))),
        model_name: "mock-llama-3.1-70b".into(),
        tenants: Arc::new(TenantPool::random(&mut rng)),
        verifiable_model: model,
        layer_prover: None,
        nonce_registry: Arc::new(NonceRegistry::new()),
    };

    tracing::info!(%addr, %metrics_addr, "ullm-tee listening");
    let listener = TcpListener::bind(&addr).await?;
    let mgmt_listener = TcpListener::bind(&metrics_addr).await?;
    // PR-1 + P9-FIX-E + P10-FIX-A: install a single SIGTERM/SIGINT
    // broadcaster whose `watch::channel(bool)` *retains* the latest
    // value, so a listener that subscribes after the signal already
    // fired still sees it. The previous `Notify::notify_waiters()`
    // had a registration race the P10 audit caught — a signal that
    // arrived during the window between `tokio::spawn` and the first
    // poll of `notified()` was silently lost.
    //
    // Two subscribers (one per listener) plus a `wait().await` clone
    // for the deadline future. All resolve on the first signal.
    let broadcaster = ullm_core::ShutdownBroadcaster::install()?;
    let protocol_state = state.clone();
    let mgmt_state = state.clone();
    let mut protocol_b = broadcaster.clone();
    let mut mgmt_b = broadcaster.clone();
    let mut deadline_b = broadcaster.clone();
    let protocol_serve = async move {
        axum::serve(listener, router(protocol_state))
            .with_graceful_shutdown(async move { protocol_b.wait().await })
            .await
            .map_err(anyhow::Error::from)
    };
    let mgmt_serve = async move {
        axum::serve(mgmt_listener, metrics_router(mgmt_state))
            .with_graceful_shutdown(async move { mgmt_b.wait().await })
            .await
            .map_err(anyhow::Error::from)
    };
    let serve_all = async {
        tokio::try_join!(protocol_serve, mgmt_serve)?;
        Ok::<(), anyhow::Error>(())
    };
    let deadline = async move {
        // Wait for the signal first, *then* time the drain.
        // `wait()` resolves immediately if the signal already fired.
        deadline_b.wait().await;
        tokio::time::sleep(SHUTDOWN_DEADLINE).await;
    };
    tokio::select! {
        res = serve_all => res?,
        _ = deadline => {
            tracing::warn!(
                deadline_secs = SHUTDOWN_DEADLINE.as_secs(),
                "ullm-tee drain exceeded deadline; forcing shutdown"
            );
        }
    }
    // P9-FIX-E: explicit drop of `state` to force the Arc strong
    // count toward zero before main returns. The MasterSecret /
    // ReceiptSigner / TeeIdentity all `Zeroize` on Drop; without the
    // explicit drop here, lingering tokio-runtime references from
    // aborted tasks can keep the strong count above zero past the
    // process-exit boundary.
    drop(state);
    tracing::info!("ullm-tee shutdown complete");
    Ok(())
}
