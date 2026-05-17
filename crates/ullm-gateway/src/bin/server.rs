// SPDX-License-Identifier: Apache-2.0
//! `ullm-gateway` binary. Terminates TLS toward clients; forwards plaintext
//! over loopback to the TEE; hosts the Sigsum-style transparency log.

use std::path::PathBuf;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ullm_gateway::{metrics_router, router, GatewayState, RateLimiter, RateLimiterConfig, SthCache};
use ullm_tls::{
    install_default_crypto_provider, server_config, server_config_strict_pq, SelfSignedCert,
};
use ullm_transparency::TransparencyLog;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ullm_gateway=info".parse()?),
        )
        .init();

    install_default_crypto_provider();

    let addr: std::net::SocketAddr =
        std::env::var("ULLM_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".into()).parse()?;
    // P9-FIX-C: `/metrics` lives on its own listener so a public
    // `ULLM_GATEWAY_ADDR=0.0.0.0:9000` doesn't accidentally publish
    // operator-internal gauges. Default loopback; operators wanting to
    // expose to a mgmt network override.
    let metrics_addr: std::net::SocketAddr = std::env::var("ULLM_GATEWAY_METRICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9100".into())
        .parse()?;
    // P10-FIX-D: refuse a non-loopback metrics bind unless explicitly
    // opted into via `ULLM_METRICS_ALLOW_PUBLIC=1`.
    let metrics_addr = ullm_core::validate_metrics_addr(metrics_addr, "ULLM_GATEWAY_METRICS_ADDR")
        .map_err(anyhow::Error::msg)?;
    let tee_base_url =
        std::env::var("ULLM_TEE_URL").unwrap_or_else(|_| "http://127.0.0.1:9001".into());

    let log_path = std::env::var("ULLM_LOG_PATH")
        .ok()
        .map(PathBuf::from);
    let transparency = match log_path {
        Some(path) => Arc::new(TransparencyLog::open_persistent(path)?),
        None => Arc::new(TransparencyLog::new()),
    };
    // PR-3: optional `ULLM_LOG_FSYNC_EVERY_N` env var lets operators
    // opt into batched fsync for throughput. Default is per-append
    // (`Always`), which is correct + safe. A `Periodic` policy
    // requires a witness cosigner deployment to maintain audit
    // integrity on crash; see `docs/OPERATIONS.md`.
    if let Ok(every) = std::env::var("ULLM_LOG_FSYNC_EVERY_N") {
        match every.parse::<u32>() {
            Ok(n) if n >= 1 => {
                transparency.set_fsync_policy(ullm_transparency::FsyncPolicy::Periodic { every_n: n });
                tracing::info!(every_n = n, "transparency log fsync policy = Periodic");
                if n > 1 {
                    // P9-FIX-G: Periodic fsync trades durability for
                    // throughput. On crash, up to `n-1` recent entries
                    // are lost — *acceptable only with a witness
                    // cosigner deployment* that can mark the truncated
                    // STH range as untrusted. Operators are required to
                    // acknowledge this in docs/OPERATIONS.md; we can't
                    // enforce the witness keyset here (no witness env
                    // var yet) but we emit a loud warning so the choice
                    // is visible in startup logs.
                    tracing::warn!(
                        every_n = n,
                        "FSYNC_EVERY_N > 1 enabled: a crash may lose up to {} entries. \
                         This is safe ONLY with at least one witness cosigner. \
                         See docs/OPERATIONS.md §3.3.",
                        n - 1
                    );
                }
            }
            _ => {
                anyhow::bail!("ULLM_LOG_FSYNC_EVERY_N must be a positive integer");
            }
        }
    }

    // The logger signing key — distributed out-of-band so auditors can verify
    // every Signed Tree Head. In production this is a long-lived key sealed
    // in the gateway's TEE; for local dev we generate fresh on startup.
    let logger_key = if let Ok(hex_seed) = std::env::var("ULLM_LOGGER_SEED") {
        let bytes = hex::decode(&hex_seed)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("ULLM_LOGGER_SEED must be 32 bytes hex"))?;
        SigningKey::from_bytes(&arr)
    } else {
        SigningKey::generate(&mut OsRng)
    };
    let logger_signing_key = Arc::new(logger_key);
    // P2-6: `log_id` is a stable per-deployment identifier baked into every
    // signed tree head. Operators set `ULLM_LOG_ID` explicitly (recommended
    // for prod, e.g. "ullm-mainnet-eu-1"); without it we fall back to the
    // hex-encoded logger public key, which is canonical-but-rotates-with-key.
    let log_id = std::env::var("ULLM_LOG_ID")
        .unwrap_or_else(|_| hex::encode(logger_signing_key.verifying_key().as_bytes()));
    // P9-FIX-G: bound `log_id` length. A 10 MB paste-buffer accident
    // would otherwise allocate that much per metrics scrape (gauge
    // body is built via `format!`). 128 chars is plenty for any
    // legitimate deployment id ("ullm-mainnet-eu-1") plus the 64-char
    // hex-pubkey fallback.
    if log_id.is_empty() || log_id.len() > 128 {
        anyhow::bail!(
            "ULLM_LOG_ID must be 1..=128 chars (got {}); use a stable identifier like \
             `ullm-mainnet-eu-1`",
            log_id.len()
        );
    }

    let state = GatewayState {
        tee_base_url,
        rate_limiter: Arc::new(RateLimiter::new(RateLimiterConfig::default())),
        transparency,
        logger_signing_key: logger_signing_key.clone(),
        log_id,
        // P10-FIX-C: shared STH cache so concurrent `/v1/transparency/head`
        // scrapes don't each force a `flush() + sign()`.
        sth_cache: Arc::new(SthCache::default()),
    };

    let cert = SelfSignedCert::generate(&["localhost", "127.0.0.1"])?;
    tracing::info!(
        addr = %addr,
        metrics_addr = %metrics_addr,
        fingerprint = %hex::encode(cert.fingerprint),
        logger_pk = %hex::encode(logger_signing_key.verifying_key().as_bytes()),
        "ullm-gateway listening on TLS"
    );

    // P13-FIX-A: opt into *strict* PQ-hybrid (X25519MLKEM768 only) via
    // `ULLM_REQUIRE_PQ=1`. With strict mode on, a MITM that strips the
    // PQ named group from `key_share`/`supported_groups` fails the
    // handshake instead of silently downgrading to classical
    // X25519 / secp256r1 — closing the audit's P13-D.HIGH-1 finding.
    // Default behavior is preserved (PQ-preferred but classical-tolerant)
    // so existing dev/staging deployments keep working; we emit a loud
    // `warn!` so the operational choice is visible at startup.
    let require_pq = std::env::var("ULLM_REQUIRE_PQ").ok().as_deref() == Some("1");
    let server_cfg = if require_pq {
        tracing::info!("PQ-hybrid strictly enforced (ULLM_REQUIRE_PQ=1) — classical fallback disabled");
        server_config_strict_pq(&cert)?
    } else {
        tracing::warn!(
            "PQ-hybrid not strictly enforced — set ULLM_REQUIRE_PQ=1 for production \
             to refuse classical-only TLS 1.3 handshakes (P13-D.HIGH-1)"
        );
        server_config(&cert)?
    };
    let rustls_cfg = RustlsConfig::from_config(server_cfg);

    // PR-1 + P10-FIX-A: graceful shutdown for the TLS-terminating
    // gateway. Use the workspace `ShutdownBroadcaster` so a SIGTERM
    // arriving during the startup race fans out to both listeners —
    // the previous `tokio::spawn(...) -> shutdown_handle.graceful_shutdown()`
    // pattern (per public listener) plus `with_graceful_shutdown(
    // shutdown_signal())` (per mgmt listener) registered SIGTERM
    // *twice* on Unix and was vulnerable to a "second handler misses
    // already-delivered signal" race the P10 audit caught.
    let broadcaster = ullm_core::ShutdownBroadcaster::install()?;
    let handle = axum_server::Handle::new();
    {
        let shutdown_handle = handle.clone();
        let mut b = broadcaster.clone();
        tokio::spawn(async move {
            b.wait().await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
    }
    // P9-FIX-A: keep a handle to the transparency log so we can force
    // a final fsync after the listener drains. Drop'ing the Arc inside
    // `state` happens later (after `serve.await` returns) but a paranoid
    // explicit flush makes the durability barrier observable in logs
    // and avoids relying on Drop ordering for the happy path.
    let transparency_for_shutdown = state.transparency.clone();
    // P9-FIX-C: bind the management listener (plain HTTP, loopback by
    // default) concurrently with the public TLS one. The TLS listener
    // owns the shutdown handle; on signal both terminate together.
    // `tokio::try_join!` propagates the first error.
    let mgmt_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
    let public_state = state.clone();
    let mgmt_state = state;
    let public_serve = async move {
        axum_server::bind_rustls(addr, rustls_cfg)
            .handle(handle)
            .serve(router(public_state).into_make_service())
            .await
            .map_err(anyhow::Error::from)
    };
    let mut mgmt_b = broadcaster.clone();
    let mgmt_serve = async move {
        axum::serve(mgmt_listener, metrics_router(mgmt_state))
            .with_graceful_shutdown(async move { mgmt_b.wait().await })
            .await
            .map_err(anyhow::Error::from)
    };
    tokio::try_join!(public_serve, mgmt_serve)?;
    if let Err(e) = transparency_for_shutdown.flush() {
        tracing::error!(error = %e, "final transparency-log fsync failed at shutdown");
    } else {
        tracing::info!("transparency log fsynced at shutdown");
    }
    // P9-FIX-E: drop the last in-scope handle to the transparency log
    // so its `Drop` impl gets a chance to fire one more best-effort
    // `sync_data()`. Without this, the `Arc` strong count is held by
    // `transparency_for_shutdown` until function-return — which is
    // *after* the "shutdown complete" log line, defeating the purpose
    // of having explicit fsync-then-log ordering.
    drop(transparency_for_shutdown);
    tracing::info!("ullm-gateway shutdown complete");
    Ok(())
}
