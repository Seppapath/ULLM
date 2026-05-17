// SPDX-License-Identifier: Apache-2.0
//! Axum-based blind reverse proxy.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as TMsg;
use tracing::{info, warn};

use ed25519_dalek::SigningKey;
use ullm_transparency::{
    InclusionProof, LogEntry, LogStatus, SignedTreeHead, TransparencyLog, TreeHead,
};

use crate::rate_limit::RateLimiter;

/// P10-FIX-C: min interval between two fresh STH signings for the
/// `/v1/transparency/head` endpoint. Repeated scrapes within this
/// window — when the log size hasn't changed — return the cached STH
/// instead of triggering a fresh `flush() + sign()`. Without this cap,
/// an unauthenticated attacker hammering the endpoint at 1000 req/s
/// would force the gateway to serialize all log appends behind that
/// many fsyncs/sec — a DoS amplification on attestation throughput.
///
/// 1 second is the same order of magnitude as the log's natural
/// fsync cadence under `Periodic` policy and well below any
/// audit-meaningful freshness target.
const STH_CACHE_TTL: Duration = Duration::from_secs(1);

/// Cached most-recently-signed STH. Stored inside `GatewayState` so
/// every handler sees the same cache. Mutex contention is bounded by
/// the lock duration (a handful of `format!` / signature ops); the
/// hot path (scrape under the TTL) is a single-pointer compare.
#[derive(Default)]
pub struct SthCache {
    inner: Mutex<Option<(SignedTreeHead, Instant)>>,
}

#[derive(Clone)]
pub struct GatewayState {
    pub tee_base_url: String,
    pub rate_limiter: Arc<RateLimiter>,
    pub transparency: Arc<TransparencyLog>,
    /// Ed25519 key the gateway uses to sign tree heads. Distributed
    /// out-of-band to clients + auditors so they can verify every STH.
    pub logger_signing_key: Arc<SigningKey>,
    /// Stable identifier for *this* transparency log, bound into every
    /// signed tree head (P2-6). Auditors compare it against an
    /// expected-log-ID list so an STH from log A can't be replayed as
    /// evidence for log B even when both share a logger key.
    pub log_id: String,
    /// P10-FIX-C: shared cache of the most-recent STH so repeated
    /// scrapes don't each force a `flush() + sign()`.
    pub sth_cache: Arc<SthCache>,
}

pub fn router(state: GatewayState) -> Router {
    // P3-3: dev-key passthrough is gated by the `dev-keys` feature so a prod
    // build (`--no-default-features --features prod`) drops the route + the
    // handler symbol entirely. The TEE has the same gate; without this
    // mirror, the gateway would still advertise `/v1/devkeys` and return a
    // 502 from the upstream — itself a deployment fingerprint.
    #[cfg_attr(not(feature = "dev-keys"), allow(unused_mut))]
    let mut router = Router::new()
        .route("/v1/healthz", get(|| async { "ok" }))
        .route("/v1/attest", get(proxy_attest))
        .route("/v1/stream", get(proxy_stream))
        .route("/v1/transparency", get(transparency_status))
        .route("/v1/transparency/log", get(transparency_log))
        .route("/v1/transparency/head", get(transparency_head))
        .route("/v1/transparency/proof", get(transparency_proof));
    #[cfg(feature = "dev-keys")]
    {
        router = router.route("/v1/devkeys", get(proxy_devkeys));
    }
    router.with_state(state)
}

/// P9-FIX-C: management router for `/metrics`. Mounted on a separate
/// listener (`ULLM_GATEWAY_METRICS_ADDR`, default `127.0.0.1:9100`) so
/// the Prometheus exposition is never reachable from the public TLS
/// listener.
///
/// P10-FIX-D + P11-FIX-D: when `ULLM_METRICS_TOKEN` is set, `/metrics`
/// requires `Authorization: Bearer <token>` (case-insensitive scheme,
/// constant-time compare). Returns `404 Not Found` with an **empty**
/// body on mismatch — matching axum's default unknown-route response
/// exactly so an attacker can't fingerprint auth-fail vs no-such-route
/// via body length. `/v1/healthz` is mounted via `route_layer` so the
/// auth middleware applies only to `/metrics` — load balancers can
/// probe mgmt-side healthz without the token, matching the public
/// listener's behavior.
pub fn metrics_router(state: GatewayState) -> Router {
    let token = std::env::var("ULLM_METRICS_TOKEN").ok().filter(|s| !s.is_empty());
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
        .route("/v1/healthz", get(|| async { "ok" }))
        .with_state(state)
}

/// P10-FIX-D middleware: constant-time bearer-token check. Drops the
/// path through to the handler on match; returns 404 with empty body
/// on miss so an attacker can't fingerprint deployments by probing
/// for 401s or by comparing response sizes against axum's default 404.
///
/// P11-FIX-D: scheme parse is case-insensitive (RFC 7235 §2.1) — a
/// client sending `bearer TOKEN` (lowercase) is accepted.
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
        // Empty body so the response is byte-for-byte the axum default
        // 404 — defeats response-length fingerprinting.
        StatusCode::NOT_FOUND.into_response()
    }
}

/// RFC 7235 §2.1 says auth-scheme matching MUST be case-insensitive
/// and allows `1*SP` between scheme and credential. Parse defensively
/// so legitimate `bearer <token>` (lowercase) and `Bearer  <token>`
/// (two spaces) clients aren't silently rejected.
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

/// Prometheus text-format `/metrics` endpoint. Surfaces the gauges
/// operators need to confirm a deployment is healthy: transparency-log
/// size (monotonic counter via `gauge` for simplicity), bucket-table
/// size vs `max_tenants` cap, and protocol version. Counters for
/// attestation requests + replays would require state changes on the
/// hot path; gauges from existing state are zero-overhead.
async fn metrics(State(state): State<GatewayState>) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    let log_size = state.transparency.status().size;
    let bucket_count = state.rate_limiter.tenant_count();
    let log_id = sanitize_metric_label(&state.log_id);
    let body = format!(
        "\
# HELP ullm_gateway_protocol_version Wire protocol version this binary speaks.
# TYPE ullm_gateway_protocol_version gauge
ullm_gateway_protocol_version {protocol}
# HELP ullm_gateway_transparency_log_size Append-only count of entries in the transparency log.
# TYPE ullm_gateway_transparency_log_size gauge
ullm_gateway_transparency_log_size{{log_id=\"{log_id}\"}} {log_size}
# HELP ullm_gateway_rate_limiter_buckets Live tenant bucket count.
# TYPE ullm_gateway_rate_limiter_buckets gauge
ullm_gateway_rate_limiter_buckets {bucket_count}
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

/// Prometheus exposition forbids `"`, `\`, and `\n` inside a label
/// value unless escaped. P9-FIX-C + P10-FIX-D: we also escape `\r`
/// (CRLF-tainted env-var injection vector), every ASCII control char,
/// the BOM (`U+FEFF`), and Unicode bidi controls (`U+202A..U+202E`,
/// `U+2066..U+2069`). Those Cf-category code points pass `is_control()`
/// as `false` in Rust but render adversarially in Grafana labels and
/// break log-grep on the scrape output. We replace them with `\uNNNN`.
fn sanitize_metric_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            // Cf category — invisible-format characters that aren't
            // `is_control()` but are equally adversarial in metric
            // labels. Cover BOM + the bidi family.
            '\u{FEFF}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(feature = "dev-keys")]
async fn proxy_devkeys(
    State(state): State<GatewayState>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let url = format!("{}/v1/devkeys", state.tee_base_url.trim_end_matches('/'));
    let (status, bytes) = http_get_passthrough(&url)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(axum::response::Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(bytes))
        .expect("response build"))
}

async fn transparency_status(State(state): State<GatewayState>) -> axum::Json<LogStatus> {
    axum::Json(state.transparency.status())
}

async fn transparency_log(State(state): State<GatewayState>) -> axum::Json<Vec<LogEntry>> {
    axum::Json(state.transparency.snapshot())
}

async fn transparency_head(
    State(state): State<GatewayState>,
) -> Result<axum::Json<SignedTreeHead>, (StatusCode, String)> {
    // P10-FIX-C + P11-FIX-C: cache-fast-path. If a fresh STH was
    // signed within `STH_CACHE_TTL`, return the cached STH without
    // touching the disk OR the log mutex. The P10 version of this
    // fast-path still called `state.transparency.status()` first,
    // which acquires the log's parking_lot::Mutex and recomputes the
    // full Merkle root over every entry — *that* was the dominant
    // cost under scrape pressure (the cache only saved `flush() +
    // sign()`, not the merkle hash, which is O(n) over the log). We
    // now check the cache first; on TTL hit we trust the cached size
    // even if a new entry has been appended since (the cached STH
    // still commits to a real past state, which is what an STH is by
    // definition).
    {
        let cache = state.sth_cache.inner.lock().expect("sth cache poisoned");
        if let Some((sth, signed_at)) = cache.as_ref() {
            if signed_at.elapsed() < STH_CACHE_TTL {
                return Ok(axum::Json(sth.clone()));
            }
        }
    }
    // Cache miss: force a durability barrier, then re-sign.
    //
    // P9-FIX-A: under `FsyncPolicy::Periodic`, up to `every_n - 1`
    // recent appends may still live only in the page cache. If we sign
    // an STH whose `size` and `root_hex` cover those un-fsynced
    // entries, a power-loss between this signature and the next
    // periodic fsync produces a signed commitment to a Merkle root the
    // restored log can never reconstruct — clients holding the cached
    // STH would never get a valid inclusion proof. Force a barrier so
    // the signed head is always durably backed.
    state
        .transparency
        .flush()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("flush: {e}")))?;
    let status = state.transparency.status();
    // P6 clock-skew: prefer the fail-closed reader, but the
    // `transparency_head` endpoint must always return *something* (it's
    // used by external auditors as a heartbeat). On a pre-1970 clock we
    // fall back to 0 — auditors will notice the implausible timestamp
    // far faster than they'd notice a 500. The `issued_at_unix` is
    // metadata, not a security gate; the cryptographic STH signature
    // doesn't depend on the timestamp value being correct.
    let now = ullm_core::now_unix_or_zero();
    let head = TreeHead {
        size: status.size,
        root_hex: status.root_hex,
        issued_at_unix: now,
        log_id: state.log_id.clone(),
    };
    let sth = SignedTreeHead::sign(head, &state.logger_signing_key);
    // Update the cache. Always overwrite — even when concurrent
    // scrapes raced past the cache check, we want the latest signing
    // time so the next request's TTL window resets.
    {
        let mut cache = state.sth_cache.inner.lock().expect("sth cache poisoned");
        *cache = Some((sth.clone(), Instant::now()));
    }
    Ok(axum::Json(sth))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofQuery {
    seq: u64,
}

async fn transparency_proof(
    State(state): State<GatewayState>,
    Query(q): Query<ProofQuery>,
) -> Result<axum::Json<InclusionProof>, (StatusCode, String)> {
    let entries = state.transparency.snapshot();
    InclusionProof::build(&entries, q.seq)
        .map(axum::Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("seq {} out of range (size={})", q.seq, entries.len()),
            )
        })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestQuery {
    nonce: String,
}

async fn proxy_attest(
    State(state): State<GatewayState>,
    Query(q): Query<AttestQuery>,
    headers: HeaderMap,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let tenant = tenant_from_headers(&headers);
    if !state.rate_limiter.try_charge(&tenant, 4096) {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit".into()));
    }
    // SECURITY: `q.nonce` flows into a constructed HTTP request URL. Reject
    // anything that isn't exactly 64 hex chars before interpolating, so the
    // upstream request line cannot be smuggled (CRLF injection) and the
    // upstream parser sees a well-formed nonce.
    if !is_hex_nonce(&q.nonce) {
        return Err((
            StatusCode::BAD_REQUEST,
            "nonce must be 64 hex chars".into(),
        ));
    }
    let url = format!(
        "{}/v1/attest?nonce={}",
        state.tee_base_url.trim_end_matches('/'),
        q.nonce
    );
    let (status, bytes) = http_get_passthrough(&url)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    // P4-5: propagate the TEE's status. The previous code returned the
    // body as bytes regardless of the upstream status code, so a 409
    // (attestation-nonce replay) was indistinguishable from a 200 bundle
    // — silently defeating the per-TEE nonce registry.
    if !status.is_success() {
        let msg = String::from_utf8_lossy(&bytes).into_owned();
        return Err((status, msg));
    }
    // Transparency log entry: postcard prefixes structs with their fields
    // in declaration order, so reading the leading 32 bytes is sufficient
    // to extract `id_pk`. The rest of the bundle stays opaque to the
    // gateway.
    //
    // SECURITY: persistence failures (disk full, fsync error) bubble up as
    // 5xx so an operator/observer can't be told "log size advanced" when
    // the on-disk view diverged from the in-memory one.
    if bytes.len() >= 32 {
        let mut id_pk = [0u8; 32];
        id_pk.copy_from_slice(&bytes[..32]);
        // P6 clock-skew: refuse to write a log entry with a corrupted
        // timestamp — an auditor walking the log expects roughly
        // monotonic `observed_at_unix`. A pre-1970 clock surfacing as
        // zero in the middle of the log is worse than failing the
        // append outright.
        let now = ullm_core::now_unix().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("transparency log timestamp unavailable: {e}"),
            )
        })?;
        state
            .transparency
            .append(id_pk, &bytes, now)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("transparency log: {e}")))?;
    }
    Ok(bytes)
}

async fn proxy_stream(
    ws: WebSocketUpgrade,
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant = tenant_from_headers(&headers);
    // P2-2: cap per-message size so a peer cannot stream a multi-GB frame
    // and OOM the gateway before we even know what it is. The protocol's
    // largest legitimate message (handshake bundle + proof envelope) fits
    // comfortably inside `MAX_WS_MESSAGE_BYTES`.
    ws.max_message_size(ullm_core::MAX_WS_MESSAGE_BYTES)
        .max_frame_size(ullm_core::MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            if let Err(e) = relay(socket, state, tenant).await {
                warn!(error = %e, "relay terminated");
            }
        })
}

async fn relay(
    client_ws: WebSocket,
    state: GatewayState,
    tenant: String,
) -> anyhow::Result<()> {
    let upstream_url = format!(
        "{}/v1/stream",
        state.tee_base_url.trim_end_matches('/')
    );
    let upstream_ws_url = http_to_ws(&upstream_url);
    let (upstream, _) = tokio_tungstenite::connect_async(upstream_ws_url).await?;

    let (mut c_tx, mut c_rx) = client_ws.split();
    let (mut u_tx, mut u_rx) = upstream.split();
    let rl = state.rate_limiter.clone();
    let tenant_in = tenant.clone();
    let tenant_out = tenant.clone();

    // Client → upstream
    let c_to_u = async move {
        while let Some(msg) = c_rx.next().await {
            let msg = msg?;
            let bytes_len = msg_len(&msg);
            if bytes_len > 0 && !rl.try_charge(&tenant_in, bytes_len as u64) {
                return Err::<(), anyhow::Error>(anyhow::anyhow!(
                    "tenant {tenant_in} rate-limited inbound"
                ));
            }
            let translated = translate_axum_to_tungstenite(msg);
            if matches!(translated, TMsg::Close(_)) {
                u_tx.send(translated).await?;
                break;
            }
            u_tx.send(translated).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    // Upstream → client
    let u_to_c = async move {
        while let Some(msg) = u_rx.next().await {
            let msg = msg?;
            let bytes_len = tmsg_len(&msg);
            if bytes_len > 0 && !state.rate_limiter.try_charge(&tenant_out, bytes_len as u64) {
                return Err::<(), anyhow::Error>(anyhow::anyhow!(
                    "tenant {tenant_out} rate-limited outbound"
                ));
            }
            let translated = translate_tungstenite_to_axum(msg);
            if matches!(translated, Message::Close(_)) {
                c_tx.send(translated).await?;
                break;
            }
            c_tx.send(translated).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(c_to_u, u_to_c)?;
    info!(%tenant, "relay finished");
    Ok(())
}

/// Sanitize the `x-ullm-tenant` header to prevent log injection and
/// arbitrary-byte tenant identifiers. Only ASCII alphanumeric, `_`, `-`,
/// and `.` survive; anything else falls back to `anonymous`.
fn tenant_from_headers(h: &HeaderMap) -> String {
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

fn is_hex_nonce(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn msg_len(m: &Message) -> usize {
    match m {
        Message::Text(s) => s.len(),
        Message::Binary(b) => b.len(),
        _ => 0,
    }
}

fn tmsg_len(m: &TMsg) -> usize {
    match m {
        TMsg::Text(s) => s.len(),
        TMsg::Binary(b) => b.len(),
        _ => 0,
    }
}

fn translate_axum_to_tungstenite(m: Message) -> TMsg {
    match m {
        Message::Text(s) => TMsg::Text(s.into()),
        Message::Binary(b) => TMsg::Binary(b.into()),
        Message::Ping(b) => TMsg::Ping(b.into()),
        Message::Pong(b) => TMsg::Pong(b.into()),
        Message::Close(c) => TMsg::Close(c.map(|c| {
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(c.code),
                reason: c.reason.into(),
            }
        })),
    }
}

fn translate_tungstenite_to_axum(m: TMsg) -> Message {
    match m {
        TMsg::Text(s) => Message::Text(s.to_string()),
        TMsg::Binary(b) => Message::Binary(b.to_vec()),
        TMsg::Ping(b) => Message::Ping(b.to_vec()),
        TMsg::Pong(b) => Message::Pong(b.to_vec()),
        TMsg::Close(c) => Message::Close(c.map(|c| axum::extract::ws::CloseFrame {
            code: c.code.into(),
            reason: c.reason.to_string().into(),
        })),
        TMsg::Frame(_) => Message::Close(None),
    }
}

fn http_to_ws(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        url.to_string()
    }
}

/// HTTP/1.1 GET that **preserves the upstream status code**. Phase 4
/// audit (P4-5) caught the previous version dropping the status line
/// entirely: a TEE-side 409 (attestation-nonce replay) was returned to
/// the client as 200 with the error string in the body — bypassing
/// the replay defense. Returning `(StatusCode, body)` lets the handler
/// echo upstream's status back to the caller.
async fn http_get_passthrough(url: &str) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let parsed = parse_url(url)?;
    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port)).await?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let body_idx = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("bad HTTP response"))?;
    // Parse the status line: "HTTP/1.1 200 OK\r\n..."
    let head_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(body_idx);
    let status_line = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| anyhow::anyhow!("non-utf8 HTTP status line"))?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP status line: {status_line}"))?;
    let status =
        StatusCode::from_u16(code).map_err(|_| anyhow::anyhow!("bad HTTP status code {code}"))?;
    Ok((status, buf[body_idx + 4..].to_vec()))
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> anyhow::Result<ParsedUrl> {
    let (_scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("bad url"))?;
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse()?),
        None => (host_port.to_string(), 80),
    };
    Ok(ParsedUrl { host, port, path })
}

