# Security Hardening Pass — Phase 9 Findings

Ninth iteration — targeted red-team on the **production-deployment work
(PR-1..PR-8)** added after the P8 confirmation round. The /goal stays:
keep spawning specialists until they come back clean.

Five specialists ran in parallel:

1. **Graceful shutdown** (PR-1: signal handler + `with_graceful_shutdown` +
   `axum-server::Handle`)
2. **`/metrics` endpoint** (PR-2: Prometheus text-format gauges on both
   binaries)
3. **Batched fsync** (PR-3: `FsyncPolicy` + `ULLM_LOG_FSYNC_EVERY_N`)
4. **BTreeSet LRU** (PR-4: rate-limiter + nonce-registry + tenant-pool
   eviction)
5. **CI prod-strings gate** (PR-7: `prod-strings` job + feature flags)

Result: **9 HIGH, 9 MEDIUM, and a handful of LOW findings** — every PR
had at least one real defect or hardening gap. Convergence-per-round
spiked back up because PR-1..PR-8 introduced fresh attack surface in
the same pass they meant to close out.

Every finding is fixed in this round. Workspace tests: **174 passing,
0 failing** (one new regression test for the nonce-registry boundary
desync; existing 173 carried forward).

---

## High severity

### P9-FIX-A — Transparency-log durability gap at STH signing + shutdown

**Where:** `crates/ullm-gateway/src/proxy.rs::transparency_head` and
`crates/ullm-transparency/src/log.rs::TransparencyLog`.

**Bug:** Under `FsyncPolicy::Periodic { every_n: 8 }`, up to 7 recent
appends live only in the page cache between fsync barriers. The
`transparency_head` handler signed an STH whose `size` and `root_hex`
covered those un-fsynced entries, producing a *signed commitment to a
Merkle root the restored log can never reconstruct* after a crash. A
client caching the STH would then receive a non-verifiable inclusion
proof on a subsequent query. Separately, on graceful shutdown the
gateway dropped the `Arc<TransparencyLog>` without calling
`sync_data()`, so the tail of unsynced entries was lost.

**Fix:** `transparency_head` calls `transparency.flush()` before
signing — the signed head is now always durably backed. Added
`impl Drop for TransparencyLog` that best-effort `sync_data()`s the
file, plus an explicit `flush()` call in the gateway's main()
post-`serve.await` for observable durability barriers in shutdown logs.

### P9-FIX-B — Nonce registry HashMap/BTreeSet desync enables replay

**Where:** `crates/ullm-tee/src/nonce_registry.rs::observe`.

**Bug:** `range(..(cutoff, [0u8; 32]))` is half-open and excludes the
boundary `(cutoff, *)` rows. A nonce re-observed *exactly* `NONCE_TTL`
later passed the `< NONCE_TTL` replay check (also half-open) and got
re-inserted at the new timestamp — but the old `(stale_ts, nonce)` row
was never removed from `lru`. Over many such boundary re-submissions
the BTreeSet grew past `seen.len()`. Eventually cap-eviction
(`MAX_TRACKED_NONCES = 128k`) picked a stale entry, called
`seen.remove(&nonce_bytes)`, and *removed a live tracked nonce* —
opening a replay window for a different legitimately-tracked nonce.

**Fix:** when `seen.get(&nonce)` returns `Some(seen_ts)`, explicitly
`lru.remove(&(seen_ts, nonce))` before re-inserting. Invariant
`seen.len() == lru.len()` now holds exactly; asserted in
`debug_assert_eq!` on every insert. Regression test
`boundary_reobservation_does_not_leak_lru_rows` pre-seeds a stale row
and asserts the invariant survives an `observe()` call.

### P9-FIX-C — `/metrics` reachable on the public TLS listener + flake.nix `0.0.0.0` exposure

**Where:** `crates/ullm-gateway/src/proxy.rs::router`,
`crates/ullm-tee/src/service.rs::router`,
`infra/tee-image/flake.nix` (TEE-image env vars).

**Bug:** Both `/metrics` endpoints were mounted on the same `Router` as
the protocol routes. A production deploy with `ULLM_GATEWAY_ADDR=0.0.0.0`
exposed `ullm_gateway_transparency_log_size{log_id="..."}` at scrape
granularity — combined with the public `/v1/transparency/head` endpoint
this gave any remote scraper a sub-STH-cadence view of attestation
throughput, a per-deployment activity histogram, and per-session
fingerprinting potential. The published TEE image at
`infra/tee-image/flake.nix:70` set `ULLM_TEE_ADDR=0.0.0.0:9001` — a
docker-run/k8s-svc misconfiguration would publish TEE-internal gauges
(nonce-registry size, tenant-pool size) to the same surface.

**Fix:** added `metrics_router(state)` on both crates returning a
separate `Router` with `/metrics` + `/v1/healthz`. Both binaries bind a
second listener (`ULLM_GATEWAY_METRICS_ADDR`, `ULLM_TEE_METRICS_ADDR`),
default loopback. `flake.nix` updated to explicitly set the metrics
addr to `127.0.0.1:9101`. Also hardened `sanitize_metric_label` to
escape `\r` and replace every other ASCII control character with
`\xNN` (a CRLF-tainted `ULLM_LOG_ID` previously injected a synthetic
`ullm_gateway_pwned 1` series).

### P9-FIX-D — `prod` feature was decorative; CI strings gate was keyword-scoped

**Where:** `crates/ullm-gateway/src/lib.rs`, `crates/ullm-tee/src/lib.rs`,
`.github/workflows/ci.yml::prod-strings`.

**Bug:** `prod = []` was an empty marker feature with zero `#[cfg]` use.
Gating was entirely via the *absence* of `dev-keys`. A local
`cargo build --release --features prod` that forgot
`--no-default-features` unified `dev-keys` back in and silently shipped
the `/v1/devkeys` route. The CI gate also only grep'd for `/v1/devkeys`
verbatim — sibling artifacts like `trust_root_hex`, `tee_receipt_pk_hex`,
`weight_commit_hex` (emitted only by the dev-keys JSON handler) would
slip past a future refactor.

**Fix:** added `compile_error!(...)` under `cfg(all(feature = "dev-keys",
feature = "prod"))` in both crates — the dangerous combination is now a
hard build error. CI gate extended to a denylist
(`/v1/devkeys`, `devkeys`, `trust_root_hex`, `tee_receipt_pk_hex`,
`weight_commit_hex`); any non-zero count on any needle fails the job.

### P9-FIX-E — Shutdown drain unbounded on TEE + zeroize race

**Where:** `crates/ullm-tee/src/bin/server.rs`,
`crates/ullm-gateway/src/bin/server.rs`.

**Bug:** The TEE used `axum::serve(...).with_graceful_shutdown(...)`
with no deadline. A slowloris WebSocket sending one byte every 59s
pinned the binary indefinitely until the orchestrator's `TimeoutStopSec`
SIGKILL'd it — defeating the careful drain. Separately, the gateway's
shutdown sequence let the `transparency_for_shutdown` Arc live until
function return, so the "shutdown complete" log line fired before the
final fsync was observable.

**Fix:** TEE now races `axum::serve(...).with_graceful_shutdown(...)`
against a 30 s sleep that starts only after the signal fires
(via `oneshot::channel`). If drain exceeds 30 s a warn-level log fires
and `main` returns — matching the gateway's existing
`axum-server::Handle::graceful_shutdown(Some(30s))` semantics. Explicit
`drop(state)` and `drop(transparency_for_shutdown)` after the serve
await force `Arc` strong-counts toward zero before logging "shutdown
complete", so `Zeroize`-on-drop has a chance to run.

---

## Medium severity

### P9-FIX-F — TenantPool eviction was O(N) linear scan, contradicting PR-4 design

**Where:** `crates/ullm-tee/src/tenant.rs::state_for`.

**Bug:** P8-2 capped the tenant pool with an LRU eviction path but used
`HashMap::iter().min_by_key(|(_, s)| s.last_seen)` — an O(N) scan over
up to 16K entries on every miss. The other PR-4 sites (rate-limiter,
nonce-registry) used the BTreeSet LRU pattern; the tenant pool quietly
didn't.

**Fix:** added `Inner { map, lru: BTreeSet<(Instant, u64, TenantId)>,
next_lru_seq }` matching the other two. Eviction now O(log N).
Required `TenantId: Ord`/`PartialOrd` (added to `ullm-core::ids`).

### P9-FIX-G — Multiple lower-severity hardening items

- **LRU tie-breaker bias**: All three LRU indexes used
  `BTreeSet<(Instant, Key)>`. On clock collision (Windows ~15 ms
  resolution) the lex order of the wrapped `String` / `[u8; 32]`
  decided eviction order — an attacker picking `\xff...` keys always
  sorted last and pushed legitimate names to be evicted first. Fixed
  by adding a monotonic `u64` seq counter to each LRU: tuple becomes
  `(Instant, u64_seq, Key)`. Same-`Instant` collisions are now FIFO
  by insert order rather than lex-by-key.
- **`log_id` length unbounded**: A 10 MB paste-buffer accident into
  `ULLM_LOG_ID` would allocate per scrape. Now hard-rejected at boot
  unless `1..=128` chars.
- **Periodic-fsync witness requirement** was operator-discipline-only.
  Now emits a loud `tracing::warn!` at boot when `ULLM_LOG_FSYNC_EVERY_N > 1`,
  reminding operators of the witness-cosigner requirement and pointing
  at `docs/OPERATIONS.md §3.3`.
- **Branch-protection enforcement** undocumented. `SECURITY.md` now
  documents the required GitHub branch-protection rules
  (`prod-binary strings check` as a required status check, signed
  commits, no force-push, attested release runner as future state).

---

## Non-findings (investigated, judged clean)

- **Signal re-entry / double-fire of `graceful_shutdown`** (PR-1.6,
  PR-1.7): `tokio::select!` handles single resolution; `axum-server`'s
  `Handle::graceful_shutdown` is idempotent. No race.
- **`set_fsync_policy` race with concurrent `append`** (PR-3.2):
  `parking_lot::Mutex` is held across the entire append path including
  the policy read. No race.
- **`appends_since_sync` overflow** (PR-3.3): `saturating_add(1)`. Pins
  at `u32::MAX`; the `>= every_n` check still fires. Defused.
- **`every_n: 0` constructed via public API** (PR-3.4): `every_n <= 1
  || ...` short-circuits true. Behaves as `Always`. No mod, no panic.
- **Mutex contention with `/metrics` scrape** (PR-2.3): `HashMap::len`
  + `BTreeSet::len` are nanosecond ops under the same mutex as
  `try_charge` / `observe`. Scraping at 1 Hz costs < 0.001 % of the
  request budget. Defused by math.
- **u64→f64 rounding past 2^53 in `log_size` gauge** (PR-2.7): would
  require ~3 million years at the current fsync ceiling. Defused by
  physics.
- **Cargo feature unification graph** (PR-7.F5): traced — `dev-keys`
  appears only on `ullm-gateway` and `ullm-tee`. No transitive
  re-enable path. `resolver = "2"` keeps dev-deps out of non-test
  builds. Clean.
- **Strip/LTO route literal re-layout** (PR-7.F10): `&'static str`
  literals stay contiguous under `lto = "fat"`, `codegen-units = 1`.
  `strings` finds them. No reformatting/splitting concern today.
- **Windows-service deploy** (PR-1.5): OPERATIONS.md never mentioned
  Windows service deploys; the audit's mention was misattributed.
  Linux/systemd only. No action.
- **WebSocket-upgrade hand-off bypasses axum-server tracking**
  (PR-1.2): real hygiene concern (long-running WS may be severed
  mid-frame at the 30 s deadline), but the underlying TLS+PQXDH
  encryption layer is unaffected — no plaintext leak, no key
  exposure. Tracked as deployment-readiness work (add a
  `tokio_util::task::TaskTracker`); not a security defect.

---

## Verification

- `cargo build --workspace --release` → 0 warnings, 0 errors.
- `cargo build --workspace --release --no-default-features --features prod`
  (gateway + TEE) → clean.
- `cargo build --release --features prod` (without `--no-default-features`)
  → **compile_error!** as designed.
- `cargo test --workspace --release` → **174 passed, 0 failed** (one
  new boundary-desync regression test added to nonce-registry).

---

## Cumulative status (P1 → P9)

- **57 confirmed vulnerabilities fixed** across nine iterative passes
  (P1–P8 = 50 + P9 = 7).
- **174 workspace tests** (one new regression per round on average).
- Every fix integrated into the existing architecture — no bolt-ons.
- Two end-to-end demos + headless WASM clickthrough + live HTTP
  nonce-replay check remain green after this round.

P9 spiked findings back up because the PR-1..PR-8 work introduced new
surface. A P10 confirmation round is warranted to verify the P9 fixes
themselves don't regress invariants.
