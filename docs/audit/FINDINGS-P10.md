# Security Hardening Pass — Phase 10 Findings

Tenth iteration — targeted red-team on the **P9 fix surface itself**.
P9 closed out the deployment-readiness work but introduced ~600 lines
of new code in security-critical paths (shutdown multiplexing, BTreeSet
LRU rewrite, `Drop` impls, compile-time gates, CI scripts). P10 audits
that code for defects the original P9 round missed.

Five specialists ran in parallel:

1. **Shutdown signal multiplexing** (P9-FIX-E: `Notify` + `oneshot` +
   `Mutex<Option>` fan-out)
2. **u64 seq tie-breaker** (P9-FIX-G: monotonic counter in all 3 LRU
   indexes)
3. **TransparencyLog `Drop` + flush** (P9-FIX-A)
4. **`/metrics` router split** (P9-FIX-C: separate listener + sanitizer)
5. **`compile_error!` mutual exclusion** (P9-FIX-D: cargo features +
   CI strings gate)

Result: **3 HIGH, 9 MEDIUM, handful of LOW**. Every HIGH was a real
defect inside the P9 fix (not a pre-existing issue), confirming the
/goal's premise that successive rounds find different bugs.

All findings are fixed in this round. Workspace tests: **176 passing,
0 failing** (two new regression tests: late-subscriber signal in
`ullm-core`, torn-write recovery in `ullm-transparency`).

---

## High severity

### P10-FIX-A — `Notify`-based signal multiplexing missed signals during the registration race

**Where:** `crates/ullm-tee/src/bin/server.rs` (P9-FIX-E pattern) and
`crates/ullm-gateway/src/bin/server.rs` (double `shutdown_signal()`
call).

**Bug:** Two issues combined:

1. **TEE side**: the P9 fix spawned a task that called
   `notify_waiters()` on an `Arc<Notify>` to broadcast SIGTERM/SIGINT
   to two listeners. `tokio::sync::Notify::notify_waiters()` only
   wakes *currently registered* waiters — it does **not** retain
   permits. A signal that arrived during the window between
   `tokio::spawn(...)` and the first poll of `notified()` inside
   `with_graceful_shutdown(...)` was silently lost; the binary would
   never start draining.
2. **Gateway side**: `shutdown_signal()` was called twice (once in
   the spawned task that drives `axum_server::Handle::graceful_shutdown`
   and once inside `with_graceful_shutdown(shutdown_signal())` on the
   mgmt listener). On Unix, `tokio::signal::unix::signal(...)` is
   edge-triggered after first install; the second registration could
   miss an already-delivered SIGTERM.

**Fix:** Introduce `ShutdownBroadcaster` in `ullm-core::shutdown`,
backed by `tokio::sync::watch::channel(bool)`. The watch **retains**
the latest sent value, so a subscriber that polls after the signal
already fired still observes `true`. One signal-handler task is
spawned per binary; all listeners + deadline timer subscribe via
`broadcaster.clone()` and wait on `.wait().await`. Eliminates both
the registration race and the double-register hazard.

Regression test: `late_subscriber_sees_fired_signal` in
`ullm-core/src/shutdown.rs` — pre-flips the watch, then constructs a
broadcaster and asserts `.wait()` resolves within 100ms.

### P10-FIX-B.1 — CI `feature-matrix --workspace --features prod` self-breaks the workspace

**Where:** `.github/workflows/ci.yml::feature-matrix` row 3.

**Bug:** The `feature-matrix` job's third row ran
`cargo check --workspace --release --no-default-features --features prod`.
With resolver=2, `--workspace` applies the `--features` flag to every
member, but downstream deps like `tools/ullm-demo/Cargo.toml`
(`ullm-tee = { workspace = true }` — no `default-features = false`)
still request defaults on `ullm-tee`. Feature unification activates
*both* `dev-keys` (from the downstream dep) and `prod` (from the
CLI flag), tripping the P9-FIX-D `compile_error!` and turning every
PR's matrix row red.

**Fix:** Scope the prod row to `-p ullm-gateway -p ullm-tee` instead
of `--workspace`. The `trusted-dealer` row gets the same treatment —
narrowed to `-p ullm-threshold` since that's the only crate defining
the feature. Matrix structure refactored from a flat list of feature
strings to an `include:` block with `name` + `cmd` fields for
readability.

### P10-FIX-B.2 — Strings denylist included a prod-path Receipt field name

**Where:** `.github/workflows/ci.yml::prod-strings` denylist
(P9-FIX-D extension).

**Bug:** The P9-FIX-D denylist added `weight_commit_hex` alongside
`/v1/devkeys`, `trust_root_hex`, and `tee_receipt_pk_hex`. But
`weight_commit_hex` is a wire-protocol field name on the prod-path
`Receipt` struct (`crates/ullm-receipts/src/lib.rs:29`), and serde's
derive embeds field-name `&'static str`s into every binary that links
the type. The prod TEE binary necessarily contains the literal,
which means the strings-check was guaranteed to fail every CI run
— either the gate had never run green since P9, or it had been
silently amended/bypassed.

**Fix:** Remove `weight_commit_hex` from the denylist. The remaining
needles (`/v1/devkeys`, `devkeys`, `trust_root_hex`, `tee_receipt_pk_hex`)
appear *only* in the `dev-keys`-gated handler and are correctly
absent in a prod build.

---

## Medium severity

### P10-FIX-C.1 — `/v1/transparency/head` flushed on every scrape → DoS amplification

**Where:** `crates/ullm-gateway/src/proxy.rs::transparency_head`
(P9-FIX-A change).

**Bug:** P9-FIX-A added `transparency.flush()` to every STH-signing
call so the signed head was always durably backed. But the endpoint
is unauthenticated and unrated; an attacker hammering it at
1000 req/s drove 1000 `sync_data()` calls/s, serializing all log
appends behind the disk's fsync rate — a DoS amplification on
attestation throughput.

**Fix:** Added `SthCache { Mutex<Option<(SignedTreeHead, Instant)>> }`
to `GatewayState`. `transparency_head` first checks if the cached
STH's tree size matches the current size *and* was signed within
`STH_CACHE_TTL = 1s`; if so, returns the cached STH without touching
the disk. Cache miss → flush + re-sign + cache-update.
Concurrent scrapes share a single fsync per ~1-second window.

### P10-FIX-C.2 — Reopen after Periodic-fsync crash refused to start

**Where:** `crates/ullm-transparency/src/log.rs::open_persistent`.

**Bug:** Under `FsyncPolicy::Periodic`, a crash mid-write leaves the
file's tail as a partially-flushed line. The previous reopen path
called `serde_json::from_str` on every line including the torn tail
and returned `ErrorKind::InvalidData` — refusing to start the gateway.

**Fix:** Reopen now reads raw bytes and parses line-by-line. On a
parse failure **at the last line only and without a trailing
newline**, log a `tracing::warn!` and truncate the file to the end
of the last good line (durably, via `set_len + sync_data`). Failures
earlier in the file remain fatal (real corruption / tampering).
Regression test: `torn_write_tail_recovers_on_reopen` simulates a
torn tail and asserts reopen + continued append both work.

### P10-FIX-C.3 — Boundary regression test didn't exercise the bug it claimed to regress

**Where:** `crates/ullm-tee/src/nonce_registry.rs::tests::boundary_reobservation_does_not_leak_lru_rows`
(P9-FIX-B test).

**Bug:** The P9 test pre-seeded an entry with
`ancient = now - 2 * NONCE_TTL` — well past the GC cutoff — so the
GC walk collected it before the boundary-remove fix path was ever
reached. The test passed because the GC works, not because the fix
works.

**Fix:** Pre-seed at *exactly* the half-open boundary
(`cutoff_exact = pre_seed_now - NONCE_TTL`). With that seed and a
subsequent `observe()` call whose computed cutoff is numerically
identical (within nanoseconds), the GC's
`range(..(cutoff, 0, [0u8; 32]))` excludes the boundary row and the
explicit `state.lru.remove(&(seen_ts, seen_seq, nonce))` is what
saves the invariant.

### P10-FIX-D.1 — Metrics listener silently accepted non-loopback bind

**Where:** `crates/ullm-{gateway,tee}/src/bin/server.rs`.

**Bug:** `ULLM_*_METRICS_ADDR` was parsed and bound without any
loopback check. An operator typo `0.0.0.0:9100` silently published
`/metrics` (with `log_id` label, transparency-log size, tenant
counts) to the public network.

**Fix:** `ullm_core::validate_metrics_addr` checks `is_loopback()`
and refuses to bind otherwise — unless `ULLM_METRICS_ALLOW_PUBLIC=1`
is set, in which case a `tracing::warn!` is emitted and the operator
is on the hook to pair it with `ULLM_METRICS_TOKEN` and a firewall.

### P10-FIX-D.2 — Sanitizer missed Unicode bidi controls + BOM

**Where:** `crates/ullm-gateway/src/proxy.rs::sanitize_metric_label`.

**Bug:** The P9-FIX-C sanitizer escaped `\`, `"`, `\n`, `\r`, and
every `c.is_control()`. But Cf-category code points (BOM `U+FEFF`,
bidi controls `U+202A..U+202E`, isolate controls `U+2066..U+2069`,
zero-width-space `U+200B..U+200F`) pass `is_control()` as `false` in
Rust and were emitted verbatim — adversarial in Grafana labels and
breaking log-grep.

**Fix:** Extended the match to escape the Cf ranges as `\uNNNN`.

### P10-FIX-D.3 — No auth on management listener

**Where:** `crates/ullm-{gateway,tee}/src/service.rs::metrics_router`.

**Bug:** Loopback alone is not a trust boundary inside a TEE-VM:
co-resident operator tools / sidecars / shell-via-RCE could scrape
freely.

**Fix:** Optional `ULLM_METRICS_TOKEN` env var. When set, a
`axum::middleware::from_fn` layer requires `Authorization: Bearer
<token>`, compared in constant time via `subtle::ConstantTimeEq`.
On mismatch the response is **404 Not Found** (not 401) so an
attacker can't fingerprint deployments by probing for auth-error
codes. Unset → unauthenticated as before (acceptable for strict
loopback deploys).

### P10-FIX-E.1 — CI gate didn't fire on release tag

**Where:** `.github/workflows/ci.yml::on`.

**Bug:** Workflow triggers were `push: branches: [main]`, `pull_request`,
`workflow_dispatch`. A maintainer cutting a release with
`git tag v0.2.0 && git push origin v0.2.0` skipped every gate
— including the strings check, the last line of defense against a
dev-keys leak.

**Fix:** Added `push: tags: ['v*.*.*']` so the prod-strings job
runs against the exact tagged commit. Also gated the `audit-packet`
job on tag pushes so the artifact corresponds 1:1 to a release.

### P10-FIX-E.2 — No CODEOWNERS protecting the compile_error + CI yml

**Where:** Repo root.

**Bug:** The P9-FIX-D `compile_error!` lines in
`crates/ullm-{gateway,tee}/src/lib.rs` and the CI strings-check in
`.github/workflows/ci.yml` are the two layers preventing a dev-keys
leak. Without a CODEOWNERS file requiring security review, a single
reviewer could approve a PR that disables both layers simultaneously.

**Fix:** Added `.github/CODEOWNERS` routing the compile_error files,
the workflow yml, the security-critical crates, the security/release
docs, and the build-reproducibility infra to `@ullm-security`.
Operators are expected to wire branch protection to require code-owner
approval for matching paths on `main`.

---

## Non-findings (investigated, judged clean)

- **P10-A signal re-entry / double `graceful_shutdown` calls**: clean
  (tokio Notify wakes only registered waiters; axum-server handle is
  idempotent). P10-A.6 noted that on a 30s force-drain mid-WS-frame,
  the receipt is *cryptographically clean* because `ReceiptSigner`
  signs post-hoc over the complete transcript — a truncated stream
  yields no partial receipt.
- **P10-B.1 u64 wraparound**: at 1B observations/sec, u64::MAX takes
  ~584 years to reach. Documented; the doc comment that previously
  claimed "6 million years" was incorrect but no exploit. Updated.
- **P10-B.5 memory budget comment**: `MAX_TRACKED_NONCES = 128k` ×
  (HashMap entry + BTreeSet entry + node overhead) ≈ 19-26 MiB worst
  case, not 5 MiB as the comment claimed. Updated comment.
- **P10-C.1 `get_mut` on Mutex during Drop**: clean. `&mut self`
  proves exclusive access via borrow checker.
- **P10-C.2 panic in Drop**: clean. `sync_data()` returns `io::Error`,
  not panic. `let _ = ...` discards.
- **P10-C.5 STH error message leak**: clean. `io::Error::to_string()`
  for fsync failures doesn't include the file path.
- **P10-D port collision / TEE healthz dual-mount / flake ExposedPorts**:
  clean (fail-fast on `bind`, dual healthz is intentional for LB
  probes, flake env default is loopback).
- **P10-E.5 bindings**: `bindings/python` and `bindings/ts` don't
  depend on `ullm-gateway` or `ullm-tee` — no surface for dev-keys
  leak via the WASM/Python boundary.

---

## Verification

- `cargo build --workspace --release` → 0 warnings, 0 errors.
- `cargo build --release --no-default-features --features prod` (gateway
  + TEE) → clean.
- `cargo build --release --features prod` (without `--no-default-features`)
  → **compile_error!** as designed (unchanged from P9).
- `cargo test --workspace --release` → **176 passed, 0 failed** (two
  new regression tests: `late_subscriber_sees_fired_signal` and
  `torn_write_tail_recovers_on_reopen`).

---

## Cumulative status (P1 → P10)

- **65 confirmed vulnerabilities fixed** across ten iterative passes
  (P1–P8 = 50, P9 = 7, P10 = 8).
- **176 workspace tests** (one or two new regressions per round).
- Every fix integrated into the existing architecture — no bolt-ons.
- Two end-to-end demos + headless WASM clickthrough + live HTTP
  nonce-replay check remain green after this round.

P10 was a **confirmation-focused round on P9's surface** rather than a
new-surface round. The three HIGH findings were all defects inside the
P9 fixes themselves (signal race, CI matrix self-break, denylist
false-positive), supporting the audit-cadence premise that
"every round of fixes adds attack surface that needs its own round."
The next round (P11) would target the P10 fix surface (watch-channel
broadcaster, SthCache contention, CODEOWNERS bypass paths) or could
pivot to a different angle (e.g., dependency-chain audit since
`subtle` was added).
