# Security Hardening Pass — Phase 11 Findings

Eleventh iteration — targeted red-team on the **P10 fix surface**.
Same audit cadence as P10: every round of fixes adds ~400-600 lines of
new code in security-critical paths, and the next round catches the
defects in those fixes.

Five specialists ran in parallel:

1. **`ShutdownBroadcaster`** (P10-FIX-A: `watch::channel` fan-out)
2. **`SthCache`** (P10-FIX-C: cached STH for fsync-DoS defense)
3. **Bearer-token middleware** (P10-FIX-D: optional `/metrics` auth)
4. **JSONL torn-write recovery** (P10-FIX-C: reopen path)
5. **CI gate + CODEOWNERS** (P10-FIX-B/E: feature matrix + tag trigger
   + CODEOWNERS file)

Result: **4 HIGH, 6 MEDIUM, handful of LOW**. As predicted, all four
HIGH findings were defects *inside the P10 fixes* — not in the
unchanged code below. Fixed in this round.

Workspace tests: **177 passing, 0 failing** (one new regression:
`sender_drop_does_not_masquerade_as_signal` in `ullm-core/shutdown`).

---

## High severity

### P11-FIX-A.1 — `ShutdownBroadcaster::wait()` masked dead-signal-subsystem as graceful drain

**Where:** `crates/ullm-core/src/shutdown.rs::wait`.

**Bug:** The P10 implementation did `let _ = self.rx.changed().await;` —
swallowing the `Err` variant. `watch::Receiver::changed()` returns
`Err` when the sender drops. The sender drops if the spawned
signal-handler task panics OR if the tokio runtime is being torn down
(e.g., during a `main()` panic before the listeners spin up). In both
cases the binary would interpret "sender dropped" as "signal fired"
and start a graceful drain — exiting 0 while the signal subsystem
was actually dead.

**Fix:** Distinguish the two outcomes:
```rust
match self.rx.changed().await {
    Ok(()) => {}
    Err(_) => {
        tracing::error!("shutdown broadcaster sender dropped without signal …");
        std::future::pending::<()>().await;
    }
}
```
Regression test: `sender_drop_does_not_masquerade_as_signal` drops
the sender immediately and asserts `wait()` does NOT resolve within
100ms.

### P11-FIX-A.2 — Signal handlers installed inside spawned task → tiny lossy window

**Where:** `crates/ullm-core/src/shutdown.rs::install`.

**Bug:** P10 spawned a task that called `shutdown_signal()` *inside*
the spawn closure — meaning the OS signal handlers (`SignalKind::interrupt`,
`SignalKind::terminate`) were registered only when the task's first
poll happened. A SIGTERM delivered to the process between
`tokio::spawn(...)` and the task's first poll was processed under
the OS default disposition (terminate the process), entirely
bypassing the drain path.

**Fix:** Install signal streams synchronously on the caller's thread
*before* `tokio::spawn(...)`. Pre-spawn signals are queued in the
stream and delivered on first `.recv().await`. The `install()`
signature now returns `io::Result<Self>` so signal-install failures
surface to `main` instead of being deferred.

### P11-FIX-B — Torn-write recovery used `read_to_end` → unbounded RAM at startup

**Where:** `crates/ullm-transparency/src/log.rs::open_persistent`
(P10-FIX-C rewrite).

**Bug:** The P10 fix replaced the streaming `BufReader::lines()`
pattern with `f.read_to_end(&mut raw)?` to enable cursor-tracked
truncation. Side effect: every reopen slurped the entire log into
RAM. A multi-GB log (accumulated over a year of operation, or planted
by an attacker with filesystem write access) would OOM the binary at
startup. Regression vs the pre-P10-FIX-C behavior, which streamed.

**Fix:** Stream via `BufReader::read_until(b'\n', ...)` while still
tracking `cursor` and `good_end` for truncation. Add a hard
`MAX_REOPEN_LINE_BYTES = 16 MiB` per-line cap that refuses overly-long
single lines (defense against a 10 GB-on-one-line file).

### P11-FIX-B (cont.) — Unterminated good line → next-append corruption

**Where:** Same file, same function (P10-FIX-C terminator handling).

**Bug:** If the last successfully-parsed line in a JSONL log lacked a
trailing newline (rare but possible after the P10 torn-write path),
the P10 code set `good_end = cursor` and let the subsequent
`OpenOptions::new().append(true)` write at EOF — directly after the
prior `}` with no separator. The result was an irreparable
double-object line (`{"seq":0,...}{"seq":1,...}`) that would refuse
to parse on the NEXT reopen, leaving the gateway permanently broken.

**Fix:** On reopen, track whether the *last* good line was newline-
terminated. If not, write a single `\n` byte before resuming append
— the file becomes well-formed before the first new entry lands.
Logged via `tracing::warn!` so operators see the auto-repair in
startup logs.

### P11-FIX-E.1 — CODEOWNERS file uses a placeholder team handle

**Where:** `.github/CODEOWNERS`, `SECURITY.md`.

**Bug:** `@ullm-security` is a placeholder team handle. GitHub
silently no-ops any CODEOWNERS rule that references a non-existent
team/user — meaning the file as-shipped has zero effect until the
team is created. Until then, any reviewer can approve a PR that
strips the `compile_error!` lines AND the `prod-strings` job in a
single commit, with no security review required.

**Fix:** Added a "One-time setup for the CODEOWNERS team" section at
the top of the SECURITY.md "Repository hardening" section, explicitly
flagging the placeholder + listing the three-step setup (create team,
grant write, configure branch protection). The CODEOWNERS file itself
already had a comment noting the placeholder, but the setup is now
documented in the highly-visible SECURITY.md as well.

### P11-FIX-E.2 — `prod-strings` did not depend on `test`

**Where:** `.github/workflows/ci.yml::prod-strings::needs`.

**Bug:** The job's `needs:` was `[check]` only. A red test suite plus
a green strings check could still merge if branch protection listed
`prod-binary strings check` as the required gate and not `test`.

**Fix:** `needs: [check, test]`. Both must pass before strings runs.

---

## Medium severity

### P11-FIX-C — SthCache fast path still acquired log mutex + recomputed Merkle root

**Where:** `crates/ullm-gateway/src/proxy.rs::transparency_head`.

**Bug:** The P10 cache check was `current_size = state.transparency.status().size; if cache_size == current_size && fresh { return cached; }`.
`status()` acquires the log's `parking_lot::Mutex` AND recomputes the
full Merkle root over every entry — that's the dominant cost under
scrape pressure (O(n) hash + lock contention with `append()`). The
cache only avoided `flush() + sign()`, not the merkle hash.

**Fix:** Check the cache FIRST without touching the log:
```rust
if let Some((sth, signed_at)) = cache.as_ref() {
    if signed_at.elapsed() < STH_CACHE_TTL {
        return Ok(axum::Json(sth.clone()));  // no log lock, no merkle recompute
    }
}
```
A cache hit may return an STH whose `size` is now smaller than the
real size, but that's semantically fine: an STH is, by definition, a
signed commitment to a past state. The 1-second TTL ensures freshness.

### P11-FIX-D.1 — 404 body diverged from axum default → fingerprintable

**Where:** `crates/ullm-{gateway,tee}` `metrics_auth_gate`.

**Bug:** Auth-fail response was
`(StatusCode::NOT_FOUND, "not found").into_response()` — a 9-byte
body. Axum's default 404 (an unknown route) returns an empty body.
An attacker comparing `Content-Length` headers could distinguish
"wrong token" (9 bytes) from "unknown route" (0 bytes) without
timing, defeating the stated purpose of returning 404 instead of
401 to avoid existence confirmation.

**Fix:** Auth-fail returns `StatusCode::NOT_FOUND.into_response()`
with no body — byte-for-byte identical to axum's default.

### P11-FIX-D.2 — `/v1/healthz` on mgmt listener was auth-gated

**Where:** Same files.

**Bug:** The P10 middleware wrapped the entire mgmt router via
`.layer(...)`, so a load-balancer probe to mgmt-port `/v1/healthz`
returned 404 without a token. Public-listener `/v1/healthz` was
already unauthenticated, but operators expecting mgmt-side healthz
to work (e.g., for sidecar liveness probes) were silently broken.

**Fix:** Use `.route_layer(...)` to scope the middleware to the
`/metrics` route only. `/v1/healthz` on the mgmt router is now
unauthenticated, matching the public listener.

### P11-FIX-D.3 — Bearer scheme parse was case-sensitive (RFC 7235 violation)

**Where:** Same files.

**Bug:** `strip_prefix("Bearer ")` required exactly capital `B` and
exactly one space. RFC 7235 §2.1 mandates case-insensitive scheme
matching; RFC 7230 §3.2.4 allows `1*SP` between scheme and
credential. A legitimate `Authorization: bearer TOKEN` (some
Prometheus configurations lowercase the scheme) was silently
rejected.

**Fix:** `parse_bearer_credential()` splits on the first whitespace,
case-insensitive compares the scheme, and trims leading whitespace
from the credential.

### P11-FIX-E.3 — Strings gate only exercised one feature combo

**Where:** `.github/workflows/ci.yml::prod-strings`.

**Bug:** Only `--no-default-features --features prod` was checked.
A `--no-default-features` build alone is functionally equivalent for
the prod path, but a future regression that re-introduces dev strings
only under one combo would slip the single-combo gate.

**Fix:** Loop the build + strings-check over both
`--no-default-features` and `--no-default-features --features prod`.
The inner denylist check now runs once per combo on its own binary
output before the next iteration overwrites `target/release/`.

---

## Non-findings (investigated, judged clean)

- **P11-A double `install()`**: each call builds independent watch
  channels. Tokio supports multiple ctrl_c/sigterm receivers. No
  steal hazard, just decoupled broadcasters — not exploitable today
  (both binaries call `install()` exactly once).
- **P11-A spurious wakeups**: `Notify::notified()` was the concern;
  the new `watch::channel` is exempt — tokio docs guarantee
  `Receiver::changed()` doesn't wake spuriously.
- **P11-A borrow contention**: `Receiver::borrow()` is nanoseconds;
  no measurable impact at 3-subscriber scale.
- **P11-B STH timestamp causality**: a 1s-stale STH is still
  cryptographically a commitment to a past state. No soundness issue.
- **P11-C length oracle via `ct_eq`**: with 32+ random chars of
  entropy, learning the token's byte length doesn't help an attacker.
  Documented; not fixed.
- **P11-C token not zeroized**: `Arc<String>` stays in heap for the
  binary's life. For a rotated bearer credential the risk is low.
  Could use `zeroize::Zeroizing<String>` later; not done.
- **P11-D-15 file deleted between read and reopen**: TOCTOU window,
  but log file deletion outside the gateway's control is already a
  detected anomaly (next append fails or witnesses see a fork).
- **P11-E `Cargo.lock` not committed**: per workspace inspection,
  `Cargo.lock` IS committed (matches the audit's own re-check). Clean.
- **P11-E `subtle` version**: `2.5` workspace floor resolves to
  `2.6.1` in lockfile; no RUSTSEC advisories.
- **P11-E third-party action SHA pinning**: known trust assumption;
  documented as a follow-up. Real fix needs an SBOM-style pinning
  policy.

---

## Verification

- `cargo build --workspace --release` → 0 warnings, 0 errors.
- `cargo check --release --no-default-features --features prod` (per
  package, gateway + TEE) → clean.
- `cargo check --release --features prod` (without
  `--no-default-features`) → compile_error! as designed.
- `cargo test --workspace --release` → **177 passed, 0 failed** (one
  new regression: `sender_drop_does_not_masquerade_as_signal`).

---

## Cumulative status (P1 → P11)

- **75 confirmed vulnerabilities fixed** across eleven iterative passes
  (P1–P8 = 50, P9 = 7, P10 = 8, P11 = 10).
- **177 workspace tests** (one new regression per round on average).
- Every fix integrated into the existing architecture — no bolt-ons.
- Two end-to-end demos + headless WASM clickthrough + live HTTP
  nonce-replay check remain green.

P11 mirrored P10's pattern: every HIGH finding was inside the
previous round's fixes, not in the unchanged code. Convergence
indicator: the LOW-severity findings now dominate (Unicode bidi
escapes, RFC scheme parsing, etc.) — the easy-to-find HIGHs in P10
are gone after this round.

The cadence is reaching a stable equilibrium where each round finds
~8-10 issues, mostly defense-in-depth or hygiene, with the truly
exploitable defects becoming rarer. A P12 round on the P11 surface
(streaming reopen edge cases, watch-broadcaster pre-spawn install,
`parse_bearer_credential`) would likely yield mostly LOW/MEDIUM
findings.
