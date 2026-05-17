# Security Hardening Pass — Phase 12 Findings

Twelfth iteration. Five specialists with **tighter** scope this round
since the curve was flattening (P9: 7, P10: 8, P11: 10 — but mostly
LOW). The goal was to push harder on adversarial inputs and find
HIGHs if they still existed.

**Result: 3 HIGH, 6 MEDIUM, handful LOW.** Two of the HIGHs were
**not** in P11 code — they were pre-existing defects the specialists
flagged while in the neighborhood:

1. `Cargo.lock` was `.gitignore`'d the whole time. Every previous CI
   run resolved fresh, so `cargo audit` could never catch a
   supply-chain attack via point release. P10/P11 audits both
   *assumed* the lockfile was committed; nobody verified.
2. `ullm-gateway/src/session_token.rs::subtle_compare` is a
   hand-rolled `diff |= x ^ y` loop with **no `black_box` fence**.
   Under our `lto = "fat"` + `codegen-units = 1` release profile,
   LLVM could legally vectorize this into an early-exit on the first
   non-zero lane, turning the session-token HMAC check into a timing
   oracle. It's been there since Phase 1.

The third HIGH is in P11 code: leading UTF-8 BOM makes the log file
unopenable.

All findings fixed. Workspace tests: **178 passing, 0 failing** (+1
new BOM regression test).

---

## High severity

### P12-FIX-A — `Cargo.lock` was excluded from version control

**Where:** `.gitignore:2` listed `Cargo.lock`.

**Bug:** A workspace that produces binary artifacts (ullm-gateway,
ullm-tee) **must** commit its lockfile — otherwise every CI run
resolves transitive deps fresh, and a malicious upstream point release
can land between `cargo update` runs without anyone noticing.
`cargo audit` in CI runs against the resolved-at-build-time lockfile,
not a committed one, so a downgrade or backdoor in any of the 200+
transitive deps would be silently accepted.

CODEOWNERS protected `Cargo.lock` (good intent), but the file wasn't
in the tree, so the rule applied to nothing.

P10 + P11 audits both assumed the lockfile was committed without
verifying. The P12-E specialist actually checked.

**Fix:** Remove the `Cargo.lock` line from `.gitignore`. The current
lockfile (with `subtle 2.6.1` and 200+ other resolved deps) is now
tracked. Workspace `subtle = "2.5"` floor is pinned to `=2.6.1` so
bumps go through CODEOWNERS review.

### P12-FIX-B — `subtle_compare` in `session_token.rs` was not constant-time under fat LTO

**Where:** `crates/ullm-gateway/src/session_token.rs::subtle_compare`
(pre-P12; removed).

**Bug:** The MAC tag check on session tokens used a hand-rolled
constant-time compare:
```rust
let mut diff: u8 = 0;
for (x, y) in a.iter().zip(b.iter()) {
    diff |= x ^ y;
}
diff == 0
```
No `black_box` / `read_volatile` fence. Under `lto = "fat"` +
`codegen-units = 1`, LLVM has whole-program visibility and can
recognize that the OR-accumulator-then-compare-to-zero pattern is
equivalent to "any nonzero byte → return false" — and emit a SIMD
vectorized loop that short-circuits on the first non-zero lane.
Result: a timing oracle on the HMAC tag bytes, exploitable across
many requests to recover the session-token signing key.

The function name "subtle_compare" was actively misleading — readers
would assume it used the `subtle` crate.

**Fix:** Replace the body with `subtle::ConstantTimeEq::ct_eq` from
the (already-workspace-dep'd) `subtle` crate. `subtle` uses
`core::hint::black_box` internally to fence the optimizer, and its
constant-time guarantees explicitly survive fat LTO.

### P12-FIX-C.1 — Leading UTF-8 BOM made log file unopenable

**Where:** `crates/ullm-transparency/src/log.rs::open_persistent`
(P11-FIX-B streaming reopen).

**Bug:** A log file accidentally re-saved through a BOM-adding editor
(PowerShell `Out-File` default, Notepad "UTF-8 with signature") has
a leading 3-byte `\xef\xbb\xbf`. The P11 streaming reopen passed
those bytes to `serde_json::from_str` which correctly rejected them
— and the gateway then refused to start. An operator using Notepad
to peek at a log file once would brick the deployment.

**Fix:** Strip a leading BOM on reopen via `BufReader::fill_buf` +
`consume(3)`. Logged via `tracing::info!` so operators see the
auto-repair in startup logs. Regression test
`reopen_strips_leading_utf8_bom` pre-prepends a BOM and verifies
reopen succeeds with the entry count intact.

---

## Medium severity

### P12-FIX-C.2 — Off-by-one on `MAX_REOPEN_LINE_BYTES`

**Where:** Same file as FIX-C.1.

**Bug:** `reader.by_ref().take(MAX + 1).read_until(b'\n', ...)` then
`if read > MAX`. A legitimate line of exactly `MAX_REOPEN_LINE_BYTES`
content bytes plus a trailing `\n` reads `MAX + 1` total bytes. The
check fires → rejected as overlong. The doc comment said "per-line
bytes" without specifying whether the newline counts.

**Fix:** Cap the underlying reader at `MAX + 2` and reject only when
`read > MAX + 1` (content + newline). Comment now documents the
inclusion of the newline byte.

### P12-FIX-D — JSON-depth defense-in-depth on log reopen

**Where:** Same file.

**Bug (status downgrade — original audit was wrong):** P12-E claimed
serde_json had no recursion limit and a deeply-nested input would
stack-overflow. Verification in the resolved `serde_json 1.0.149`
source showed `remaining_depth: u8 = 128` is the default — depth
bombs return `Err(RecursionLimitExceeded)`, not stack-overflow.
However: 128 is high relative to `LogEntry`'s actual structure
(flat: object → array of hex strings, depth ≤ 4 in legitimate use).

**Fix:** Pre-scan each log line for unmatched `{`/`[` brackets and
reject anything with depth > 32 before handing it to serde_json. The
scanner tracks JSON string boundaries (skipping bracket characters
inside string values) and escapes. Defense-in-depth against future
deserializer changes; doesn't depend on serde_json internals.

### P12-FIX-E.1 — Windows broadcaster path used async error reporting

**Where:** `crates/ullm-core/src/shutdown.rs::install`.

**Bug:** The P11-FIX-A pre-spawn install pattern worked symmetrically
on Unix (both `signal(SignalKind::interrupt())?` and
`signal(SignalKind::terminate())?` return `io::Result` synchronously)
but the Windows path constructed `tokio::signal::ctrl_c()` eagerly
without checking for install failure — any error surfaced inside the
spawned task as a `tracing::warn!`, and the broadcaster never fired.
Caller saw `Ok(Self)` with a silently-dead handler.

**Fix:** Use `tokio::signal::windows::ctrl_c()?` which returns
`io::Result<CtrlC>` synchronously. Error propagates out of
`install()` matching the Unix branch. Doc-comment updated to note
the runtime-context requirement (must be inside `#[tokio::main]` or
`Runtime::block_on`).

### P12-FIX-E.2 — `install()` runtime-context requirement undocumented

**Where:** Same function.

**Bug:** `install()` is not `async` but requires a tokio runtime
context (calls `tokio::spawn` internally, and on Windows the
`signal::windows::ctrl_c()` constructor needs the runtime handle).
Callers using sync `fn main()` would hit a panic inside `tokio::spawn`
with no clear error message.

**Fix:** Doc-comment at the top of `install()` explicitly states
"MUST be called from within a tokio runtime context. Both
`#[tokio::main]` and `Runtime::block_on(...)` provide one."

### P12-FIX-A.cont — `subtle` version is now exact-pinned

**Where:** `Cargo.toml::subtle`.

Was `subtle = "2.5"` (caret-pin, allows 2.7+). Now `subtle = "=2.6.1"`
matching the lockfile. Future bumps go through CODEOWNERS review.

---

## Non-findings (investigated, judged clean)

### P12-D — `route_layer` HTTP-method dispatch is correct

The specialist did a careful read of axum 0.7.9's `method_routing.rs`
and confirmed:
- `MethodRouter::route_layer` applies the wrapping layer to **every**
  method endpoint slot (including the auto-derived HEAD-via-GET path).
- HEAD `/metrics` runs through the auth middleware before the GET
  handler — `is_head` strips the body AFTER the layered service
  returns, on auth-fail the response is empty anyway, on auth-success
  the body is built and stripped (perf cost only, no leak).
- Non-GET/HEAD methods 405 via the un-layered `fallback`.
- Path normalization (`/Metrics`, `//metrics`, `/metrics/`) does NOT
  match the case-sensitive byte-literal route.

No HEAD bypass. No method-override bypass. No path-normalization bypass.
Clean.

### P12-B / P12-C non-findings

- Windows-deploy gaps (`CTRL_CLOSE_EVENT` not handled): real but
  OPERATIONS.md is Linux/systemd-only. Documented in the rustdoc, not
  fixed.
- Bearer parser strict-rejection of trailing whitespace + NBSP
  separators: spec-correct (RFC 7235 + RFC 6750 token68). Operator
  doc-only nit.
- Length oracle via `ct_eq` length mismatch: 32+ random char tokens
  make this uninteresting in practice.

### P12-E — Other supply-chain items

- `serde_json` recursion limit is 128 by default — already protects
  against stack-overflow depth bombs. The P12-FIX-D depth-32 pre-scan
  is defense-in-depth, not a fix for an actual bug.
- `panic = "abort"` skips `TransparencyLog::Drop` fsync. Documented in
  P11-FIX-B already.
- `cargo install --locked cargo-audit` + run-time advisory-db fetch:
  trust assumption acceptable, follow-up for SBOM-style pinning.

---

## Verification

- `cargo build --workspace --release` → 0 warnings, 0 errors.
- `cargo check --release -p ullm-gateway -p ullm-tee --no-default-features --features prod`
  → clean.
- `cargo check --release --features prod` (without `--no-default-features`)
  → compile_error! as designed.
- `cargo test --workspace --release` → **178 passed, 0 failed** (+1
  regression: `reopen_strips_leading_utf8_bom`).

---

## Cumulative status (P1 → P12)

- **84 confirmed vulnerabilities fixed** across twelve passes
  (P1–P8 = 50, P9 = 7, P10 = 8, P11 = 10, P12 = 9).
- **178 workspace tests**.
- Every fix integrated into the existing architecture — no bolt-ons.
- Demos, headless WASM, live HTTP nonce-replay all green.

### Convergence note

P12 found 3 HIGHs but two of them were **pre-existing** defects
(Cargo.lock, hand-rolled `subtle_compare`) caught while specialists
were doing supply-chain + LTO analysis nearby. The actual rate of
HIGHs in the latest fix-pass surface (P11) was 1 (BOM corruption).
The trend toward LOW-severity findings is real; finding pre-existing
HIGHs gets harder as audit rounds deepen but it isn't zero.

The Cargo.lock miss is the kind of finding that would have been
caught by a simple `ls Cargo.lock | git check-ignore` check earlier
in the audit cadence — worth adding to a P13+ "deployment-readiness
sanity check" specialist.

Per the /goal: **the system is converging toward clean but not yet
clean**. A P13 round would likely find 2-4 LOWs in the P12 fix
surface (BOM-strip edge cases, depth-pre-scan UTF-8 quirks,
exact-pin drift if Dependabot lands). The next high-leverage move
beyond more audit rounds is the external-audit refresh.
