# Security Hardening Pass — Phase 6 Findings

Sixth iteration. Cumulative P1+P2+P3+P4+P5 = 43 confirmed bugs. P6
launched six new specialists, **deliberately picking angles that hadn't
been the primary focus before**: `unsafe`+FFI audit, tracing/logging
secret leakage, Cargo features matrix, time/clock-skew robustness,
`unwrap`/`panic!` reachability, and HTML-demo browser-side security.

Verification: **169 workspace tests pass, 0 failures**. End-to-end
demos + headless WASM clickthrough + live HTTP nonce-replay check all
green. Prod gateway + TEE binaries (`--features prod`) ship with
**zero** `/v1/devkeys` strings.

---

## High severity

### P6-1 — Wall-clock `unwrap_or(0)` opened a freshness-check bypass

**Where:** `crates/ullm-client/src/session.rs::now_unix`,
`crates/ullm-tee/src/service.rs` (both `attest` and `handle_session`),
`crates/ullm-gateway/src/proxy.rs` (transparency append),
new `crates/ullm-core/src/clock.rs`

**Bug:** Every wall-clock read followed the pattern

```rust
SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
```

`duration_since(UNIX_EPOCH)` returns `Err` whenever the system clock is
set before 1970-01-01 — an attacker-influenceable scenario in
containers, VMs, or anywhere NTP can be poisoned. The fallback
substitutes `0`, and downstream freshness checks of the form
`now.saturating_sub(issued_at) > TTL` then collapse to `0`, so every
stale attestation looks eternally fresh. **Real freshness-defense
bypass when the attacker controls the clock**.

**Fix:** New `ullm_core::clock` module:
- `now_unix() -> Result<u64>` — fails closed on a pre-1970 clock; used on
  every security-critical freshness or log-timestamp path (`session::connect_with`,
  TEE `attest`, TEE `handle_session`, gateway transparency log
  append).
- `now_unix_or_zero() -> u64` — keeps the old behaviour but explicitly
  named "non-security metadata only"; used only by the gateway's
  `transparency_head` heartbeat endpoint (the STH's
  `issued_at_unix` is informational; the signature doesn't depend on
  the timestamp value).

Every previous call site was reviewed and routed through the
appropriate helper.

---

## Medium severity

### P6-2 — Demo lacked `Content-Security-Policy`

**Where:** `bindings/ts/demo/serve.mjs`

**Bug:** The static demo server returned `text/html` without a CSP,
leaving any future XSS sink with no defense-in-depth.

**Fix:** Added an explicit CSP plus `X-Content-Type-Options: nosniff`
and `Referrer-Policy: no-referrer` on every response:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src  'self' 'unsafe-inline';
connect-src 'self' https: wss:;
object-src 'none';
base-uri 'self';
form-action 'self';
frame-ancestors 'none'
```

`wasm-unsafe-eval` is necessary for `WebAssembly.instantiate`;
`connect-src https: wss:` permits the user-supplied gateway URL.

### P6-3 — Demo accepted arbitrary gateway URL (incl. `javascript:`/`data:`)

**Where:** `bindings/ts/demo/index.html` (`run()` handler)

**Bug:** The gateway-URL field was used verbatim in `fetch()` and
`new WebSocket(...)`. A user pasting `javascript:alert(...)` or a
malicious URL would cause unpredictable behaviour. Combined with the
missing CSP this widened the attack surface for clipboard-injection
phishing.

**Fix:** The `run()` handler now parses the URL via `new URL(...)` and
rejects anything other than `https://` (or `http://localhost` for the
dev path). Failure mode is a clear log message in the demo's output
panel.

### P6-4 — `hexDecode` could OOM the tab on a giant pasted string

**Where:** `bindings/ts/demo/index.html` (`hexDecode` helper)

**Bug:** `s.match(/.{1,2}/g)` on a 100MB string allocates a 50M-entry
array before any length check fires. The browser tab can lock up or
crash before the user sees the actual validation error.

**Fix:** `hexDecode` now enforces a `HEX_INPUT_CAP` of 2048 chars (≈ 30×
larger than any legitimate input), a strict `^[0-9a-fA-F]*$` regex,
and even-length parity before decoding into a fixed-size `Uint8Array`
via byte-pair iteration.

---

## Non-findings (investigated, judged clean)

- **`unsafe` audit.** Only one `unsafe` block exists in the workspace:
  `memmap2::Mmap::map(&weights)` in `ullm-llm/src/real.rs`. The
  weights file is operator-supplied (not attacker-controlled), and
  the mmap is consumed immediately by the GGUF parser. Documented as
  a known design-time TOCTOU window; production deployments are
  expected to ship the weights file on read-only storage.
- **wasm-bindgen FFI boundary.** Every `#[wasm_bindgen]` export
  validates `&[u8]` length before structural use (P1-2, P2-9, etc.
  closed all the obvious holes). `getrandom = { features = ["js"] }`
  is the correct WASM RNG wiring. No `unsafe impl Send/Sync`, no
  manual `transmute`, no raw pointers.
- **pyo3 FFI boundary.** `block_on` correctly releases the GIL during
  async work; no Python object references cross the async boundary.
- **Tracing/logging.** Every `tracing::*` call site reviewed. No keys,
  plaintext prompts, or attestation nonces are logged. The two debug-
  level error-context calls in `signature.rs` carry only the
  crypto-library's generic error display; both are below the default
  `info` filter. Session-ID + tenant pairs appear at info level — a
  *correlation* leak, but not a confidentiality break, and the
  tracing config is dev-default.
- **Cargo features matrix.** `cargo build --no-default-features` works
  on every binary crate. `phase4_combined` test imports
  `distribute_with_trusted_dealer` which is feature-gated; the test
  itself compiles cleanly with default features (the intended path).
- **`unwrap`/`expect`/`panic!` hunt.** Zero reachable-on-attacker-input
  panics in production code. Every remaining `.expect()` is either
  provably infallible (HKDF within budget, AEAD with fixed-length
  key, deterministic AES-GCM-SIV) or guards an internal-state
  invariant (mutex poison, postcondition check after explicit `Ok`).
- **HTML demo XSS sinks.** Every DOM write uses `textContent` /
  `setAttribute`; no `innerHTML`, no `document.write`. The CSP added
  in P6-2 is pure defense-in-depth.
- **Symlink protection in `serve.mjs`.** Already correct via
  `path.normalize` + `.startsWith(root)`.

---

## Verification

- `cargo test --workspace --release` → **169 passed, 0 failed**
- `ullm-demo` end-to-end → green
- `ullm-phase4-demo` (MPC + multi-vendor + FROST + onion) → green
- Headless WASM clickthrough → 17/17 assertions pass
- Live HTTP replay (P4-5 still working): first `/v1/attest?nonce=X` →
  200, second → **409 Conflict**
- Prod gateway binary `strings | grep -c "/v1/devkeys"` → **0**
- Prod TEE binary `strings | grep -c "/v1/devkeys"` → **0**
- Prod threshold build (`--no-default-features`) → succeeds with
  `distribute_with_trusted_dealer` compiled out

---

## Cumulative status (P1 → P6)

- **47 confirmed vulnerabilities fixed** across six iterative passes
- **169 workspace tests** with new regression tests at every round
- Every fix integrated into the existing architecture — no bolt-ons,
  no band-aids
- Both end-to-end demos, headless WASM clickthrough, and live HTTP
  replay check all green after every round
- All six rounds' findings + non-findings documented in
  `docs/audit/FINDINGS{,-P2,-P3,-P4,-P5,-P6}.md`
