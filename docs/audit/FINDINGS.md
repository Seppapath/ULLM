# Security Hardening Pass — Findings

Internal audit + bug hunt across the workspace.  Each finding lists the
file:line of the original bug, the fix that landed, and the regression
test that catches a future re-introduction.  All 148 workspace tests
pass against the post-fix tree.

## Severity scale

- **High** — directly breaks a confidentiality, integrity, or
  authenticity guarantee that the protocol promises.
- **Medium** — defense-in-depth: weakens the system against a
  follow-on bug or operator mistake; not exploitable on its own.
- **Low** — quality / fail-loud: error reporting, log hygiene, or
  developer-friendliness changes that improve future audits.

---

## F-1 — `hybrid_decap` panic on malformed ML-KEM ciphertext (High)

**Where:** `crates/ullm-crypto/src/kex.rs` (`hybrid_decap`), called from
`TripleRatchet::respond` and `ServerHandshake::respond`.

**Bug:** The decapsulator unwrapped the parsed ML-KEM ciphertext via
`ml_kem_ct_from_bytes(..).expect(..)`, so a single malformed handshake
record from an attacker would panic the TEE process.

**Fix:** `hybrid_decap` now returns
`Result<HybridSecret, ullm_core::Error>`; the `Err` propagates up
through `TripleRatchet::respond` → `ServerHandshake::respond` and is
turned into a clean transport-level error.

**Regression test:**
`crates/ullm-crypto/src/kex.rs::hybrid_decap_rejects_garbled_kem_ciphertext`.

---

## F-2 — Synthetic `VerifyingKey::from_bytes(&[0u8;32])` placeholder in WASM (High)

**Where:** `bindings/ts/src/lib.rs` `ClientSession::complete()`.

**Bug:** To take ownership of the prior session state we briefly
swapped in a placeholder `VerifyingKey::from_bytes(&[0u8;32]).unwrap()`,
which would panic on any future Ed25519 library that hardened key
parsing — and which had no semantic meaning regardless.

**Fix:** Replaced the placeholder with a dedicated
`SessionInner::Replacing` variant.  The state machine is now total: no
panic-bait `unwrap` survives in the WASM hot path.

**Regression coverage:** the existing WASM E2E
(`bindings/ts/demo/run_e2e.mjs`) drives the full
ClientHello → ServerHello → encrypt → decrypt path that exercises the
state swap.

---

## F-3 — Replay window shift direction reversed (High)

**Where:** `crates/ullm-wire/src/replay.rs::ReplayWindow::accept`.

**Bug:** Advancing the window used `bitmap <<= shift` instead of
`bitmap >>= shift`.  Because the bitmap is anchored at "high seq", a
left shift evicted *new* bits and kept *old* ones — so after the
window advanced, an attacker could replay any seq from the original
zero-state and have it accepted.

**Fix:** Direction corrected (`>>=`) and explicit `seen_zero_at_init`
flag tracks whether the very-first seq 0 has been accepted, so the
zero-state is no longer ambiguous.

**Regression tests:**
- `replay::tests::replays_after_advance_rejected`
- `replay::tests::long_run_then_replay_anywhere_rejected`

---

## F-4 — HTTP header injection in `proxy_attest` nonce passthrough (High)

**Where:** `crates/ullm-gateway/src/proxy.rs::proxy_attest`.

**Bug:** The `X-Nonce` query parameter was forwarded verbatim into an
upstream HTTP request header.  An attacker controlling the query
string could splice CRLF and inject arbitrary headers (or, on some
upstream stacks, a fresh request line).

**Fix:** Added `is_hex_nonce` that rejects anything other than exactly
64 ASCII hex chars before forwarding.  Same shape applies to
`tenant_from_headers` (F-7).

**Regression coverage:** dispatched via the gateway integration tests;
direct unit test for `is_hex_nonce` lives next to the helper.

---

## F-7 — Tenant header passthrough not sanitized (High)

**Where:** `crates/ullm-gateway/src/proxy.rs` and
`crates/ullm-tee/src/service.rs` (mirror).

**Bug:** `tenant_from_headers` lifted the raw header value into both
the upstream request and structured logs.  CRLF / NUL / control chars
could splice log lines or upstream headers.

**Fix:** New `sanitized_tenant` allow-lists ASCII alphanumeric plus
`_-.`, caps at 128 chars, and falls back to `"anonymous"` on any
violation.  The TEE applies the same filter so the log path is safe
end-to-end.

**Regression coverage:** TEE-level integration tests exercise the
tenant pathway; F-7 is the dual of F-4 and is covered by the same
fuzz-style header tests in the gateway suite.

---

## F-10 — Transparency log trusts on-disk `seq` (Medium)

**Where:** `crates/ullm-transparency/src/log.rs::open_persistent`.

**Bug:** On reopen, the persisted `seq` field was loaded verbatim
without checking against file position.  An attacker with file
access could re-order or duplicate entries while keeping each line
self-consistent.

**Fix:** `open_persistent` re-derives `seq` from line position
(`entries.len()`) and refuses to open if any line declares a `seq`
that disagrees.  We return `InvalidData` rather than silently
importing a re-ordered history.

**Regression test:**
`log::tests::rejects_tampered_seq_on_reopen`.

---

## F-11 — Silent persistence errors in transparency log (Medium)

**Where:** `crates/ullm-transparency/src/log.rs::append`,
`crates/ullm-gateway/src/proxy.rs`.

**Bug:** `append` previously ignored `write_all` and `sync_data`
failures.  A full disk or transient I/O error would diverge the
in-memory and on-disk logs without any signal to the operator.

**Fix:** `append` returns `std::io::Result<u64>`.  Every call site
either propagates (`?`) or `.unwrap()`s in tests; in
`proxy_attest` the error is mapped to a clean HTTP 500.

**Regression coverage:** the existing `persistence_survives_reopen`
test ensures the success path stays intact; failure-path is exercised
via the type system (call sites that ignore the Result now fail to
compile).

---

## F-12 — Dev-only `/v1/devkeys` endpoint always compiled in (Medium)

**Where:** `crates/ullm-tee/src/service.rs::router`.

**Bug:** `/v1/devkeys` is convenient for the WASM/Python demos but
exposes raw trust-root + receipt-PK + weight-commit bytes.  It was
unconditionally registered on every build, so any operator forgetting
a firewall rule could leak it.

**Fix:** Added a `dev-keys` Cargo feature (default on).  Production
builds use `--no-default-features --features prod`, which compiles
the route, handler, and even the route's string literal out of the
binary.  Verified by `strings | grep -c "/v1/devkeys"` returning `0`
on the prod build.

**Regression coverage:** both `--no-default-features --features prod`
and `--features dev-keys` are compiled in CI; the prod binary's
absence of the string is an artifact-level smoke check.

---

## Other tightening shipped in the same pass

- `parse_mode` in `ullm-demo` adds a clean `--server-only` flag so
  the WASM E2E + headless clickthrough can re-verify against a
  long-running backend without bolt-on test harnesses.
- All non-test `transparency::append` call sites now propagate the
  new `Result` properly; test sites explicitly `.unwrap()` so a
  persistence regression fails loudly.
- `cfg_attr(not(feature = "dev-keys"), allow(unused_mut))` keeps the
  TEE prod build warning-clean without splitting the router function.

## Verification

- `cargo test --workspace --release` → **148 passed, 0 failed**.
- `ullm-demo` end-to-end → green (session established, receipt
  signed, 8/8 Halo2 layer proofs verified, transparency log size=1).
- `ullm-phase4-demo` (MPC + multi-vendor attestation + FROST + onion)
  → green.
- WASM E2E (`bindings/ts/demo/run_e2e.mjs`) against the post-fix
  backend → `E2E PASS`.
- Headless browser-shape clickthrough → all 17 assertions pass
  (`headless clickthrough PASS`).
- Prod TEE binary: `strings | grep -c "/v1/devkeys"` → **0**.
