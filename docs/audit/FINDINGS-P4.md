# Security Hardening Pass — Phase 4 Findings

Fourth iteration. Cumulative findings across P1+P2+P3 = 30. This pass
went after the residual subtleties that survive when the surface-level
issues are gone: cryptographic domain separation, negotiated-but-
unimplemented algorithm branches, attestation-nonce replay, TOCTOU on
freshness, and the gateway's status-code propagation.

Six exploration agents covered: state-machine confusion, key separation
+ forward secrecy, ratchet desync, cipher-suite negotiation, postcard
canonicalisation, and Phase-4 component isolation. As before, every
claim was checked against the actual source before becoming a code
change. Of ~30 leads raised, **7 confirmed**; another agent claim
(gateway HTTP-status propagation, P4-12 below) was caught only because
P4-5's live verification failed. The rest are documented as
non-findings.

Verification: **168 workspace tests pass, 0 failures** (up from 161).
Both end-to-end demos, the headless WASM clickthrough, and an explicit
HTTP curl-against-the-live-backend nonce-replay check (P4-5 returns
**409 Conflict** on the second attempt) are green. Production gateway,
TEE, and threshold binaries (`--no-default-features --features prod`)
build cleanly and ship with **zero** `/v1/devkeys` string references in
both gateway and TEE.

---

## High severity

### P4-1 — TEE identity key signed two contexts without domain separation

**Where:** `crates/ullm-tee/src/identity.rs::build_bundle`,
`crates/ullm-tee/src/service.rs::handle_session` (callback),
verifiers in `crates/ullm-client/src/attest_check.rs` and
`bindings/ts/src/lib.rs`

**Bug:** The TEE's long-lived `id_sk` (Ed25519) signed both the
PreKeyBundle concatenation (`id_pk || spk_pk || pq_pk || evidence`,
~1.3 KB) and the handshake's `pre_sig_hash` (32 bytes). With no
domain-separation prefix on either, a signature produced for one
context is in principle a valid signature for the other — the
probability of a useful collision is small (~2⁻²⁵⁶ per attempt) but
non-zero, and the lack of separation is a textbook hygiene gap.

**Fix:** New constants `SIG_DOMAIN_BUNDLE = b"ULLM-v1 bundle-sig\0"`
and `SIG_DOMAIN_HANDSHAKE = b"ULLM-v1 handshake-sig\0"` exported from
`ullm-handshake`. Both signers prepend the relevant prefix; both
verifiers (native + WASM) do the same. Mismatch → verify fails.

### P4-3 + P4-4 — Cipher-suite negotiation was a silent no-op

**Where:** `crates/ullm-core/src/version.rs::AeadId`,
`crates/ullm-handshake/src/messages.rs::CipherSuite::validate`

**Bug:** `AeadId::Aes256GcmSiv = 0x02` was a defined variant and
`validate()` accepted it, but the record-layer codec hardcoded
XChaCha20-Poly1305. A peer advertising 0x02 passed validation, both
sides hardcoded XChaCha, and the "negotiated cipher suite" was a
wire-level lie. ServerHello didn't echo a chosen suite, so there was
no way for either side to detect a downgrade.

**Fix:** `CipherSuite::validate()` now explicitly rejects every
algorithm whose record-layer dispatch isn't implemented. Currently
that means only `(KemId::X25519MlKem768, AeadId::XChaCha20Poly1305,
HashId::Sha256)` passes. Future protocol versions implementing
`Aes256GcmSiv` or `Sha384` lift the gate. **Regression tests:**
`rejects_unimplemented_aead_aes_gcm_siv`, `rejects_unknown_aead_byte`,
`rejects_unknown_hash_byte`, `rejects_known_but_unimplemented_hash`.

### P4-12 — Gateway dropped upstream HTTP status (caught by P4-5 live verify)

**Where:** `crates/ullm-gateway/src/proxy.rs::http_get_passthrough`,
both call sites (`proxy_devkeys`, `proxy_attest`)

**Bug:** The custom HTTP/1.1 GET helper returned only the response
body, throwing the status line on the floor. The gateway then wrapped
the body in a 200 response regardless of what the TEE actually
returned. This was a latent bug *and* it silently defeated the P4-5
nonce-replay defense: the TEE's 409 Conflict became a 200 with the
error string in the body, and the WASM/Python clients happily tried
to parse the error string as a bundle.

**Fix:** `http_get_passthrough` now returns `(StatusCode, Vec<u8>)`.
Callers propagate non-success status codes by returning them
unchanged. Caught at the eleventh hour by the explicit curl-replay
check after P4-5 landed — a strong argument for live verification
beyond unit tests.

---

## Medium severity

### P4-2 — `CipherSuite.hash` field never validated

Folded into P4-3+P4-4 above. The `hash` byte was previously unchecked;
now it must be `HashId::Sha256` (the only one Phase 1 implements).

### P4-5 — Attestation nonce reuse not server-side checked

**Where:** `crates/ullm-tee/src/service.rs::attest`, new module
`crates/ullm-tee/src/nonce_registry.rs`

**Bug:** The TEE's `/v1/attest` endpoint accepted any 32-byte nonce
and issued fresh evidence. An attacker who captured a nonce from
session A could replay it to a *different* TEE instance and obtain
identically-shaped attestation evidence — a cross-instance identity-
linkage oracle and a re-cache-of-evidence amplification path.

**Fix:** New `NonceRegistry` module (per-TEE, TTL-bounded, capped at
128 K entries with LRU eviction beyond cap). Wired into `AppState`
and called from the `attest` handler. Replays within
`NONCE_TTL_DEFAULT_SEC` return HTTP 409 Conflict.

**Live verification:** `curl -k https://gateway/v1/attest?nonce=…`
twice — first returns 200, second returns 409.

### P4-8 — Client hangs on dropped END_OF_TURN / receipt envelope

**Where:** `crates/ullm-client/src/session.rs::read_binary`

**Bug:** `read_binary` awaited `ws.next()` with no timeout. A
malicious gateway keeping the WS alive without forwarding the
END_OF_TURN frame caused `next_token()` to loop forever; same trap
for `finalize()`'s wait on the receipt envelope.

**Fix:** Added a 60 s `WS_READ_TIMEOUT` wrapped around the
`ws.next()` call via `tokio::time::timeout`. A stalled peer surfaces
as `Error::Transport("ws idle for 60s …")` rather than a hung
process.

### P4-10 — FROST trusted-dealer DKG not gated for production

**Where:** `crates/ullm-threshold/src/dkg.rs`,
`crates/ullm-threshold/Cargo.toml`

**Bug:** `distribute()` ran the trusted-dealer DKG unconditionally.
The dealer is a single point of failure: a compromised dealer
trivially learns the master secret. Suitable for tests + demos, not
production — but the API made it look like the canonical path.

**Fix:** Renamed to `distribute_with_trusted_dealer` (explicit
naming). Gated behind a `trusted-dealer` Cargo feature (default ON
for tests/demos). Production builds via `--no-default-features`
compile the function out entirely. The old `distribute` name is
retained as a deprecated alias under the same feature.

---

## Non-findings (investigated, judged clean)

- **Seq-jump ratchet fast-forward DoS.** Agent claimed seq=999_999
  would force the receiver to advance the chain 999_999 times. The
  actual code calls `next_key()` once per received frame; the AEAD
  with `nonce = derive(epoch, 999_999)` against `K1` immediately
  fails the tag check and the receiver returns `Error::Decrypt`. No
  CPU DoS path.
- **Out-of-order receive losing keys.** The chain is strictly
  ordered; out-of-order WS frames decrypt to wrong keys and fail.
  But WebSocket-over-TLS-over-TCP is reliably in-order, and a
  malicious WS gateway reordering frames just causes DoS (not key
  leakage). Treated as documented design constraint, not a bug.
- **Receipt signer key cross-context reuse.** Verified: receipt
  signing key is a distinct `SigningKey` generated independently of
  `id_sk`, used only for `Receipt`-shaped payloads.
- **FROST nonce reuse.** Per-call `BTreeMap` of nonces; dropped on
  function return; no persistent storage; per the FROST spec the
  crate handles internal zeroization.
- **MPC share leakage.** Reconstruction is additive `mod p`; party
  observing only their share learns nothing structurally. Honest-
  but-curious threat model is documented.
- **Onion overlay AAD per-layer.** Each layer has a fresh ephemeral
  X25519 key → fresh shared secret → fresh AEAD key, so the static
  nonce is fine. Already noted in P2.
- **Phase4-demo cross-scenario state.** Each scenario in
  `tools/ullm-phase4-demo/src/main.rs::main` is fully local — no
  shared `static` state.

---

## Verification

- `cargo test --workspace --release` → **168 passed, 0 failed** (7
  new regression tests vs Phase 3)
- `ullm-demo` end-to-end → green
- `ullm-phase4-demo` (MPC + multi-vendor + FROST + onion) → green
- Headless WASM clickthrough → all 17 assertions pass
- Live HTTP replay check: first `/v1/attest?nonce=X` → 200, second
  identical request → **409 Conflict** (P4-5)
- `cargo build --release -p ullm-gateway --no-default-features --features prod`
  → succeeds; `/v1/devkeys` count = **0**
- `cargo build --release -p ullm-tee --no-default-features --features prod`
  → succeeds; `/v1/devkeys` count = **0**
- `cargo build --release -p ullm-threshold --no-default-features`
  → succeeds with `distribute_with_trusted_dealer` compiled out
