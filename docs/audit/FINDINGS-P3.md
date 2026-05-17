# Security Hardening Pass — Phase 3 Findings

Third iteration. After Phase 1 (8 findings) and Phase 2 (11 findings),
the surface attack patterns are exhausted, so this pass focused on
**subtle** issues: TOCTOU windows, side-channel oracles, byte-level
coverage of signatures, multi-tenant isolation, memory hygiene, and
HTTP-endpoint authorization.

Six exploration agents covered the surface in parallel. The same triage
discipline as P2 applied: every claim was verified against the actual
source before turning into a code change. Of ~50 leads raised, **11
survived** to become real fixes; the rest are catalogued in the
"non-findings" section so a future audit doesn't waste cycles
re-investigating them.

Verification: **161 workspace tests pass, 0 failures** (up from 158).
Both end-to-end demos and the headless WASM clickthrough are green
against the post-fix backend. Production gateway + TEE builds
(`--no-default-features --features prod`) ship binaries with **zero**
`/v1/devkeys` string references.

---

## High severity

### P3-1 — `REPORT_DATA` byte equality compared in variable time

**Where:** `crates/ullm-attest/src/real_verifier.rs:62/68/87`,
`crates/ullm-attest/src/mock.rs:65`

**Bug:** All three attestation backends checked the 64-byte
channel-binding payload via `evidence.report_data != *expected`, which
the compiler lowers to a short-circuit byte compare. An attacker who
can drive the verifier repeatedly with crafted inputs can binary-search
the expected payload one byte at a time.

**Fix:** New `ct_eq_report_data` helper uses `subtle::ConstantTimeEq`
on the slice form of the array (subtle 2.x doesn't impl it for
`[u8; 64]` directly). All three callers route through it, plus the
mock verifier.

### P3-2 — Attestation freshness window stretched by network latency (TOCTOU)

**Where:** `crates/ullm-client/src/session.rs::connect_with`

**Bug:** `now_unix()` was captured *once* and reused for both the
bundle-freshness check and the ServerHello-evidence freshness check.
Bundle fetch can take hundreds of ms; the handshake adds another
round-trip. The effective TTL was "configured TTL + fetch latency +
handshake latency", giving a slow-network attacker extra room to
replay a near-expiry attestation.

**Fix:** Re-read `now_unix()` immediately before each freshness check
(`now_bundle` for the bundle, `now_handshake` for the ServerHello).

### P3-3 — Gateway's `/v1/devkeys` route always compiled in

**Where:** `crates/ullm-gateway/src/proxy.rs::router`,
`crates/ullm-gateway/Cargo.toml`

**Bug:** Phase 1 gated the TEE-side `/v1/devkeys` behind a `dev-keys`
feature flag. The gateway's `proxy_devkeys` *passthrough* was missed.
A prod-built gateway in front of a prod-built TEE would advertise the
route, hand back a 502, and leak deployment fingerprint.

**Fix:** Mirrored the feature flag: `default = ["dev-keys"]`, `prod = []`.
Route registration + handler are both `#[cfg(feature = "dev-keys")]`.
Verified by `strings | grep -c "/v1/devkeys"` = 0 on the prod gateway
binary.

---

## Medium severity

### P3-4 — Rate-limiter LRU eviction reset full burst to new tenant

**Where:** `crates/ullm-gateway/src/rate_limit.rs::try_charge`

**Bug:** Phase 2's `max_tenants` cap evicts the LRU bucket when a new
tenant arrives at a full table. The new bucket was seeded with the
full `burst_bytes` budget. An attacker rotating through unique tenant
IDs amplified their effective rate by claiming a fresh burst on each
new ID — and could evict legitimate tenants' buckets in the process.

**Fix:** New `last_eviction` tracker. Within `EVICTION_COOLDOWN_SECS`
(60 s) of any eviction, new buckets start at `COLD_BURST_FRACTION`
(1/8) of `burst_bytes` rather than full burst. Legitimate first-time
tenants encountered during quiescent periods still get the full
budget. **Regression test:**
`eviction_pressure_throttles_new_bucket_burst` — saturate the table,
verify the next attacker gets ≤ 12.5 % of burst.

### P3-6 — TEE-side plaintext output buffer not zeroized

**Where:** `crates/ullm-tee/src/service.rs::handle_session`

**Bug:** `output_bytes: Vec<u8>` accumulated the model's plaintext
token stream for the receipt's output digest. After the session
completed the Vec was dropped without wiping its heap, leaving the
plaintext recoverable from a post-mortem heap dump.

**Fix:** Wrapped in `zeroize::Zeroizing<Vec<u8>>`. The plaintext is
public from the client's perspective (every token reaches them), but
the server has no business persisting it past session end —
defense-in-depth against memory-residency / cold-boot attacks.

### P3-7 — `Receipt` fields had lenient `#[serde(default)]` defaults

**Where:** `crates/ullm-receipts/src/lib.rs`

**Bug:** `weight_commit_hex`, `activation_commits_hex`,
`kv_blocks_cloaked`, and `output_digest_hex` were all marked
`#[serde(default)]` for back-compat. A receipt deserialised from a
wire form that omitted these fields silently produced an empty string
or zero — and downstream code had to remember to re-validate.
Forgetting that check (or refactoring it away) becomes a malleability
bug.

**Fix:** Removed `#[serde(default)]` from every Phase-2/3 field. Added
`Receipt::validate_structural()` enforcing the hex shape on the
critical fields, and gated `verify()` on it. The previous lax-shape
foot-gun is now caught at the API boundary. **Regression tests:**
`empty_weight_commit_rejected`,
`malformed_activation_commit_rejected`.

### P3-8 — `kdf::expand` returned a plain `Vec<u8>` of key material

**Where:** `crates/ullm-crypto/src/kdf.rs::expand`

**Bug:** HKDF-Expand's output (chain keys, message keys, nonce salts,
ratchet input keying material) was returned as a plain `Vec<u8>`.
Every caller copied into a fixed-size array, but the original `Vec`'s
heap buffer was dropped without zeroization. A heap residue attack
could recover the expanded key material *before* the wrapping types
zeroize their own copy.

**Fix:** Changed the return type to `zeroize::Zeroizing<Vec<u8>>`.
All call sites compile unchanged (deref to `Vec<u8>` is transparent
for the existing `&out` slice patterns).

### P3-9 — CLI tools followed symlinks supplied as arguments

**Where:** `tools/ullm-watcher/src/main.rs`,
`tools/ullm-log-auditor/src/main.rs`

**Bug:** Both tools called `std::fs::read(path)` directly on
caller-supplied paths. An attacker who can write to a shared scratch
directory plants a symlink (`/tmp/receipt → /etc/passwd`) and tricks
an operator into running `ullm-watcher --receipt /tmp/receipt …` —
the tool reads the targeted file and may log its contents on parse
failure.

**Fix:** New `read_regular_file` helper in each binary stats with
`symlink_metadata`, refuses symlinks + non-regular files, and reads
the literal path only. Applied to every CLI file-input flag
(`--receipt`, `--sth`, `--proof`, `--entry`, `--witness-keyset`).

---

## Low severity

### P3-10 — Attestation signature errors leaked per-step failure cause

**Where:** `crates/ullm-attest/src/signature.rs`
(`verify_tdx_quote_signature`, `verify_snp_report_signature`)

**Bug:** TDX and SNP signature verification returned distinct error
strings for each sub-step ("attestation key parse", "signature decode",
"signature verify"). An attacker probing with crafted inputs learned
exactly which step rejected, narrowing their search.

**Fix:** All sub-step failures now collapse to a single opaque
`"tdx/snp signature verification failed"` message on the wire. Verbose
context still reaches `tracing::debug!` for operator inspection.

### P3-11 — Query-param structs accepted unknown fields silently

**Where:** `crates/ullm-gateway/src/proxy.rs::AttestQuery`,
`ProofQuery`; `crates/ullm-tee/src/service.rs::AttestQuery`

**Bug:** Serde's default lets `Query<AttestQuery>` ignore unknown
query parameters. Future param additions could be silently misnamed
by an attacker without rejection.

**Fix:** Added `#[serde(deny_unknown_fields)]` on all
HTTP-query-param structs.

---

## Non-findings (investigated, judged clean)

These were raised by audit agents but didn't survive code review:

- **ServerHello fields not in signature.** The TEE identity signs only
  `pre_sig_hash` (the ClientHello-only transcript). The agent claimed
  this leaves `server_x25519_pk` + `server_random` ungoverned — but
  `server_x25519_pk` is bound by the attestation issuer's signature
  over `report_data`, and `server_random` only feeds the transcript
  hash used for key derivation. An attacker can't produce a tampered
  ServerHello whose derived root collides with the honest one without
  knowing the hybrid shared secret.
- **Mid-stream key_update WS race.** The TEE service uses a single
  task that sequences `{data frame send → control frame send → adopt
  new ratchet}` atomically — there's no `await` interleaving that
  could split a frame across the key boundary.
- **TenantPool derive-then-insert race.** `state_for` holds the mutex
  across the entire check-derive-insert sequence; a second concurrent
  caller blocks on the lock and observes the inserted state.
- **`/v1/transparency/log` world-readable.** Reading the full log is
  the *whole point* of a transparency log — that's how external
  auditors check consistency. Sigsum and CT operate the same way.
- **Onion-overlay static AEAD nonce.** Already noted in Phase 2: the
  AEAD key is freshly derived per encryption (`HKDF(ephemeral_sk × pk)`),
  so the (key, nonce) pair is unique even with a constant nonce.
- **FROST aggregate not re-verified.** The `frost_ed25519::aggregate`
  function already verifies the result against the group public key
  per the FROST spec.

---

## Verification

- `cargo test --workspace --release` → **161 passed, 0 failed** (up
  from 158 in Phase 2; 3 new regression tests added)
- `ullm-demo` end-to-end → green
- `ullm-phase4-demo` (MPC + multi-vendor + FROST + onion) → green
- Headless WASM clickthrough → 17/17 assertions pass
- `cargo build --release -p ullm-gateway --no-default-features --features prod`
  → succeeds; `/v1/devkeys` string count in the prod gateway binary = **0**
- `cargo build --release -p ullm-tee --no-default-features --features prod`
  → succeeds; `/v1/devkeys` string count in the prod TEE binary = **0**
