# Security Hardening Pass — Phase 2 Findings

A second, deeper hardening pass after the Phase 1 fixes landed. Phase 2
launched six parallel exploration agents covering crypto, ZK + attestation,
transparency log, DoS / memory exhaustion, WASM + TLS, and threshold + MPC
+ onion. Each lead was verified by reading the source before turning into
a code change — about half of the agent reports were over-eager and didn't
survive scrutiny; the eleven below did, plus several non-findings that are
documented here so the same paths don't get re-flagged next time.

Verification: **158 workspace tests pass, 0 failures**. Both end-to-end
demos (`ullm-demo`, `ullm-phase4-demo`) and the headless WASM clickthrough
(17 assertions) pass against the post-fix backend.

---

## High severity

### P2-1 — `fp_from_bytes` silently clamped non-canonical inputs

**Where:** `crates/ullm-zk/src/circuit.rs::fp_from_bytes`

**Bug:** When the input encoded a value ≥ `p`, the function cleared the
top two bits and tried again. Two distinct 32-byte inputs mapped to the
same `Fp` — representation malleability on the activation-commit boundary.
A receipt whose `activation_commits_hex` were re-encoded with high bits
flipped would still verify because both encodings clamp to the same field
element.

**Fix:** `fp_from_bytes` now returns `Result<Fp, &'static str>` and rejects
non-canonical inputs outright. Every caller propagates the error.

**Regression test:** `fp_from_bytes_rejects_noncanonical`.

### P2-2 — WebSocket frame size unbounded on gateway and TEE

**Where:** `crates/ullm-gateway/src/proxy.rs::proxy_stream`,
`crates/ullm-tee/src/service.rs::stream`

**Bug:** Neither WS upgrade configured `max_message_size` /
`max_frame_size`. An attacker could announce a multi-gigabyte WS frame
and `tokio-tungstenite` would happily buffer the entire thing before
the handler was even invoked — instant OOM.

**Fix:** Both upgrades now cap inbound at the new
`ullm_core::MAX_WS_MESSAGE_BYTES` constant (256 KB), which leaves room
for the handshake bundle + proof envelopes while killing the
"send a 4 GB frame" DoS.

### P2-3 — Rate limiter map unbounded by tenant cardinality

**Where:** `crates/ullm-gateway/src/rate_limit.rs::RateLimiter`

**Bug:** The per-tenant token-bucket map grew without eviction. Phase-1
sanitisation caps each tenant string at 128 ASCII chars, but the
*number* of distinct tenants was unlimited. An attacker rotating tenant
IDs through ~10^200 possible values fills the heap with bucket entries
that never go away.

**Fix:** Added `RateLimiterConfig.max_tenants` (default 16 K). When the
bucket map hits the cap, inserting a brand-new tenant evicts the LRU
bucket (oldest `last_refill`). Linear scan is fine — eviction only runs
on the cold path, the cap is bounded.

**Regression test:** `bucket_map_bounded_by_max_tenants` — flood 1000
unique tenants, assert the map stays at the cap.

---

## Medium severity

### P2-4 — `InclusionProof::verify` API trap (entry binding optional)

**Where:** `crates/ullm-transparency/src/inclusion.rs::InclusionProof::verify`

**Bug:** `verify(root)` walked the Merkle path from the proof's
attacker-supplied `leaf_hash_hex` up to the root. The caller was expected
to *separately* check that `leaf_hash_hex == leaf_hash(my_entry)` before
trusting the proof. Forget that check (very easy to miss) and the proof
becomes evidence that "some leaf with this hash exists" — useful only
if the verifier knows which entry the leaf belongs to.

**Fix:** `verify(root, expected_entry)` is the new signature. The
function computes `leaf_hash(expected_entry)` internally and refuses to
walk the path unless the proof's claimed leaf hash matches. The
`verify_inclusion_against_head` auditor entry-point grew the same
`expected_entry: &LogEntry` parameter; the CLI auditor (`ullm-log-auditor`)
grew a `--entry` flag.

**Regression tests:**
- `proof_rejected_when_unbound_entry_doesnt_match` — valid proof for
  seq 1 must NOT verify against entry-at-seq-2.
- `size_one_proof_still_requires_entry_binding` — closes the
  "size-1 tree means root == leaf" tautology hole.

### P2-5 — Empty-tree root sentinel collided with valid leaves

**Where:** `crates/ullm-transparency/src/merkle.rs::merkle_root`,
`root_of_leaves`

**Bug:** The empty-log root was hard-coded to `[0u8; 32]`. A 2⁻²⁵⁶ leaf
hash collision would make a size-1 tree indistinguishable from a size-0
tree — small in absolute terms but a structural API leak that became
exploitable in combination with P2-4.

**Fix:** Introduced `empty_root() = SHA256("ULLM-transparency-v1 empty")`,
domain-separated from `LEAF_DOMAIN` / `NODE_DOMAIN`. The constant
cannot collide with any honest leaf or node hash.

**Regression test:** `empty_root_is_domain_separated`.

### P2-6 — STH lacked log-ID binding (cross-log replay)

**Where:** `crates/ullm-transparency/src/sth.rs::TreeHead`,
`crates/ullm-transparency/src/auditor.rs::verify_inclusion_against_head`

**Bug:** The signed payload was `(size, root, issued_at)` only. An STH
from log A could be replayed as evidence for log B if both shared a
logger key — operator key-reuse mistakes turn into "any signed head is
valid for any log".

**Fix:** Added `TreeHead.log_id: String`, bound into the canonical
signature payload. `GatewayState` grew a `log_id` field; the binary's
default sources it from `$ULLM_LOG_ID` (operator-set) or falls back to
the hex-encoded logger public key. `verify_inclusion_against_head`
accepts `expected_log_id: Option<&str>` and rejects with
`AuditError::UnexpectedLogId` on mismatch. The CLI auditor exposes
`--expected-log-id`.

**Regression tests:**
- `tampered_log_id_rejected` — flipping log_id after signing invalidates
  the STH.
- `rejects_log_id_mismatch` — auditor with pinned expected log_id refuses
  an STH for a different log even though the signature checks out.

### P2-7 — `FingerprintVerifier` ignored TLS SNI

**Where:** `crates/ullm-tls/src/lib.rs::FingerprintVerifier`

**Bug:** The verifier checked only the SHA-256 of the leaf cert. The
SNI (the name the client thought it was connecting to) was ignored. A
cert with the right fingerprint, presented for *any* hostname, was
accepted — a misconfiguration that turns one pinned cert into a
universal MITM key.

**Fix:** `FingerprintVerifier` now carries `expected_sans: Vec<String>`
and rejects when the SNI is not in that list. `client_config_pinned`
*requires* the caller to supply the SAN list (so it can't be silently
forgotten); `TlsPinning::pin` and `TlsPinning::pin_multi` are the
convenient wrappers.

**Regression test:** `fingerprint_pin_also_enforces_sni`.

### P2-8 — Self-signed cert had no validity window

**Where:** `crates/ullm-tls/src/lib.rs::SelfSignedCert::generate`

**Bug:** rcgen's `CertificateParams::new` left `not_before` / `not_after`
at whatever the library happened to pick. A leaked dev key was a multi-
year MITM loaded gun even if the operator rotated the key the next day.

**Fix:** `generate` defaults to a 24-hour window via
`generate_with_validity(SANs, Duration)`. Operators who need longer
pass an explicit `validity` (longer-lived prod deploys should use a
real CA via `client_config_with_root` anyway).

### P2-9 — `PreKeyBundle` Vec fields had no structural validation

**Where:** `crates/ullm-handshake/src/messages.rs::PreKeyBundle`

**Bug:** `pq_pk_mlkem: Vec<u8>` and `attestation_evidence: Vec<u8>` had
no length checks at the postcard-decode boundary. With the WS frame
cap (P2-2) the deserialiser can't allocate gigabytes, but it can still
spend cycles + memory on a megabyte-sized garbage bundle before the
signature check catches it.

**Fix:** New `PreKeyBundle::validate_structural()`. Enforces
`pq_pk_mlkem.len() == ML_KEM_768_EK_LEN` (1184 B) and
`attestation_evidence.len() <= MAX_ATTESTATION_EVIDENCE_LEN` (8 KB).
Every wire-decode site (`session.rs::fetch_bundle`, WASM
`ClientSession::start`) calls it before passing the bundle further down.

---

## Low severity

### P2-10 — `FrameFlags::from_bits_retain` accepted undefined bits

**Where:** `crates/ullm-wire/src/codec.rs::read_header`

**Bug:** Bits 12-15 are not defined as flags. `from_bits_retain` kept
them through decode, so any future code that called `flags.bits() & MASK`
without re-masking could be tricked. The AEAD authentication of the
full header already prevents attacker-controlled tampering, so the
practical exploitability is nil — but defense-in-depth.

**Fix:** Switched to `from_bits_truncate` so undefined bits are zeroed
on read.

**Regression test:** `unknown_flag_bits_are_normalized_on_read`.

### P2-11 — WASM `complete()` left session in dead `Replacing` state on error

**Where:** `bindings/ts/src/lib.rs::ClientSession::complete`

**Bug:** Phase 1 introduced the `Replacing` placeholder variant to dodge
a dalek panic. But any error path *inside* `complete()` left the slot
set to `Replacing` permanently — every subsequent `encrypt`/`decrypt`
returned the misleading "session is mid-transition" forever.

**Fix:** Added a `SessionInner::Poisoned(String)` terminal variant.
Every failure inside `complete()` poisons the session with the original
error message, so the user-facing JS gets a clear "session poisoned:
&lt;reason&gt;" and knows to discard the session rather than retry.

---

## Non-findings (investigated, judged clean)

These were flagged by audit agents but didn't survive code-review:

- **Onion AEAD nonce constant.** `crates/ullm-overlay/src/layer.rs` uses a
  fixed 12-byte nonce *with a fresh ephemeral key derived per
  encryption*. AEAD's (key, nonce) uniqueness is satisfied because the
  key is always fresh, not because the nonce is. Defense-in-depth would
  derive the nonce from the ephemeral_pk anyway, but it isn't a bug.
- **`FROST::aggregate` not re-verified.** The wrapper trusts
  `frost_ed25519::aggregate`, which internally checks the aggregate
  signature against the group public key per the FROST spec. Not a bug.
- **`Onion::route` "guard skips middle".** A malicious guard skipping
  the middle hop forwards opaque ciphertext addressed to exit; exit
  decrypts the same payload either way. The crypto guarantee is
  unchanged; the routing-confusion attack is about traffic analysis,
  which is out of scope for the in-memory test relay.
- **Merkle leaf vs internal-node second-preimage.** Already correctly
  domain-separated with `LEAF_DOMAIN` / `NODE_DOMAIN` (RFC-6962 style).
- **Constant-time fingerprint compare.** `constant_eq` in
  `ullm-tls/src/lib.rs` is already a XOR-accumulate loop.
- **Replay-window correctness on epoch transition.** Already fixed in
  Phase 1 (`seen_zero_at_init`).
- **MPC active-security.** The design explicitly assumes
  honest-but-curious; an active-adversary fix is a phase-3 task, not a
  bug.

---

## Verification

- `cargo test --workspace --release` → **158 passed, 0 failed**
  (up from 148 in Phase 1; 10 new regression tests added)
- `ullm-demo` end-to-end → green, 8/8 Halo2 layer proofs verified
- `ullm-phase4-demo` (MPC + multi-vendor + FROST + onion) → green
- `cargo build --release -p ullm-tee --no-default-features --features prod`
  → succeeds; `/v1/devkeys` still compiled out
- Headless WASM clickthrough → all 17 assertions pass
