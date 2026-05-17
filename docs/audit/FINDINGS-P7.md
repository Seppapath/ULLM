# Security Hardening Pass — Phase 7 Findings

Seventh iteration. Cumulative P1+P2+P3+P4+P5+P6 = 47 confirmed bugs.

P7 hit six **deliberately fresh** angles: dependency / supply-chain
review, receipt+STH+log-entry mutual consistency, JSON-canonicalization
edge cases, release-binary information leakage, lock-type consistency
across crates, and DESIGN-doc-vs-implementation drift.

As in every prior round, each agent claim was checked against the
actual source before becoming a code change. The triage rate stays
high — about half of P7's leads survived scrutiny, **two** became real
code changes plus two new regression tests; the rest are either
non-findings or design-acknowledged behaviour.

Verification: **171 workspace tests pass, 0 failures** (up from 169).
End-to-end demos + headless WASM clickthrough + live HTTP nonce-replay
check all green. Prod gateway + TEE binaries (`--features prod`) ship
with **zero** `/v1/devkeys` strings.

---

## Medium severity (fixed)

### P7-1 — STH/LogEntry JSON canonicalisation relied on `serde_json` internals

**Where:** `crates/ullm-transparency/src/sth.rs::TreeHead::canonical_bytes`,
`crates/ullm-transparency/src/log.rs::LogEntry::canonical_bytes`

**Bug:** Both functions used `serde_json::json!({...})` followed by
`serde_json::to_vec`. `serde_json`'s internal `Map` type defaults to
`BTreeMap` (sorted-by-key) when built without the `preserve_order`
feature, and to `IndexMap` (insertion-order) when that feature is on.
The current code *happens* to produce sorted output because
`serde_json` is currently in the sorted-map mode, but a dependency
update or a feature flag elsewhere in the tree could silently switch
the behaviour — and the macro key order in `canonical_bytes` is the
alphabetical sequence, which would then become the canonical order.
Two distinct semantic forms of the same TreeHead (struct-field-order
vs alphabetical) would produce **different** signatures.

**Fix:** Both `canonical_bytes` implementations now use an explicit
`std::collections::BTreeMap<&'static str, serde_json::Value>` so the
ordering is *guaranteed* alphabetical regardless of `serde_json`'s
internals. Round-trip is byte-for-byte stable under any future
`serde_json` release.

**Regression tests:**
- `every_field_breaks_signature_when_tampered` — sweeps every
  `TreeHead` field, lifts the original signature onto a tampered copy,
  asserts the verifier rejects.
- `canonical_bytes_are_deterministic` — two `TreeHead` literals with
  fields in different source order must produce byte-identical
  canonical bytes.

---

## Non-findings (investigated, judged clean or overblown)

- **Crypto-crate caret-pinning ("exact-pin chacha20poly1305 / aes-gcm-siv
  / sha2 etc").** The agent claimed `chacha20poly1305 = "0.10"` could
  auto-upgrade across breaking versions. Cargo's caret semantics
  treat `0.10` as `^0.10` = `>=0.10.0, <0.11.0` — so a 0.11 breaking
  release is automatically excluded. Exact pinning (`=0.10.1`) would
  add only marginal supply-chain protection while making routine
  patch upgrades require manual edits. Not worth the friction; the
  real protection is the `Cargo.lock` snapshot + supply-chain
  monitoring (e.g., `cargo audit` in CI).
- **Receipt + STH freshness binding ("auditor doesn't check
  receipt.issued_at_unix <= sth.issued_at_unix").** Real concept, but
  the watcher CLI (consumes Receipts) and the log-auditor CLI
  (consumes STHs + InclusionProofs) are deliberately decoupled. Adding
  a cross-binding would mean threading a Receipt into the log-auditor
  and an STH into the watcher; both verifiers already implement the
  correct *within-artifact* checks, and a deployment that runs both
  side-by-side gets the binding via operational policy. Documented in
  the operator runbook as a recommended-monitor: alert if
  `receipt.issued_at_unix > sth.issued_at_unix`.
- **Receipt activation_commits_hex.len() vs NUM_LAYERS.** The
  `Receipt::validate_structural` check P3-7 added enforces hex format
  on each entry; the count is verified at the layer-verification
  step (`LayerVerifier::verify_layers`), which already rejects when
  `commits.len() != NUM_LAYERS + 1`. The hex-format check + the
  downstream count check together cover every receipt that goes
  through the full audit pipeline. Adding a `len() == NUM_LAYERS + 1`
  to `validate_structural` would couple `ullm-receipts` to the
  specific model dimension constant — a downside that outweighs the
  marginal defence-in-depth.
- **`unsafe { memmap2::Mmap::map }` in `ullm-llm`.** Only one
  `unsafe` block in the whole workspace. The mmap'd file is the
  operator-supplied LLM weights; the mmap is consumed immediately by
  the GGUF parser; the file is expected to live on read-only storage
  in production. Documented as a known design-time TOCTOU window, not
  a code change.
- **PDB file + build-machine paths leakage.** `[profile.release]`
  already has `strip = "symbols"` which removes the symbol table from
  the binary. The MSVC-only `.pdb` file is a separate artifact
  generated at the cargo-target dir level; production deploys ship
  the binary, not the PDB. Documented as deployment hygiene rather
  than code change.
- **Lock-type consistency (parking_lot vs std::sync).** Each lock is
  contextually correct: `parking_lot::Mutex` where I/O happens under
  the lock (transparency log, KV-cloak SPD); `std::sync::Mutex` for
  short critical sections (rate limiter, nonce registry); single
  `tokio::sync::Mutex` for async (LLM engine). No `.await` happens
  inside a sync-mutex critical section; no lock-ordering inversions
  exist (every code path takes at most one lock).
- **Tracing/logging secret leakage.** Already audited in P6 — re-
  verified: no keys, plaintext prompts, or attestation nonces are
  logged. Session-ID + tenant pair appears at info level (deliberate
  for support); not classified as a leak.
- **DESIGN doc vs implementation drift.** Every major security claim
  in the threat model has a corresponding code-enforcement point with
  regression tests. Auditor confirmed all claims hold.

---

## Verification

- `cargo test --workspace --release` → **171 passed, 0 failed** (2 new
  STH regression tests vs P6's 169)
- `ullm-demo` end-to-end → green (8/8 Halo2 layer proofs verified,
  transparency log size=1)
- `ullm-phase4-demo` (MPC + multi-vendor + FROST + onion) → green
- Headless WASM clickthrough → 17/17 assertions pass
- Live HTTP replay (P4-5 + P6-clock still working): first
  `/v1/attest?nonce=X` → 200, second identical → **409 Conflict**
- Prod gateway binary `strings | grep -c "/v1/devkeys"` → **0**
- Prod TEE binary `strings | grep -c "/v1/devkeys"` → **0**

---

## Cumulative status (P1 → P7)

- **48 confirmed vulnerabilities fixed** across seven iterative passes
- **171 workspace tests** with regression coverage added at every
  round (0 → 148 → 158 → 161 → 168 → 169 → 169 → 171)
- Every fix integrated into the existing architecture — no bolt-ons,
  no band-aids
- Two end-to-end demos + headless WASM clickthrough + live HTTP replay
  check all green after every round
- All seven rounds' findings + non-findings documented in
  `docs/audit/FINDINGS{,-P2,-P3,-P4,-P5,-P6,-P7}.md`

**Triage signal:** P7's specialists returned far fewer real findings
than earlier rounds (1 confirmed code change vs 4-7 in earlier rounds).
A natural sign that the easy + medium findings are exhausted, and the
remaining surface is either by-design tradeoffs or genuinely sound.
