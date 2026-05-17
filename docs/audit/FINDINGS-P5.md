# Security Hardening Pass — Phase 5 Findings

Fifth iteration. Cumulative P1+P2+P3+P4 = 38 confirmed bugs. This pass
launched six new specialists with deliberately different angles:
hand-crafted adversarial parser inputs, network-malice probing,
cryptographic primitives vs spec, audit-tool semantic correctness, API
misuse / public-surface ergonomics, and test-coverage holes.

As in previous rounds, every agent claim was verified against the
actual source before becoming a code change. Of ~30 leads raised, **5
survived** triage; the rest are catalogued as non-findings.

Verification: **169 workspace tests pass, 0 failures** (up from 168).
Both end-to-end demos, headless WASM clickthrough, and live HTTP
replay check are green. Prod gateway + TEE binaries (`--features prod`)
build cleanly with **zero** `/v1/devkeys` string references.

---

## Medium severity

### P5-1 — ECDSA P-256 / P-384 signature malleability (low-s not enforced)

**Where:** `crates/ullm-attest/src/signature.rs::verify_tdx_quote_signature`
(P-256), `verify_snp_report_signature` (P-384)

**Bug:** Both verifiers called `Signature::from_slice(...)` followed by
`vk.verify(body, &sig)`. ECDSA admits two valid encodings per
signature — `(r, s)` and `(r, n − s)` — and neither `p256` nor `p384`
normalises `s` before verifying. An attacker who captures a legitimate
attestation signature can re-encode it with high-s and the verifier
accepts the rewritten form. Defeats any downstream dedup keyed on
signature bytes.

**Fix:** Inserted `let sig = sig.normalize_s().unwrap_or(sig);` between
parse and verify. Both encodings now canonicalize to the same low-s
form before verification.

### P5-2 — Server-side WS write had no timeout (slow-client hang)

**Where:** `crates/ullm-tee/src/service.rs` (every `sender.send(...).await?`
site)

**Bug:** P4-8 added a *read* timeout on the client side. The
corresponding server-side path had no *write* timeout — a slow or
malicious peer could keep the TCP connection alive at 1 byte/sec and
block the server's `sender.send(...).await` indefinitely, pinning the
session slot.

**Fix:** New `send_ws()` helper wraps every WS send in
`tokio::time::timeout(WS_SEND_TIMEOUT, ...)`. 60 s ceiling matches the
client-side `WS_READ_TIMEOUT`; on expiry the session returns a clean
"peer not draining" error and the slot is released.

### P5-3 — Orphaned inference task on streaming-loop early exit

**Where:** `crates/ullm-tee/src/service.rs` (around the inference
`tokio::spawn`)

**Bug:** `handle_session` spawns `engine.run(prompt, tok_tx)` as a
background task and awaits it after the streaming loop completes. Any
`?` propagation from a WS send error (or the new P5-2 timeout) skips
the await — leaving the inference task running orphaned until the LLM
naturally completes (or forever, depending on the engine).

**Fix:** New `InferenceTaskGuard` (RAII): wraps the `JoinHandle`,
aborts on `Drop`. The success path calls `guard.finish().await` to let
the task drain; every error path drops the guard, triggering `abort()`
on the spawned task.

### P5-6 — Watcher CLI panicked on malformed input

**Where:** `tools/ullm-watcher/src/main.rs`

**Bug:** The CLI documented exit code 2 for parse failures but used
`.expect("seed hex")` / `.expect("tee-pk hex")` / `.expect("decode
receipt")` throughout argument parsing. A typo'd hex value produced
a panic (SIGABRT, no exit code) instead of the contractual 2.

**Fix:** New `bail2(msg)` helper + `parse_hex32(flag, v)` that produce
the documented exit code with a human-readable message on every
malformed-input path. Every `.expect()` in argument parsing replaced.

### P5-7 — `ReceiptSigner::sign` could produce structurally-invalid receipts

**Where:** `crates/ullm-receipts/src/lib.rs::ReceiptSigner::sign`

**Bug:** P3-7 added `Receipt::validate_structural()` and gated
`verify()` on it — but the *sign* path never called it. A TEE coding
error that produced a `Receipt` with empty / wrong-length
`weight_commit_hex` would sign it cleanly and ship it; only the
*receiving* client would catch the corruption.

**Fix:** `sign()` now returns `Result<SignedReceipt>` and gates on
`validate_structural()` before signing. Errors propagate at the
sender side, surfacing the bug at the TEE rather than the client.

---

## Regression tests added

### P5-9 — Field-by-field receipt-signature coverage

New test `tampered_any_field_breaks_signature` enumerates every
`Receipt` field (`tenant`, `session`, `model`, `input_tokens`,
`epoch`, `issued_at_unix`, `kv_blocks_cloaked`), tampers it on a
signed receipt, and asserts `verify` fails. Catches any future
refactor that accidentally drops a field from the signed canonical
bytes.

### P3-7 / P5-7 — Structural validation on sign path

Renamed regression tests `empty_weight_commit_rejected_at_sign` +
`malformed_activation_commit_rejected_at_sign` — they assert that
`ReceiptSigner::sign()` itself rejects malformed Receipts rather than
deferring the failure to a downstream `verify`.

---

## Non-findings (investigated, judged clean or overblown)

- **`InclusionProof::verify` and `tree_size: u64::MAX` DoS.** Agent
  claimed 64 SHA-256 ops per crafted proof was exploitable. 64 SHA-256
  ops ≈ 100 µs — not a DoS at any realistic input rate. And the
  `auditor::verify_inclusion_against_head` wrapper already checks
  `proof.tree_size == sth.head.size`, so a value-out-of-bounds proof
  never enters the walk.
- **Seq-jump ratchet fast-forward.** Re-confirmed from P4: receiver
  calls `next_key()` once per frame and AEAD-fails when the resulting
  key doesn't match the (epoch, seq) nonce derivation. No CPU
  amplification path.
- **Out-of-order receive losing keys.** WS-over-TLS-over-TCP is
  reliably in-order; a malicious gateway reordering causes DoS, not
  key leakage. Documented design constraint.
- **`PreKeyBundle` fields public.** Misuse here requires a caller to
  build a bundle with a mismatched signature, then process it through
  the protocol — verify on the receiving side already rejects.
  Sealing the fields is a breaking change for a low-risk pattern.
- **`LayerVerifier` / `LayerProver` trait misuse.** Documented contract;
  agent's concern is "what if someone writes a stub" — addressable
  only by trait docs, not by code.
- **Slowloris on `/v1/attest`.** Real, but the canonical mitigation is
  a reverse-proxy / load-balancer in front of the TEE (Phase 1's
  threat model already assumes one). No `tower-http` in the
  workspace; adding it for this one feature would be heavyweight.

---

## Verification

- `cargo test --workspace --release` → **169 passed, 0 failed** (1 new
  field-coverage regression test vs P4's 168; the P5-9
  `tampered_any_field_breaks_signature` test exercises 7 sub-cases)
- `ullm-demo` end-to-end → green
- `ullm-phase4-demo` (MPC + multi-vendor + FROST + onion) → green
- Headless WASM clickthrough → 17/17 assertions pass
- Live HTTP replay (P4-5): first `/v1/attest?nonce=X` → 200, second →
  **409 Conflict**
- Prod gateway binary `strings | grep -c "/v1/devkeys"` → **0**
- Prod TEE binary `strings | grep -c "/v1/devkeys"` → **0**

---

## Cumulative status (P1 → P5)

- **43 confirmed vulnerabilities fixed** across five iterative passes
- **169 workspace tests** (up from 0 → 148 → 158 → 161 → 168 → 169 over
  the five rounds)
- Every fix integrated into the existing architecture — no bolt-ons,
  no band-aids
- Both end-to-end demos, headless WASM clickthrough, and live HTTP
  replay check all green after every round
- All five rounds' findings + non-findings documented in
  `docs/audit/FINDINGS{,-P2,-P3,-P4,-P5}.md`
