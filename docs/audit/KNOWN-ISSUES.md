# Known Issues — Do NOT Flag As New Findings

This document enumerates **deliberately-deferred** items. The auditor
who finds these should file a comment referencing the relevant
entry here, not a new finding. Anything NOT on this list is fair
game.

---

## Architectural truths

### A1 — Slice 1 is effectively undeployed in the prod TEE binary

**Discovered:** P13-E.F1.

**Status:** Roadmap (Slice 11).

**Description:** `crates/ullm-tee/src/bin/server.rs` constructs
`engine: Arc::new(MockEngine::default())` at startup. `MockEngine`
in `crates/ullm-tee/src/inference.rs` returns
`format!("echo: {prompt}")` token-by-token. The real LLM substrate
in `crates/ullm-llm/` (Slice 1) is reachable only from test/demo
fixtures (e.g., `tools/ullm-phase4-demo`, integration tests).

**Why deferred:** Wiring `RealLlmEngine` into prod requires:
1. Adding `ullm-llm = { workspace = true, features = ["candle"] }`
   to `crates/ullm-tee/Cargo.toml`.
2. Resolving the `ULLM_MODEL_PATH` / `ULLM_TOKENIZER_PATH` env-var
   contract.
3. Verifying the safetensors / GGUF file against the manifest's
   `image_sha256` at startup.
4. Documenting the operational cost (model load time, GPU
   requirements, memory pressure).
5. Updating the Nix flake to bake a real model into the
   reproducible image (or providing a known-hash download step).

These are operational decisions, not defect fixes.

**Security implications:** All cryptographic guarantees still hold
(encryption, attestation, transparency log, signed receipts, ZK
proofs against the synthetic model). The mock just doesn't run a
useful LLM. A deployment running this binary is **not insecure** —
it's just unhelpful.

---

### A2 — ZK proofs cover the synthetic toy model, not the real LLM

**Discovered:** P13-E.F12.

**Status:** Roadmap (Slice 12).

**Description:** Even after A1 is resolved, the per-layer Halo2
proofs in `crates/ullm-zk` cover `crates/ullm-model::Model` — the
synthetic 8-layer × 8-wide matrix toy used for the verifiable-substrate
demo. The real LLM runs through `InferenceEngine::run` totally
independently of the ZK trace. The `weight_commit_hex` field in the
Receipt commits to the *toy*, not to the safetensors/GGUF file the
real engine loads.

**Why deferred:** A real-LLM ZK circuit is genuinely hard. Options
under consideration:
- Per-layer matmul proofs over INT8 quantized weights (proof time
  dominated by the field-element conversion overhead).
- Lookup-argument-based proofs (Jolt / Lasso style) over the LLM's
  forward pass.
- Folding (Nova / Sonobe) over per-layer proofs to amortize.

None of these have been audited or benchmarked against
production-realistic models yet.

**Security implications:** Once Slice 11 wires `RealLlmEngine`, the
system runs in **"attestation-only" mode** for verifiability —
clients trust the TEE attestation chain + the encrypted-stream
binding to it, but cannot independently verify the model output is
the result of running the *committed* weights on their prompt.
P13-FIX-C's session/layer/weight binding is correct for what the
proofs *do* attest (the synthetic toy); a verifier should be aware
the proofs commit to the synthetic model commitment, not to the
real model's weights.

---

## Documented MEDIUMs deferred

### M1 — No field-element range checks in ZK circuits

**Discovered:** P13-C.M7.

**Status:** Tracked. Requires `RangeChip`.

**Description:** `crates/ullm-zk/src/layer.rs::LayerCircuit::synthesize`
constrains `y = W·x + b` over the **full** Pallas scalar field
(~2^254). A malicious prover witnessing `x[i] = 2^200` produces a
valid proof but a nonsensical activation. The `Model::run` honest
path uses `fp_from_wide` which clamps to ~254 bits, but the circuit
doesn't enforce any magnitude bound.

**Severity is dampened** by A2 (the proofs cover a synthetic toy
where magnitude doesn't carry semantic meaning). Once Slice 12 lands
a real-LLM circuit, this MUST be fixed.

---

### M2 — KV-Cloak is invertible by holder of the cloak key

**Discovered:** P13-E.F14. Documented in
`crates/ullm-kvcloak/src/lib.rs:1-22` already.

**Status:** Threat model — by design.

**Description:** Both `cloak.rs::uncloak` and `matrix.rs::uncloak`
are pure inverses (XOR keystream + permutation, or `L⁻¹·Pᵀ`). The
threat model is "HBM-snoop with the key inside the TEE" — the cloak
is NOT a one-way function. Anyone who exfiltrates `MasterSecret` +
`tenant_salt` + `session_id` recovers every historical KV.

**Why this is OK in the threat model:** the cloak key never leaves
the TEE; the threat model is about preventing a process-level
adversary (e.g., a co-resident container, a microarchitectural
snoop) from reading raw KV blocks in DRAM. The cloak key is
re-rolled on every TEE startup (`MasterSecret::random`).

**What would change this:** a future Sub-Slice that exposes cloak
keys outside the TEE for any reason would invalidate the threat
model.

---

### M3 — No chain-length cap on `Evidence::cert_chain`

**Discovered:** P13-D item-12.

**Status:** Deferred.

**Description:** `crates/ullm-attest/src/evidence.rs::Evidence`
has `cert_chain: Vec<Vec<u8>>` decoded via postcard with no length
bound. A 1000-cert chain is feasible CPU exhaustion when signature
checking ships. Practical exploit requires an attacker who can
submit evidence at handshake time.

**Why deferred:** the current `RealVerifier` doesn't recursively
walk the chain — it only inspects `report_data` and `measurement`.
The DoS only materializes once Slice 13 (full vendor-PKI chain
verification) lands.

---

### M4 — NRAS JWS signature not yet verified

**Discovered:** P13-D item-11.

**Status:** Partial mitigation in P13-FIX-E; full fix deferred.

**Description:** `crates/ullm-attest/src/nvidia.rs::NvidiaQuote::parse`
extracts `signature` and `signed_message` but `RealVerifier` only
checks `measurement_hex` against an allowlist. The JWS itself is
parsed but not cryptographically verified.

**Partial mitigation:** P13-FIX-E's `attestation_identity` for NRAS
incorporates `signed_message || signature`, so an attacker who
hand-crafts a JSON payload with any allowlisted measurement still
produces a *different* attestation identity from a real NVIDIA
quote — preventing the "one NRAS compromise pretends to be k=2"
attack from P13-FIX-E.

**Full fix requires:** transporting the NVIDIA root pubkey in
`Evidence`, or fetching it from a published NRAS-pubkey allowlist.

---

### M5 — TDX identity does not yet chain to Intel root CA

**Discovered:** P13-FIX-E own limitation note.

**Status:** Tracked.

**Description:** TDX `attestation_identity` hashes `attestation_key
|| cert_data` directly, without parsing `cert_data` as a DER chain
and binding to the Intel root CA fingerprint. A node that rolls its
QE between quotes would produce two distinct identities (good for
non-collusion threshold), but **a single QE persists across
sessions** so the same node produces the same identity across all
its quotes — which is what we want for dedup.

**Why deferred:** chain parsing is non-trivial; requires a DER
parser + the Intel PCS root CA published fingerprint. The current
identity is sufficient for the threshold-k dedup property.

---

### M6 — SEV-SNP identity uses chip_id, not VCEK fingerprint

**Discovered:** Same as M5.

**Status:** Tracked.

**Description:** Per `crates/ullm-attest/src/snp.rs`, the VCEK cert
chain isn't currently transported in the `Evidence` envelope.
`attestation_identity` falls back to `chip_id || signature`.

**Why deferred:** extending `Evidence` to carry VCEK cert chains is
a wire-format change; postpone to a future PROTOCOL_VERSION bump.

---

### M7 — `panic = "abort"` skips `Drop` impls on panic

**Discovered:** P12-E.F6.

**Status:** Documented in `OPERATIONS.md`.

**Description:** `Cargo.toml` workspace `[profile.release]` includes
`panic = "abort"`. On any panic during operation, destructors do
NOT run — `TransparencyLog::Drop` doesn't fsync, `Zeroize` doesn't
zeroize on the panic'd path.

**Why this is OK:** the panic-abort decision was made to harden
against panic-as-control-flow (P6 hunt found many `unwrap` sites);
the trade-off is documented. Operators should pair `Periodic`
fsync policy with witness cosigners to detect entry loss on crash.

---

### M8 — `unsafe { Mmap::map }` in `ullm-llm/real.rs` has unverified `from_gguf` ownership

**Discovered:** P13-A.F1.

**Status:** Latent. Only manifests if A1 is resolved (the engine is
wired in).

**Description:** `Mmap::map` is unsafe because the OS doesn't
guarantee the file isn't concurrently modified. The mmap is consumed
by `candle::ModelWeights::from_gguf`. **It is unverified whether
`from_gguf` copies the parsed structures out of the mmap or borrows
them.** If it borrows, the mmap must outlive `RealLlmEngine`, which
the current code does NOT enforce.

**Why deferred:** the engine isn't wired (see A1), so this latent
UB has no runtime path today. Before Slice 11 wires it, verify
`from_gguf` semantics and either store the `Mmap` as a field of
`RealLlmEngine` to extend its lifetime, or trust that `from_gguf`
copies.

---

## Operational / non-cryptographic deferred items

### O1 — CODEOWNERS uses a placeholder `@ullm-security` team

**Discovered:** P11-E.HIGH-1.

**Status:** First-time setup. Documented in `SECURITY.md`.

**Description:** `.github/CODEOWNERS` routes every security-critical
path to `@ullm-security`. **This is a placeholder handle.** GitHub
silently no-ops any CODEOWNERS rule that references a non-existent
team/user. Until the team is created and branch protection is
configured, the file is non-functional.

**Why deferred:** first-time repository setup, not a code defect.

---

### O2 — `RealVerifier` does not run live CRL / OCSP checks

**Discovered:** Documented in `crates/ullm-attest/src/real_verifier.rs:11-13`.

**Status:** Acceptable.

**Description:** Live revocation-status fetching isn't performed.
Operators rely on offline CRL refresh + measurement allowlist
management.

---

### O3 — Third-party GitHub Actions not SHA-pinned

**Discovered:** P11-E LOW item.

**Status:** Documented trust assumption.

**Description:** `.github/workflows/ci.yml` uses tag references
(`@v4`, `@stable`). A re-pointed tag would inject malicious code
into the runner.

**Why deferred:** large refactor of CI; should be addressed before
v0.2.0 final.

---

### O4 — Sampling is greedy / deterministic in `RealLlmEngine`

**Discovered:** P13-E.F7.

**Status:** Roadmap.

**Description:** Generation uses `argmax_keepdim`. Determinism is
fine for replay protection but means an attacker who probes the
model can pre-compute outputs offline.

**Why deferred:** related to A1 (engine not wired); when wired, use
`OsRng` for sampling and bind seed into AAD/receipt.

---

## Out of scope (for reference)

These items will NOT be in scope for the external auditor at all:

- Side-channel attacks against the underlying CPU/GPU
  (microarchitectural, power, EM)
- Live model weights and inference correctness (subject of A1+A2)
- Vendor PKI mis-issuance (T4 threat tier — out of scope for crypto
  audit)
- Phala overlay network internals (we use it; not our code)
- HQC / Classic McEliece migration (Phase 5, not in v0.2)
- WASM bindings for protocol correctness (memory safety only)
- `ullm-bench/` benchmark crate (measurement only)
