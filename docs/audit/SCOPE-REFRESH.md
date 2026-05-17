# Audit Scope Refresh — Delta Since Slice 4

This document enumerates **every code change** between the Slice 4
external audit tag (v0.1.0) and the v0.2.0-rc1 refresh tag. Used by
the auditor to prioritize attention and by the maintainer to confirm
nothing is silently out-of-scope.

> Companion to [`SCOPE.md`](SCOPE.md) (the original Slice 4 scope
> doc) and [`AUDIT-REFRESH-BRIEF.md`](AUDIT-REFRESH-BRIEF.md) (the
> auditor cover letter).

---

## 1. Workspace structure delta

### New crates

- `crates/ullm-llm/` (NEW) — Real LLM substrate. Loads GGUF weights
  via `candle`, runs Phi-3-mini / Qwen-2.5-0.5B-class models behind
  the `InferenceEngine` trait. **Not yet wired into the prod TEE
  binary** — see `KNOWN-ISSUES.md`. Auditor's surface: ~250 LOC.
- `crates/ullm-phala/` (NEW) — Phala Network DePIN integration.
  Mostly orchestration; minimal new cryptographic surface.
- `tools/ullm-log-auditor/` (NEW) — Offline transparency-log auditor
  binary. New in P13-FIX-B: `compare-sths` subcommand for fork
  detection.

### Significantly changed crates

- `crates/ullm-attest/` — Real TDX (`src/tdx.rs`), SEV-SNP
  (`src/snp.rs`), and NVIDIA NRAS (`src/nvidia.rs`) parsers added in
  Slice 2. `src/real_verifier.rs` is the new entry point. **The
  parsers have not had a focused adversarial-input audit since
  landing** — P2 fuzzed the v0.1 parsers but the new Slice 2 code
  is substantively different.
- `crates/ullm-zk/src/layer.rs` — 6-row public-input vector
  (P13-FIX-C); `LayerProver::prove_trace` + `LayerVerifier::verify`
  signatures changed. `LAYER_CIRCUIT_K` bumped 12→13.
- `crates/ullm-tls/src/lib.rs` — Strict-PQ provider (P13-FIX-A) +
  `server_config_strict_pq` + `client_config_pinned_strict_pq`.
- `crates/ullm-federation/src/multi_vendor.rs` — Dedup by
  attestation identity (P13-FIX-E). `Verifier` trait grew an
  `attestation_identity` method.
- `crates/ullm-receipts/src/lib.rs` — `output_string_digest_hex`
  field added (P13-FIX-D); `output_digest_hex` semantics changed
  from "decoded UTF-8 hash" to "token-id stream hash".
- `crates/ullm-transparency/src/log.rs` — Persistent JSONL backing
  + `FsyncPolicy::{Always, Periodic}` (PR-3) + torn-write recovery
  + BOM stripping + bracket-depth defense (P10..P12).
- `crates/ullm-tee/src/service.rs` — `TokenChunk` typed stream;
  `metrics_router` split (P9-FIX-C); shutdown-broadcaster wiring;
  STH cache contention work.
- `crates/ullm-gateway/src/proxy.rs` — Metrics router, STH cache,
  bearer-token middleware (`ULLM_METRICS_TOKEN`), rate-limiter LRU
  with monotonic seq tie-breaker.
- `crates/ullm-gateway/src/bin/server.rs` — Strict-PQ opt-in
  (`ULLM_REQUIRE_PQ=1`), management listener, broadcaster-based
  graceful shutdown.
- `crates/ullm-core/src/`:
  - `shutdown.rs` (NEW) — `ShutdownBroadcaster` + sync signal install
  - `validate_metrics_addr` (NEW) — loopback enforcement
  - `version::PROTOCOL_VERSION` — `0x01` → `0x02` (P8) → `0x03` (P13)

### Workspace-level changes

- `.github/workflows/ci.yml` (NEW since Slice 4) — full CI pipeline
- `.github/CODEOWNERS` (NEW) — security-critical-path ownership
- `Cargo.toml` workspace `[profile.release]`:
  - `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`,
    `strip = "symbols"`
- `Cargo.lock` — now committed (P12-FIX-A); was previously
  `.gitignore`d (this was itself a P12 finding)
- `subtle = "=2.6.1"` exact-pinned (P12-FIX-A)
- `infra/` (significantly expanded) — Nix flake, Azure CC + Phala
  recipes

---

## 2. Protocol-level changes

### PROTOCOL_VERSION bumps

- `0x01` → `0x02` (P8-1): cumulative wire-format / signature-payload
  deltas (P2-5 empty-root sentinel, P2-6 log_id field, P3-7 required
  Receipt fields, P4-1 signature-payload domain separation).
- `0x02` → `0x03` (P13-FIX-D): `Receipt` schema gained
  `output_string_digest_hex`; `output_digest_hex` is now over token
  IDs, not decoded bytes.

A pre-bump client/server pair fails fast at `ClientHello`
boundary check rather than producing confusing downstream signature
errors.

### Receipt schema changes since Slice 4

| Field | Status |
|---|---|
| `tenant` | unchanged |
| `session` | unchanged |
| `epoch` | unchanged |
| `input_hash_hex` | unchanged |
| `output_digest_hex` | **semantics changed (P13-FIX-D)**: was SHA-256 over decoded UTF-8 string pieces; now SHA-256 over `"ULLM-v1 token-id-digest" \|\| input_hash \|\| u32-LE(count) \|\| id_0 \|\| ... \|\| id_{n-1}` |
| `output_string_digest_hex` | **NEW (P13-FIX-D)**: separate decoded-bytes hash for UI use |
| `weight_commit_hex` | unchanged (still SHA-512-truncated-to-32 over `to_repr()` bytes of the synthetic model; **does NOT cover the real LLM weights**) |
| `activation_commits_hex` | unchanged |
| `output_token_total` | unchanged |
| `kv_blocks_cloaked` | unchanged |
| `latency_ms` | unchanged |

### ZK proof public-input vector (P13-FIX-C)

| Slot | Slice-4 contents | v0.2.0-rc1 contents |
|---|---|---|
| 0 | `x_commit` (Fp) | `x_commit` (Fp) — unchanged |
| 1 | `y_commit` (Fp) | `y_commit` (Fp) — unchanged |
| 2 | — | **NEW**: `Fp::from(layer_idx as u64)` |
| 3 | — | **NEW**: `Fp::from_u128(session_id_le)` |
| 4 | — | **NEW**: `weight_commit_lo` = `Fp::from_u128(bytes[0..16])` |
| 5 | — | **NEW**: `weight_commit_hi` = `Fp::from_u128(bytes[16..32])` |

Each slot is enforced via `Layouter::constrain_instance`. A proof
minted for `(session_a, layer_i, weight_w)` does not verify when
fed `(session_b, *, *)` or `(*, layer_j, *)` where `i != j`, etc.
Regression tests in `crates/ullm-zk/src/layer.rs` confirm.

### Strict-PQ TLS (P13-FIX-A)

- `server_config_strict_pq(cert: &SelfSignedCert) -> rustls::Result<ServerConfig>`
- `client_config_pinned_strict_pq(...) -> ClientConfig`
- Both pin `kx_groups` to `&[&X25519MLKEM768]` only — classical
  X25519 / secp256r1 fallback paths refused.
- Gateway opt-in via `ULLM_REQUIRE_PQ=1`. Default behavior
  preserved (PQ-preferred + classical-tolerant) for dev/staging.

### Vendor identity binding (P13-FIX-E)

- `Verifier::attestation_identity(&self, &Evidence) -> Option<[u8;32]>`
  added to the trait in `ullm-attest`.
- Each vendor verifier returns a SHA-256 digest of cryptographic
  material:
  - TDX: `SHA-256(attestation_key \|\| cert_data)`
  - SEV-SNP: `SHA-256(chip_id \|\| signature)`
  - NRAS: `SHA-256(signed_message \|\| signature)`
  - MockVerifier: `SHA-256("ullm/mock-verifier/v1" \|\| trust_root_pubkey \|\| report_data)`
- `MultiVendorVerifier::verify` now dedups by attestation identity,
  not by `cpu_quote_kind` label. Threshold satisfaction requires
  **distinct cryptographic identities**, not just distinct
  caller-supplied labels.

**Audit-worthy gaps in the above** (documented in
`crates/ullm-federation/src/multi_vendor.rs`):
- TDX identity does NOT yet chain to Intel root CA fingerprint —
  still hashes only the in-quote attestation key + cert_data blob.
  Follow-up to parse `cert_data` as a DER chain.
- SNP identity uses chip_id + signature, not real VCEK fingerprint
  (VCEK cert chains aren't currently transported).
- NRAS identity is anchored to the JWS bytes, not the NVIDIA root
  pubkey directly.

---

## 3. Production-deployment changes (PR-1..PR-8)

Each was followed by P9..P12 hardening rounds. End state:

| PR | Status | Notable hardening |
|---|---|---|
| PR-1 graceful shutdown | landed + watch-broadcaster (P10/P11/P12) | sync signal install, sender-drop-doesn't-masquerade-as-fire |
| PR-2 /metrics | landed + split listener (P9) + auth (P10) + Unicode-safe sanitizer (P10/P11) | bearer token via `ULLM_METRICS_TOKEN`, loopback enforcement, route_layer scopes auth only to /metrics not /v1/healthz |
| PR-3 fsync policy | landed | `ULLM_LOG_FSYNC_EVERY_N`, witness-warning, flush-before-STH-sign |
| PR-4 LRU eviction | landed + tie-breaker (P9/P10) | `BTreeSet<(Instant, u64_seq, key)>` on rate-limiter / nonce-registry / tenant-pool |
| PR-5 OPERATIONS.md | landed | runbook, incident response, key compromise, log fork, replay attack |
| PR-6 SECURITY.md + CHANGELOG.md | landed + branch-protection rules (P10/P11) | coordinated disclosure terms, CODEOWNERS one-time setup notice |
| PR-7 CI | landed + denylist refinement (P10/P11/P12) | `prod-binary strings check`, feature-matrix scoped to gateway+TEE for `--features prod` row, release-tag trigger |
| PR-8 version bump | landed | `0.1.0` → `0.2.0-rc1` |

---

## 4. Internal red-team rounds (P1..P13) — outcomes

See `FINDINGS-INDEX.md` for the index. Cumulative: **104 confirmed
vulnerabilities fixed**. Trend:

| Round | Findings | Notable |
|---|---|---|
| P1 | 8 | hybrid_decap panic, transcript binding, replay window |
| P2 | 11 | epoch/seq desync, ZK Fiat-Shamir, attestation parser fuzzing |
| P3 | 11 | TOCTOU, timing leaks, AAD coverage, eviction cooldown |
| P4 | 8 | protocol state-confusion, key separation, signature domain separation |
| P5 | 5 | low-s normalization, watcher semantics |
| P6 | 4 | WASM injection, fail-closed time, log secret leakage |
| P7 | 1 | canonical-JSON, lock-type review, cargo-audit |
| P8 | 2 | PROTOCOL_VERSION bump, tenant pool LRU cap |
| P9 | 7 | shutdown drain deadlines, fsync semantics, ZK-LRU hardening |
| P10 | 8 | broadcaster registration race, STH fsync DoS, JSONL torn-write |
| P11 | 10 | wait() Err handling, signal pre-spawn install, JSONL streaming |
| P12 | 9 | **3 HIGHs**: Cargo.lock not committed, hand-rolled subtle_compare non-CT under LTO, BOM corruption |
| P13 | 20 | **5 CRITICALs**: PQ downgrade, watcher trust-without-verify, ZK rebindability, output_digest, vendor dedup |

P12 and P13 each surfaced pre-existing HIGH/CRITICAL defects that
the previous twelve rounds had missed — both were caught by pivoting
the audit lens (P12: supply-chain + LTO; P13: underexplored
subsystems). The external audit refresh is the natural next step.

---

## 5. Dependency floor (Cargo.toml workspace deps)

Notable since Slice 4:

- `rustls = "0.23"` (was 0.21) — TLS 1.3 only
- `rustls-post-quantum = "0.2"` — added in Slice 5
- `axum = "0.7"` — added in Slice 7
- `axum-server = "0.7"` — added in PR-1
- `frost-ed25519 = "2"` — unchanged
- `ml-kem = "0.2"` — unchanged
- `x25519-dalek = "2.0"` — unchanged
- `subtle = "=2.6.1"` — **exact-pinned** (P12-FIX-A)
- `ed25519-dalek = "2.1"` — was 2.0 (CVE-fixed)
- `candle-core` family — added in Slice 1 (gated behind feature in
  `ullm-llm`)

Full SBOM in `audit-packet/DEPENDENCY-SBOM.txt` (output of
`cargo tree --workspace --edges normal,build --prefix none`).

---

## 6. Out-of-scope items (unchanged from Slice 4 + new additions)

- `crates/ullm-bench/` — measurement only
- `tools/ullm-demo`, `tools/ullm-phase4-demo` — example code
- `tools/ullm-watcher` — **was in scope**, now under audit; the
  P13-FIX-B restructure left it substantially changed
- `bindings/python`, `bindings/ts` — FFI; review for memory safety
  but not protocol correctness
- `infra/` — deployment recipes (operational not cryptographic, but
  reproducibility verification is welcomed)
- The Phala overlay network proper (not our code; we use it)
- Live vendor PCS / OCSP integration (still a roadmap item)
- Side-channel attacks against the underlying CPU/GPU
  (microarchitectural, power, EM)
- Live model weights and inference correctness (Slice 11+)
