# ullm

> **Ultimate Private LLM Communication Layer.** End-to-end encrypted,
> attested LLM inference. Plaintext exists only on the client and
> inside an attested TEE. Every session produces a transparency-logged
> Ed25519-signed receipt the client can independently audit, plus
> optional per-layer Halo2 ZK proofs that bind the activation trace
> to the committed model weights.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](rust-toolchain.toml)
[![Tests](https://img.shields.io/badge/tests-200%20passing-brightgreen.svg)](#verify)
[![Audit rounds](https://img.shields.io/badge/internal%20audits-13%20rounds-blueviolet.svg)](docs/audit/FINDINGS-INDEX.md)
[![Findings fixed](https://img.shields.io/badge/findings%20fixed-104-success.svg)](docs/audit/FINDINGS-INDEX.md)
[![Status](https://img.shields.io/badge/status-v0.2.0--rc1-yellow.svg)](RELEASE-NOTES-v0.2.0-rc1.md)

---

## Why this exists

LLM providers see your prompts. Even when they say they don't,
they *technically can*. ullm closes that gap by treating the
inference provider as a network adversary: plaintext never leaves
the client unencrypted, never reaches the gateway in the clear, and
only decrypts inside a TEE whose identity is cryptographically
bound to the published model weights.

The threat model assumes:
- The **client** is honest (the user controls it).
- The **gateway** is curious or actively malicious.
- The **TEE** is mostly honest but may be compromised — defended
  by multi-vendor k-of-n attestation, per-layer ZK proofs, and
  transparency-log gossip.

If any one of those layers fails, the rest still hold.

---

## What's in here

```
┌──────────┐        TLS 1.3              ┌───────────────┐
│ client   │◄──── X25519MLKEM768  ────►  │ ullm-gateway  │
│ (SDK or  │       (PQ-hybrid)           │ (blind proxy, │
│  WASM)   │                              │  trans. log)  │
└────┬─────┘                              └──────┬────────┘
     │           E2E AEAD over WS               │ loopback
     │      (XChaCha20-Poly1305 + ratchet)      │  plaintext
     ▼                                          ▼
                                            ┌────────────┐
   verifiable receipt   ◄──── signs ───┤  ullm-tee  │
   (Ed25519 + STH +                    │ (attested  │
    per-layer ZK)                       │  enclave)  │
                                        └────────────┘
```

Concretely:

- **PQ-hybrid 1-RTT handshake**: ML-KEM-768 + X25519 with strict-PQ
  TLS opt-in (`ULLM_REQUIRE_PQ=1`)
- **Record layer**: XChaCha20-Poly1305 + symmetric ratchet + DH
  ratchet for forward secrecy / post-compromise security
- **Attestation**: real TDX + SEV-SNP + NVIDIA NRAS parsers with
  measurement allowlist; `MultiVendorVerifier` enforces k-of-n
  over **cryptographic vendor identities** (not caller-asserted
  labels)
- **ZK proofs**: per-layer Halo2 (Poseidon `ConstantLength<8>`,
  matmul + commitment) with 6-row public-input vector binding
  `(x_commit, y_commit, layer_idx, session_id, weight_commit_lo,
  weight_commit_hi)`. Non-replayable across sessions/layers/models.
- **Transparency log**: Sigsum-style append-only log, persistent
  JSONL, Signed Tree Heads, witness cosignatures, offline auditor
  with `compare-sths` fork detection
- **Receipts**: Ed25519-signed, bind tenant + session + epoch +
  token-id digest + decoded-string digest + weight commit + per-layer
  activation commits
- **KV-Cloak**: Petridish SPD process model for per-tenant KV-cache
  isolation
- **Threshold / federation**: FROST-Ed25519 t-of-n receipts; 2PC
  fallback for non-collusion deployments; 3-hop onion overlay
- **Production wiring**: graceful shutdown, Prometheus `/metrics`
  on a separate mgmt listener with optional bearer auth, tunable
  fsync policy, O(log N) LRU eviction with monotonic seq
  tie-breaker, GitHub Actions CI with a `/v1/devkeys`-strings
  denylist gate

---

## Status

**v0.2.0-rc1** — release candidate.

| Component | State |
|---|---|
| Cryptographic core | Production-ready; externally audited at v0.1.0 (Slice 4) |
| PQ-hybrid TLS | Production-ready; strict-PQ opt-in via env var |
| Transparency log + auditor | Production-ready |
| Watcher + receipt verification | Production-ready (P13-FIX-B restructure) |
| Multi-vendor attestation | Production-ready (P13-FIX-E identity binding) |
| Per-layer ZK | Production-ready *for the synthetic toy model* |
| Real LLM substrate | Crate exists (`ullm-llm`); **not wired into prod TEE yet** ([known issue A1](docs/audit/KNOWN-ISSUES.md#a1)) |
| Real-LLM ZK circuit | Roadmap (Slice 12) |

See [`docs/audit/KNOWN-ISSUES.md`](docs/audit/KNOWN-ISSUES.md) for the
full deferred-items list.

### Audit history

- **Slice 4** (v0.1.0): external crypto + protocol audit on the
  ~6,500 LOC cryptographic core
- **13 internal red-team rounds** (P1 → P13): **104 vulnerabilities
  fixed**, with regression tests in the workspace for every fix.
  Per-round catalogue in
  [`docs/audit/FINDINGS-INDEX.md`](docs/audit/FINDINGS-INDEX.md).
- **External audit refresh packet** ready in
  `scripts/build_audit_packet.sh` — see
  [`docs/audit/AUDIT-REFRESH-BRIEF.md`](docs/audit/AUDIT-REFRESH-BRIEF.md)
  if you want to commission a paid review against v0.2.0-rc1.

---

## Quickstart

```bash
# Clone + build
git clone https://github.com/<you>/ullm
cd ullm
cargo build --workspace --release

# Run the test suite (expect: 200 passed, 0 failed)
cargo test --workspace --release

# Run the end-to-end demo:
# in-process gateway + TEE + client; PQXDH handshake;
# encrypted streaming; signed receipt; 8 ZK proofs verified;
# inclusion proof against the transparency log.
cargo run -p ullm-demo --release

# Run the Phase-4 capabilities demo:
# MPC 2PC + 2-of-3 multi-vendor attestation + FROST t-of-n
# receipts + 3-hop onion routing.
cargo run -p ullm-phase4-demo --release
```

## Verify

```bash
# Clean build, zero warnings
cargo build --workspace --release

# Full test suite — 200 passing, 0 failing at v0.2.0-rc1
cargo test --workspace --release

# Compile-time mutual exclusion of dev-keys + prod (intentional)
cargo check -p ullm-gateway --release --features prod
# → compile_error: features `dev-keys` and `prod` are mutually exclusive

# Correct prod build
cargo check -p ullm-gateway -p ullm-tee --release --no-default-features --features prod

# Supply-chain audit
cargo install --locked cargo-audit
cargo audit

# Prod-binary dev-string leakage check
bash scripts/build_audit_packet.sh
# Look for "STRINGS-CHECK: PASS" in the output
```

---

## Repo layout

| Path | What |
|---|---|
| `crates/ullm-crypto/` | ML-KEM-768 + X25519 hybrid KEX, AEAD, ratchet |
| `crates/ullm-wire/` | Binary frame codec, sliding-window replay protection |
| `crates/ullm-handshake/` | PQXDH-style 1-RTT handshake state machine |
| `crates/ullm-tls/` | rustls + rustls-post-quantum configs, strict-PQ mode |
| `crates/ullm-attest/` | TDX/SEV-SNP/NRAS quote parsers, real vendor PKI |
| `crates/ullm-zk/` | Halo2 per-layer matmul + Poseidon proofs |
| `crates/ullm-model/` | Synthetic verifiable model (placeholder for real LLM) |
| `crates/ullm-llm/` | Real LLM substrate (Phi-3 / Qwen via candle) |
| `crates/ullm-receipts/` | Ed25519-signed receipts |
| `crates/ullm-transparency/` | Append-only log + STH + inclusion proofs |
| `crates/ullm-federation/` | Multi-vendor k-of-n + reproducible-build admission |
| `crates/ullm-threshold/` | FROST-Ed25519 t-of-n threshold signing |
| `crates/ullm-mpc/` | 2PC over additive Fp shares |
| `crates/ullm-overlay/` | 3-hop onion routing |
| `crates/ullm-kvcloak/` | Per-tenant KV-cache cloaking |
| `crates/ullm-tee/` | TEE-side WebSocket service |
| `crates/ullm-gateway/` | Blind reverse proxy + transparency-log host |
| `crates/ullm-client/` | Client SDK |
| `crates/ullm-bench/` | Criterion benches against `docs/SLO.md` |
| `bindings/python/` | pyo3 bindings |
| `bindings/ts/` | wasm-bindgen bindings + browser demo |
| `tools/ullm-demo/` | End-to-end CLI demo |
| `tools/ullm-watcher/` | Client-side receipt + log verifier |
| `tools/ullm-log-auditor/` | Offline transparency-log auditor |
| `infra/` | Reproducible Nix flake + Azure CC + Phala recipes |
| `docs/` | Design, audit history, operations runbook, SLOs |

---

## Documentation

| Doc | Purpose |
|---|---|
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Production runbook: deploy, configure, observe, incident response, upgrade, rollback |
| [`docs/SLO.md`](docs/SLO.md) | Per-component performance budgets + Criterion bench mapping |
| [`docs/audit/THREAT-MODEL.md`](docs/audit/THREAT-MODEL.md) | Adversary tiers, in-scope assets, trust assumptions |
| [`docs/audit/SCOPE.md`](docs/audit/SCOPE.md) | Slice 4 external-audit scope (v0.1.0) |
| [`docs/audit/SCOPE-REFRESH.md`](docs/audit/SCOPE-REFRESH.md) | Delta since v0.1.0 (for the v0.2.0-rc1 refresh) |
| [`docs/audit/FINDINGS-INDEX.md`](docs/audit/FINDINGS-INDEX.md) | Index of all 13 internal red-team rounds |
| [`docs/audit/KNOWN-ISSUES.md`](docs/audit/KNOWN-ISSUES.md) | Deliberately-deferred items |
| [`docs/audit/AUDIT-REFRESH-BRIEF.md`](docs/audit/AUDIT-REFRESH-BRIEF.md) | Cover letter for external audit firms |
| [`SECURITY.md`](SECURITY.md) | Coordinated-disclosure policy |
| [`CHANGELOG.md`](CHANGELOG.md) | Cumulative changes since v0.1.0 |
| [`RELEASE-NOTES-v0.2.0-rc1.md`](RELEASE-NOTES-v0.2.0-rc1.md) | This release's ship notes |
| [`infra/README.md`](infra/README.md) | Deployment recipes (Nix, Azure CC, Phala) |

---

## Configuration (production deploys)

Operators configure both binaries via environment variables. Full
list in [`docs/OPERATIONS.md`](docs/OPERATIONS.md). Highlights:

| Variable | Component | Notes |
|---|---|---|
| `ULLM_GATEWAY_ADDR` | gateway | Public TLS listener |
| `ULLM_GATEWAY_METRICS_ADDR` | gateway | Mgmt listener (default loopback; refuses non-loopback without `ULLM_METRICS_ALLOW_PUBLIC=1`) |
| `ULLM_TEE_ADDR` | tee | Protocol listener (must be loopback in prod) |
| `ULLM_TEE_METRICS_ADDR` | tee | Mgmt listener (loopback) |
| `ULLM_METRICS_TOKEN` | both | Optional bearer-token auth on `/metrics` |
| `ULLM_REQUIRE_PQ=1` | gateway | Refuse classical-only TLS handshakes |
| `ULLM_LOG_PATH` | gateway | Persistent JSONL transparency log |
| `ULLM_LOG_FSYNC_EVERY_N` | gateway | Batched fsync (requires witness cosigner) |
| `ULLM_LOGGER_SEED` | gateway | 32-byte hex; STH signing key |
| `ULLM_LOG_ID` | gateway | Stable per-deployment identifier |

---

## Security

**Report vulnerabilities privately.** See [`SECURITY.md`](SECURITY.md)
for the coordinated-disclosure policy and PGP key.

Do not file public GitHub issues for security bugs.

---

## Contributing

Contributions are welcome under the [Apache-2.0 license](LICENSE)
with a Developer Certificate of Origin (DCO) sign-off
(`git commit -s`). Useful targets:

- **Slice 11**: wire `RealLlmEngine` into the prod TEE binary
  ([known issue A1](docs/audit/KNOWN-ISSUES.md#a1))
- **Slice 12**: real-LLM ZK circuit
  ([known issue A2](docs/audit/KNOWN-ISSUES.md#a2))
- **Vendor PKI chain parsing**: bind TDX identity to Intel root CA,
  SNP to VCEK, NRAS to NVIDIA root — see
  [KNOWN-ISSUES M4/M5/M6](docs/audit/KNOWN-ISSUES.md)
- **Field-element range checks in ZK**:
  [KNOWN-ISSUES M1](docs/audit/KNOWN-ISSUES.md)
- **Independent auditor reviews of any subsystem** — the audit packet
  in `scripts/build_audit_packet.sh` is exactly what we hand external
  firms

Before opening a PR:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --release
cargo test --workspace --release
```

The CI pipeline runs all of these plus `cargo audit`, a WASM build,
and the `/v1/devkeys`-strings denylist gate. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Acknowledgements

ullm builds on, and would not exist without:

- [rustls](https://github.com/rustls/rustls) +
  [rustls-post-quantum](https://github.com/rustls/rustls-post-quantum)
- [ml-kem](https://github.com/RustCrypto/KEMs) (RustCrypto)
- [halo2](https://github.com/zcash/halo2) +
  [halo2-gadgets](https://github.com/zcash/halo2)
- [frost-ed25519](https://github.com/ZcashFoundation/frost) (Zcash Foundation)
- [candle](https://github.com/huggingface/candle) (Hugging Face)
- [axum](https://github.com/tokio-rs/axum) + tokio
- [signal protocol](https://signal.org/docs/) inspiration for the
  ratchet design
