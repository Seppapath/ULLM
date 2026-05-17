# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Cryptographic protocol breaks are called out under "Protocol" sections so
that operators can correlate `PROTOCOL_VERSION` bumps against client
compatibility.

## [Unreleased]

## [0.2.0-rc1] — 2026-05

First release candidate of the post-audit, deployment-ready tree.

**Cumulative audit work since v0.1.0:**
- **104 vulnerabilities fixed** across thirteen internal red-team
  rounds (P1–P13). Per-round catalogue in
  [`docs/audit/FINDINGS-INDEX.md`](docs/audit/FINDINGS-INDEX.md).
- External audit refresh packaged
  ([`docs/audit/AUDIT-REFRESH-BRIEF.md`](docs/audit/AUDIT-REFRESH-BRIEF.md))
  for shipment to candidate firms.
- 200 workspace tests, 0 failing.
- Prod-binary `/v1/devkeys` denylist gate runs clean across both
  feature combos (`--no-default-features` and `--no-default-features
  --features prod`).
- See [`RELEASE-NOTES-v0.2.0-rc1.md`](RELEASE-NOTES-v0.2.0-rc1.md)
  for the full ship-state summary.

### Protocol

- **BREAKING**: `PROTOCOL_VERSION` bumped twice since 0.1.0:
  - `0x01` → `0x02` (P8-1): cumulative wire-format / signature-payload
    deltas (empty-root sentinel, `log_id` field, required Receipt
    fields, signature-payload domain separation).
  - `0x02` → `0x03` (P13-FIX-D): `Receipt.output_digest_hex`
    semantics changed from "decoded UTF-8 hash" to "token-id stream
    hash"; new `Receipt.output_string_digest_hex` field for the
    decoded-string digest. PR-FIX-D fixed a soundness break where
    two distinct token sequences decoding to the same UTF-8 string
    hashed identically.

  A pre-0x03 client connecting to a 0x03 gateway is rejected at the
  `ClientHello` boundary with `Error::BadVersion` — explicit
  mismatch, no negotiated downgrade.

### Added

- **Operations runbook** (`docs/OPERATIONS.md`) — deploy procedure,
  configuration knobs, observability, incident response, upgrade and
  rollback workflows.
- **Security disclosure policy** (`SECURITY.md`) — coordinated
  disclosure process + audit history pointer.
- **Prometheus `/metrics` endpoint** on both gateway and TEE: protocol
  version, transparency-log size, rate-limiter bucket count, nonce
  registry size, tenant pool size.
- **Graceful shutdown** on `SIGTERM` / `SIGINT` for both binaries.
  Gateway uses `axum-server::Handle::graceful_shutdown` with a 30 s
  deadline; TEE uses `axum::serve(...).with_graceful_shutdown(...)`.
- **Operator-tunable fsync policy** for the transparency log via
  `ULLM_LOG_FSYNC_EVERY_N`. `Periodic` mode requires a witness
  cosigner to maintain audit integrity on crash; default remains
  per-append (`Always`).
- **`tools/ullm-log-auditor`** — offline binary that verifies a Signed
  Tree Head and an inclusion proof; usable in CI for periodic audits.
- **Tenant pool eviction** matching the rate-limiter + nonce-registry
  caps (16k tenants, LRU keyed on `last_seen`).

### Changed

- **O(log N) eviction everywhere** — the rate limiter, nonce registry,
  and tenant pool now maintain `BTreeSet<(Instant, key)>` LRU indexes
  alongside their primary hash maps. Eviction is O(log N) instead of
  the previous full-table linear scan, and the per-observe GC walks
  only the expired prefix (O(k) for k expired entries).
- **`PROTOCOL_VERSION`** bumped (see Protocol).
- **Default release profile** is `lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`, `strip = "symbols"` — production-grade.

### Security

50 cumulative findings fixed across eight internal red-team rounds.
Full per-round catalogues live in `docs/audit/FINDINGS-P{1..8}.md`.
Highlights:

- **P1 — Crypto/protocol surface (8 findings)**: `hybrid_decap` panic
  on malformed ML-KEM ciphertext → `Result` propagation. Transcript
  binding fixes. AEAD nonce-derivation review. Replay-window soundness.
- **P2 — Stateful + parser surface (11 findings)**: epoch/seq desync
  hardening, ZK Fiat-Shamir transcript binding, attestation parser
  fuzzing, Merkle proof crafting defense.
- **P3 — Concurrency + multi-tenant (11 findings)**: TOCTOU window in
  the nonce registry, timing-leak fixes in error paths, AAD coverage
  expansion, cross-tenant pivot audit (P3-4 introduced the
  eviction-cooldown cold-burst penalty).
- **P4 — State machine + key separation (8 findings)**: protocol
  state-confusion eliminated, key-separation invariants enforced,
  signature-payload domain separation introduced.
- **P5 — Adversarial inputs + ecdsa low-s (5 findings)**: low-s
  normalization for P-256 / P-384, network-malice probes, watcher
  semantic correctness.
- **P6 — FFI / time / unsafe (4 findings)**: WASM bindings reviewed
  for JS-injection paths, `now_unix_or_zero` fail-closed time source,
  zero `unsafe` blocks on the security-critical paths, log-secret
  leakage audit.
- **P7 — Supply chain + canonicalization (1 finding)**: STH / log
  entry / receipt canonical-JSON consistency, lock-type review,
  `cargo audit` on the locked tree.
- **P8 — Confirmation round (2 findings)**: `PROTOCOL_VERSION` bump
  for cumulative wire deltas, tenant-pool LRU cap.

### Infrastructure

- **Reproducible Nix flake** for the TEE image
  (`infra/tee-image/flake.nix`). Two independent builders must produce
  byte-identical image SHA-256 hashes before deploy.
- **Azure CC + Phala recipes** (`infra/azure-cc`, `infra/phala`) for
  H100 CC-mode + Intel TDX, and Phala-network DePIN nodes.
- **`ReproducibleBuildVerifier`** admission allowlist gated on the
  manifest from a successful reproducible build.

### Verified

- **173 workspace tests** passing across `cargo test --workspace
  --release`.
- **Two end-to-end demos** green (`ullm-demo`, `ullm-phase4-demo`).
- **Headless WASM clickthrough** — 17/17 assertions pass.
- **Live HTTP nonce-replay check** — first `/v1/attest?nonce=X` returns
  200, second returns 409 Conflict.
- **Production binary strings check** — both `ullm-gateway` and
  `ullm-tee` ship with zero `/v1/devkeys` occurrences.

---

## [0.1.0] — 2025-Q4 → 2026-Q1

Initial reference implementation. Phase 1 → Phase 4 + the 10-slice
deployment-readiness roadmap.

### Added — Phase 1: Crypto and transport

- `ullm-crypto` — ML-KEM-768 + X25519 hybrid KEX, XChaCha20-Poly1305
  AEAD, HKDF-SHA-384 ratchet.
- `ullm-wire` — binary frame codec + sliding-window replay window.
- `ullm-handshake` — PQXDH-style 1-RTT handshake state machine.
- `ullm-tls` — production PQ-hybrid TLS (`X25519MLKEM768` via
  `rustls-post-quantum`).
- `ullm-client` — high-level `Session` SDK.
- `ullm-tee` — TEE service hosting handshake + record layer + LLM.
- `ullm-gateway` — Axum-based blind proxy.

### Added — Phase 2: Attestation + receipts

- `ullm-attest` — TDX, SEV-SNP, and NVIDIA NRAS quote parsing + a
  development mock verifier.
- `ullm-receipts` — Ed25519-signed usage receipts.
- `ullm-transparency` — Sigsum-style transparency log with Merkle
  proofs and Signed Tree Heads.

### Added — Phase 3: ZK verifiable inference

- `ullm-zk` — Halo2 per-layer matrix model proofs (Poseidon, ConstantLength<8>).
- `ullm-model` — synthetic verifiable model with reproducible weight
  commitments.

### Added — Phase 4: MPC + onion + federation

- `ullm-mpc` — real 2PC over additive Fp shares (Pallas curve).
- `ullm-federation` — multi-vendor k-of-n attestation + provider pool +
  build admission control.
- `ullm-threshold` — FROST-Ed25519 t-of-n threshold receipts.
- `ullm-overlay` — 3-hop onion-routed transport (ChaCha20-Poly1305
  layers, fresh ephemeral X25519 per hop).
- `tools/ullm-phase4-demo` — end-to-end Phase 4 capabilities demo.

### Added — Slices 1–10 (deployment readiness)

- **Slice 1**: real LLM substrate (Phi-3-mini / Qwen-2.5-0.5B).
- **Slice 2**: real TDX + SEV-SNP + NRAS verifier with vendor PKI
  chains.
- **Slice 3**: reproducible Nix flake + Azure CC / Phala recipes.
- **Slice 4**: external crypto + protocol audit.
- **Slice 5**: production PQ-hybrid TLS via `rustls-post-quantum`.
- **Slice 6**: Criterion benchmarks + per-component SLO document
  (`docs/SLO.md`).
- **Slice 7**: real Sigsum-style transparency log + auditor tooling.
- **Slice 8**: Petridish SPD + real KV-Cloak in a real attention layer.
- **Slice 9**: mid-stream `key_update` under sustained load.
- **Slice 10**: Phala Network DePIN integration.

### Added — bindings + tooling

- `bindings/python` — `pyo3`-based Python bindings for `Session`.
- `bindings/ts` — `wasm-bindgen`-based WASM bindings for `Session`.
- `tools/ullm-demo` — end-to-end CLI demo.
- `tools/ullm-watcher` — client-side receipt verifier.
- `tools/ullm-log-auditor` — offline transparency-log auditor.

### Cargo features

- `dev-keys` (default; **off in prod**): exposes `/v1/devkeys` for
  tests.
- `prod`: hardening flag asserted by CI strings-check.
- `trusted-dealer` (default): trusted-dealer DKG for FROST. Off
  forces n-party DKG.

[Unreleased]: https://github.com/example/ullm/compare/v0.2.0-rc1...HEAD
[0.2.0-rc1]: https://github.com/example/ullm/compare/v0.1.0...v0.2.0-rc1
[0.1.0]: https://github.com/example/ullm/releases/tag/v0.1.0
