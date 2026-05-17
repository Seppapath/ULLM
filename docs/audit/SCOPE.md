# External Audit — Scope Document

## What's being audited

The Apache-2.0 open-source crates that form the cryptographic core of the
Ultimate Private LLM Communication Layer:

| Crate | Responsibility | Lines | Tag |
|---|---|---|---|
| `ullm-core` | Shared types, error taxonomy, protocol IDs | ~250 | v0.1.0 |
| `ullm-crypto` | ML-KEM-768 + X25519 hybrid KEX, XChaCha20-Poly1305 AEAD, HKDF-SHA-256, per-chunk symmetric ratchet + DH/Triple-Ratchet | ~600 | v0.1.0 |
| `ullm-wire` | Binary frame codec + 64-slot sliding-window anti-replay | ~400 | v0.1.0 |
| `ullm-handshake` | PQXDH-shaped 1-RTT state machine, transcript hash, REPORT_DATA binding | ~400 | v0.1.0 |
| `ullm-attest` | Evidence envelope, TDX/SEV-SNP/NRAS parsers, ECDSA-P256 signature verification, RealVerifier with measurement-pin policy | ~900 | v0.1.0 |
| `ullm-tls` | rustls 0.23 + rustls-post-quantum configs (PQ-hybrid X25519MLKEM768), self-signed cert generation, fingerprint pinning | ~250 | v0.1.0 |
| `ullm-zk` | Halo2 LayerCircuit: matmul + Poseidon-`ConstantLength<8>` commitments of `x` and `y` per layer, IPA backend | ~600 | v0.1.0 |
| `ullm-kvcloak` | KV-Cloak matrix transform (`P·L·v` over `Fp`), Petridish SPD process model, AES-GCM-SIV sealed-blob wrap | ~700 | v0.1.0 |
| `ullm-receipts` | Ed25519-signed usage receipts | ~150 | v0.1.0 |
| `ullm-mpc` | Honest-but-curious 2PC over the synthetic model via additive shares | ~300 | v0.1.0 |
| `ullm-overlay` | 3-hop onion routing (nested ChaCha20-Poly1305 layers) | ~350 | v0.1.0 |
| `ullm-threshold` | FROST-Ed25519 t-of-n threshold signing | ~250 | v0.1.0 |
| `ullm-transparency` | Append-only log, signed tree heads, inclusion proofs, witness cosignatures | ~600 | v0.1.0 |
| `ullm-federation` | Multi-vendor k-of-n attestation, reproducible-build admission, provider pool | ~450 | v0.1.0 |
| `ullm-model` | Deterministic synthetic 8×8×8 model (placeholder for real LLM) | ~250 | v0.1.0 |

Total Rust LOC under review: ~6,500.

## What's NOT in scope

- Phase 1 deployment scripts (Slice 3) — operational, not cryptographic.
- The synthetic `ullm-model` weights — placeholder for real model in Slice 1.
- Live vendor PCS / OCSP integration — Slice 2 next milestone.
- The `ullm-bench` crate — measurement only.

## Threat model

See `docs/threat-model.md` (separate). Cliffs notes:

- **Adversary T1 (curious provider)**: Confidentiality required against the gateway operator.
- **Adversary T2 (active malicious provider)**: Integrity required against forged or replayed bundles.
- **Adversary T3 (compromised TEE)**: Reduce trust to intersection of TEE attestation + zkML.
- **Adversary T4 (nation-state / vendor PKI coercion)**: Mitigated by Phase 4 multi-vendor k-of-n + MPC + non-collusion.

## Threats out of scope for this audit

- Side-channel attacks against the underlying CPU/GPU (microarchitectural,
  power, EM). Mitigations are deployment-time.
- Live model weights and inference correctness (depends on Slice 1).
- Vendor PKI mis-issuance (handled at the deployment layer).

## What the auditor should look for

### Cryptographic primitive misuse
- Nonce reuse in AEAD (impossible by construction via per-chunk ratchet — verify)
- Constant-time guarantees in `ullm-crypto` and `ullm-overlay`
- KAT compliance: FIPS 203 ML-KEM-768 test vectors, RFC 8439 ChaCha20-Poly1305 vectors
- KyberSlash fault-attack resistance in the `ml-kem` crate

### Protocol soundness
- PQXDH handshake transcript binding (REPORT_DATA covers nonce + pre-keys + weight commitment)
- ServerHello signature payload coverage
- Mid-stream `key_update` state machine correctness (`ullm-tee::service`)
- Replay window edge cases at epoch boundaries

### ZK soundness
- `ullm-zk::layer::LayerCircuit` matmul gate correctness
- Poseidon-`ConstantLength<8>` in-circuit vs. native equivalence (already tested in `ullm-model::commit::tests::matches_zk_layer_native_hash`)
- Fixed-column W, b handling under arbitrary witness inputs
- Cross-binding `report_data` ⇄ activation commitments at the receipt boundary

### MPC / threshold / overlay
- Single-share information-theoretic security in `ullm-mpc`
- FROST-Ed25519 implementation correctness (we use ZcashFoundation `frost-ed25519` — itself audited; we audit our integration)
- Layer-strip ordering correctness in `ullm-overlay`

### Memory hygiene
- `Zeroize + ZeroizeOnDrop` on every secret type
- No `Clone` of a secret without intentional zeroization
- `unsafe` block census (target: zero `unsafe` blocks in the audited crates)

## Deliverables expected from auditor

1. **Findings report** — severity-graded (critical/high/medium/low/info) findings with reproducer paths.
2. **Remediation review** — sign-off after we land fixes.
3. **Public audit report** (redacted as needed) — published in `docs/audit/REPORT-v0.1.0.md`.

## Audit packet contents

The `audit-packet.tar.gz` build script (`scripts/build_audit_packet.sh`)
produces:

- Snapshot of the workspace at the audit tag.
- This SCOPE document.
- `THREAT-MODEL.md`.
- `RECENT-CHANGES.md` — commit log since last audit (none for v0.1.0).
- `DEPENDENCY-SBOM.md` — full third-party manifest.
- `KAT-VECTORS.tar.gz` — pinned test vectors for every primitive.
- `BUILD-INSTRUCTIONS.md` — reproducible build steps.

## Reference audit firms (priority order)

1. **Trail of Bits** — strong Rust cryptography track record (rustls, libsignal audits)
2. **NCC Group** — broad cryptographic + protocol depth (PQ-hybrid TLS audits)
3. **Cure53** — focused, fast turnaround
4. **Kudelski Security** — Halo2-specific zkML audit history
5. **Project Eleven** (formerly Quarkslab) — PQ crypto specialist

## Timeline

- **Code freeze at the audit tag**: D-day.
- **Auditor execution window**: ~4–6 weeks calendar.
- **Internal remediation**: 2–3 week buffer.
- **Public report**: D + 8 weeks.

## Contact

`audit@<org>` — single inbound mailbox. Responsible for:
- Scoping calls with prospective firms.
- NDA handling.
- Day-to-day liaison during the audit.
- Remediation coordination.

## Stop-ship findings

Any **critical** finding blocks the v0.1.0 release. Any **high** finding
blocks until remediation is implemented + re-tested. Mediums are tracked
with timeboxed remediation plans.
