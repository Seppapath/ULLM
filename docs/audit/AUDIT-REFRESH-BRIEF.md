# External Audit Refresh — Auditor Brief

> **Status**: Open call. Sent to candidate audit firms alongside the
> packaged `audit-packet-<sha>.tar.gz` produced by
> `scripts/build_audit_packet.sh`.
>
> **Prior audit**: Slice 4 covered the v0.1.0 cryptographic core. This
> refresh covers the delta since: Slices 1–10 (real LLM substrate,
> real vendor PKI, reproducible Nix, etc.), production-deployment
> wiring (PR-1..PR-8), and thirteen internal red-team rounds (P1–P13).

---

## 1. Project elevator pitch

ullm is an end-to-end encrypted, attested LLM inference layer.
Plaintext exists only on the client and inside an attested TEE.
Every session produces a transparency-logged, Ed25519-signed receipt
the client can independently audit, plus optional per-layer Halo2
ZK proofs that bind the activation trace to the committed model
weights.

PROTOCOL_VERSION at the audit tag: **0x03** (bumped from 0x01 → 0x02
in P8, 0x02 → 0x03 in P13-FIX-D).

Workspace version at the audit tag: **0.2.0-rc1**.

---

## 2. What's new since the Slice 4 audit

See [`SCOPE-REFRESH.md`](SCOPE-REFRESH.md) for the full delta. Highlights:

| Slice | What changed | Crates / files |
|---|---|---|
| 1 | Real LLM substrate (Phi-3-mini / Qwen-2.5-0.5B) via candle | `crates/ullm-llm/` (NEW); **important**: not yet wired into prod TEE binary — see [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md) |
| 2 | Real TDX + SEV-SNP + NRAS verifier with vendor PKI chains | `crates/ullm-attest/src/{tdx,snp,nvidia,real_verifier}.rs` |
| 3 | Reproducible Nix flake; Azure CC + Phala deployment recipes | `infra/tee-image/flake.nix`, `infra/{azure-cc,phala}/` |
| 5 | Production PQ-hybrid TLS via `rustls-post-quantum 0.2` | `crates/ullm-tls/` — **strict-PQ mode** added in P13-FIX-A |
| 6 | Criterion benchmarks + per-component SLOs | `crates/ullm-bench/`, `docs/SLO.md` |
| 7 | Sigsum-style transparency log with witness cosignatures + auditor tool | `crates/ullm-transparency/`, `tools/ullm-log-auditor/` |
| 8 | Petridish SPD + real KV-Cloak inside attention | `crates/ullm-kvcloak/` |
| 9 | Mid-stream `key_update` under sustained load | `crates/ullm-tee/src/service.rs` |
| 10 | Phala DePIN integration | `crates/ullm-phala/`, `infra/phala/` |

Production wiring (PR-1..PR-8):

- PR-1: Cross-platform SIGTERM/SIGINT graceful shutdown + drain deadlines
- PR-2: Prometheus `/metrics` on both binaries (separate mgmt listener,
  P9/P10/P11 hardening rounds)
- PR-3: Tunable fsync policy on transparency log
- PR-4: O(log N) LRU eviction on rate-limiter / nonce-registry /
  tenant-pool
- PR-5: `docs/OPERATIONS.md` runbook
- PR-6: `SECURITY.md` + `CHANGELOG.md`
- PR-7: GitHub Actions CI (fmt+clippy, tests, feature-matrix,
  cargo-audit, prod-binary `/v1/devkeys`-strings gate, headless
  WASM E2E)
- PR-8: Workspace version bump to 0.2.0-rc1

Internal red-team rounds (P1–P13): **104 confirmed vulnerabilities
fixed** across thirteen iterative audits, each followed by an
engineered-fix round. Full per-round catalogues in
`FINDINGS{,-P2,...,-P13}.md`. Index in
[`FINDINGS-INDEX.md`](FINDINGS-INDEX.md).

---

## 3. What to audit — primary surface

Same crate set as Slice 4 plus the new crates. Total Rust LOC under
review: **~9,200**.

| Crate | Slice-4 audited? | Lines | Notes |
|---|---|---|---|
| `ullm-core` | yes | ~600 | NEW: `shutdown::ShutdownBroadcaster`, `validate_metrics_addr` |
| `ullm-crypto` | yes | ~700 | Per-frame AEAD + ratchet + DH-ratchet unchanged |
| `ullm-wire` | yes | ~450 | Replay window unchanged |
| `ullm-handshake` | yes | ~450 | PQXDH transcript + ServerHello sig unchanged |
| `ullm-attest` | yes | ~1100 | **MAJOR**: real TDX/SNP/NRAS parsers (Slice 2); new `Verifier::attestation_identity` (P13-FIX-E) |
| `ullm-tls` | yes | ~350 | **NEW**: `strict_pq_provider`, `server_config_strict_pq` (P13-FIX-A) |
| `ullm-zk` | yes | ~750 | **MAJOR**: 6-row instance vector with layer/session/weight binding (P13-FIX-C) |
| `ullm-kvcloak` | yes | ~750 | Phase 8 work; threat model documented |
| `ullm-receipts` | yes | ~250 | **CHANGED**: `output_string_digest_hex` field (P13-FIX-D) |
| `ullm-mpc` | yes | ~300 | unchanged |
| `ullm-overlay` | yes | ~350 | unchanged |
| `ullm-threshold` | yes | ~250 | unchanged |
| `ullm-transparency` | yes | ~900 | NEW: persistent JSONL + fsync policy + torn-write recovery |
| `ullm-federation` | yes | ~550 | **MAJOR**: dedup by attestation identity (P13-FIX-E) |
| `ullm-model` | yes | ~300 | synthetic toy; unchanged |
| `ullm-llm` | NO (NEW) | ~250 | real-LLM crate; see KNOWN-ISSUES |
| `ullm-tee` | yes | ~1100 | many changes — `TokenChunk`, metrics router, mgmt listener |
| `ullm-gateway` | yes | ~900 | new STH cache, metrics router, rate-limit LRU |
| `ullm-client` | yes | ~700 | TLS pinning + watcher integration |
| `ullm-phala` | NO (NEW) | ~200 | DePIN; mostly orchestration |

**Out of scope:**
- `crates/ullm-bench/` — measurement only
- `tools/ullm-demo`, `tools/ullm-phase4-demo` — example code
- `bindings/python`, `bindings/ts` — FFI; review for memory safety
  but not protocol correctness (auditor's choice)
- `infra/` — deployment recipes, operationally not cryptographically
  scoped (but reproducibility verification is welcome)

---

## 4. Known issues — do NOT flag as new findings

See [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md). The big two:

1. **Slice 1 is effectively undeployed**: the production `ullm-tee`
   binary still constructs `MockEngine::default()` which literally
   echoes the prompt. `RealLlmEngine` in `ullm-llm` is reachable
   only from test/demo code. **This is roadmap Slice 11, not a
   bug.** All cryptographic guarantees (encryption, attestation,
   transparency, receipts) hold regardless — the mock just doesn't
   run a useful model.

2. **ZK proofs cover the synthetic toy model**. The per-layer Halo2
   proofs in `ullm-zk` attest the 8-layer × 8-wide synthetic
   `ullm-model::Model`, not whatever real LLM may eventually be
   wired in. Even after Slice 11 wires `RealLlmEngine`, the system
   runs in "attestation-only" mode for verifiability until Slice 12
   lands a real-LLM ZK circuit. P13-FIX-C's session/layer/weight
   binding is sound for what the proofs *do* attest.

Plus ~12 documented MEDIUM-severity items deferred as roadmap work
(field-element range checks in ZK, KV-Cloak invertibility threat
model, etc.) — see KNOWN-ISSUES.md.

---

## 5. Threat model

Unchanged from Slice 4. See `THREAT-MODEL.md` in this packet for the
adversary tiers and trust assumptions.

**One refinement**: T3 (compromised TEE) now includes the case of a
*single-vendor compromise* against multi-vendor deployments. P13-FIX-E
binds vendor identity to cryptographic material (attestation key
fingerprint) rather than caller-asserted `kind` labels, closing the
"one TDX compromise pretends to be two vendors" path.

---

## 6. Verification baseline

The auditor should be able to reproduce this baseline locally:

```bash
git clone <repo-url> && cd ullm
git checkout v0.2.0-rc1   # or the tag matching the audit packet

# Build
cargo build --workspace --release
# Expect: 0 warnings, 0 errors.

# Tests
cargo test --workspace --release
# Expect: 200 passed, 0 failed.

# Prod-feature compile-time gate (intentional compile error)
cargo check -p ullm-gateway --release --features prod
# Expect: compile_error! firing for dev-keys+prod mutual exclusion.

cargo check -p ullm-gateway -p ullm-tee --release --no-default-features --features prod
# Expect: clean compile.

# Supply-chain audit
cargo install --locked cargo-audit
cargo audit --deny warnings
# Expect: clean (no known advisories against committed Cargo.lock).

# Prod-binary dev-string leakage check
cargo build --release --bin ullm-gateway --no-default-features --features prod
cargo build --release --bin ullm-tee     --no-default-features --features prod
for needle in "/v1/devkeys" "devkeys" "trust_root_hex" "tee_receipt_pk_hex"; do
  for bin in target/release/ullm-gateway target/release/ullm-tee; do
    strings "$bin" | grep -cF "$needle"
    # Expect: 0 for each (bin, needle) pair.
  done
done
```

Reference machine: see `docs/SLO.md`.

---

## 7. Deliverables expected

1. **Per-round findings report** — severity-graded
   (Critical/High/Medium/Low/Info) with file:line citations and
   reproducer paths.
2. **Cryptographic spec compliance attestation** for the primitives
   in scope (ML-KEM-768, XChaCha20-Poly1305, HKDF-SHA-384, Ed25519,
   FROST-Ed25519, X25519MLKEM768, Halo2/IPA, Pasta curves).
3. **Remediation review** — sign-off after we land fixes.
4. **Public audit report** (redacted as needed) published in
   `docs/audit/EXTERNAL-AUDIT-REPORT-v0.2.0-rc1.md`.

---

## 8. Severity rubric

| Severity | Definition |
|---|---|
| **Critical** | Directly breaks a confidentiality, integrity, authenticity, or freshness guarantee the protocol promises. Plaintext recovery, key extraction, signature forgery, undetectable log forks, cross-tenant cache pivots. Blocks v0.2.0 release. |
| **High** | A multi-step attack with the same outcome as Critical given attainable prerequisites. Or: a defense-in-depth layer that an attacker must defeat to advance a Critical. Blocks v0.2.0 until remediation. |
| **Medium** | Weakens the system against follow-on bugs or operator mistakes; not exploitable standalone. Tracked with timeboxed remediation. |
| **Low** | Hygiene, fail-loud, developer-friendliness. Not gating. |
| **Info** | Observations, suggestions, code-quality. |

Findings that are **already documented** in `KNOWN-ISSUES.md` should
be filed as a comment cross-referencing that document, not as a
new finding.

---

## 9. Coordinated-disclosure terms

- **Embargo window**: 90 days from acknowledgement, unless mutually
  extended. We won't release without the auditor's sign-off; the
  auditor agrees not to publish before the embargo.
- **Severity-based escalation**:
  - Critical: 7-day fix target
  - High: 30-day fix target
  - Medium: 90-day fix target
  - Low: rolled into next scheduled release
- **Credit**: full credit in the public report and CHANGELOG, unless
  the auditor opts for anonymity.

---

## 10. Submission format

- One Markdown file per finding under
  `submissions/<finding-id>.md` with: severity, title, scope path,
  attack scenario, reproducer (test or trace), suggested fix.
- One `summary.json` enumerating findings.
- Optional: a `consistency-tests/` directory with new test cases the
  auditor would like merged into the workspace test suite.

---

## 11. Reference audit firms (priority order — same as Slice 4)

1. **Trail of Bits** — strong Rust cryptography track record (rustls,
   libsignal audits)
2. **NCC Group** — broad cryptographic + protocol depth (PQ-hybrid
   TLS audits)
3. **Cure53** — focused, fast turnaround
4. **Kudelski Security** — Halo2-specific zkML audit history
5. **Project Eleven** (formerly Quarkslab) — PQ crypto specialist
6. **Zellic** — recent strong work in Rust + ZK

---

## 12. Timeline

- **Code freeze at audit tag**: `v0.2.0-rc1` (already tagged).
- **Auditor execution window**: 6–10 weeks calendar (broader scope
  than Slice 4 — 9,200 LOC vs 6,500).
- **Internal remediation buffer**: 3–4 weeks.
- **Public report**: D + 12 weeks.

---

## 13. Contact

`security@<org>` — single inbound mailbox. Responsibilities:
- Scoping calls + NDA
- Day-to-day liaison
- Remediation coordination
- Public-report publication

Out-of-band channel: PGP key at
`https://<org>/.well-known/security.asc` (rotates annually).

---

## 14. What we particularly want fresh eyes on

The internal red-team caught its own work in P9–P12 (curve flattened),
but P13's pivot to underexplored angles surfaced 5 new CRITICALs
including two pre-existing defects (PQ downgrade in Slice 5,
caller-asserted vendor dedup in Slice 5). The audit cadence reaches
diminishing returns when targets repeat; external eyes are the
strongest defense against blind spots.

Specifically the auditor's attention is welcomed on:

- **Halo2 circuit soundness** under the new 6-row public-input
  vector (P13-FIX-C). We added layer-idx + session-id +
  weight-commit bindings via advice-only `load_pub_witness`; we want
  an independent check that the constrain_instance wiring is
  complete and the permutation argument actually enforces what we
  claim.
- **Vendor-PKI parsers** in `ullm-attest`. P2 fuzzed them once but
  Slice 2 added significant new parsing surface (TDX SGX-style
  signature chain, AMD VCEK, NVIDIA JWS) — these have not had
  adversarial-input audit since landing.
- **Real LLM substrate** in `ullm-llm`, even though it isn't wired
  into prod yet. We'd rather catch defects before Slice 11 wires it
  than after.
- **Cross-crate invariants**. Each crate has its own correctness
  tests; the boundary between them (e.g., does the receipt's
  `weight_commit` match what the attestation evidence's `report_data`
  pins?) is harder to test in isolation.

Thank you.
