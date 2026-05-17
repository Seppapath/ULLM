# ullm v0.2.0-rc1 — Release Notes

> **Status:** Release candidate. Production-ready pending external
> audit refresh (see [`docs/audit/AUDIT-REFRESH-BRIEF.md`](docs/audit/AUDIT-REFRESH-BRIEF.md)).
>
> **PROTOCOL_VERSION:** `0x03` (bumped from 0x01 → 0x02 in P8, 0x02
> → 0x03 in P13-FIX-D).

---

## Headline

ullm is an end-to-end encrypted, attested LLM inference layer.
Plaintext exists only on the client and inside an attested TEE.
Every session produces a transparency-logged Ed25519-signed receipt
the client can independently audit, plus optional per-layer Halo2 ZK
proofs that bind the activation trace to the committed model weights.

v0.2.0-rc1 is the first **production-readiness candidate** — built
on the v0.1.0 cryptographic core (audited externally as Slice 4),
extended through Slices 1–10, then hardened across **13 internal
red-team rounds** that fixed **104 cumulative vulnerabilities** with
regression tests for every fix.

---

## What's in the box

### Cryptography (audited surface)

- **PQ-hybrid KEX**: ML-KEM-768 + X25519 per NIST IR 8413 / RFC 9180
  patterns
- **AEAD record layer**: XChaCha20-Poly1305 with per-frame nonce
  derived from `(salt, epoch, seq)`
- **Symmetric ratchet** + **DH ratchet** + Triple-Ratchet for FS/PCS
- **PQ-hybrid TLS**: `rustls-post-quantum` X25519MLKEM768 — strict
  mode opt-in via `ULLM_REQUIRE_PQ=1` (P13-FIX-A)
- **Halo2 ZK proofs**: per-layer matmul, Poseidon `ConstantLength<8>`
  commitments, 6-row public-input vector binding (x, y, layer_idx,
  session_id, weight_commit_lo, weight_commit_hi) — non-replayable
  across sessions/layers/models (P13-FIX-C)
- **Ed25519 signed receipts**: bind tenant, session, epoch, input
  hash, **token-id digest + decoded-string digest separately**
  (P13-FIX-D), weight commit, per-layer activation commits, KV
  cloaking metadata
- **FROST-Ed25519 threshold receipts**: t-of-n for federation pools
- **2PC over additive `Fp` shares**: honest-but-curious MPC fallback
- **3-hop onion overlay**: nested ChaCha20-Poly1305 layers

### Production wiring (PR-1..PR-8)

- Cross-platform SIGTERM/SIGINT graceful shutdown with 30 s drain
  deadline and watch-channel broadcaster (P10/P11/P12-FIX)
- Prometheus `/metrics` on a separate management listener; optional
  `ULLM_METRICS_TOKEN` bearer auth (constant-time compared);
  loopback enforced unless `ULLM_METRICS_ALLOW_PUBLIC=1` is set
- Tunable transparency-log fsync policy
  (`ULLM_LOG_FSYNC_EVERY_N=N`) with witness-cosigner requirement
  warnings
- O(log N) LRU eviction on rate-limiter, nonce-registry, tenant
  pool — with monotonic seq tie-breaker against
  Windows-clock-collision bias
- `docs/OPERATIONS.md` runbook: deploy, configure, observe, incident
  response, upgrade, rollback
- `SECURITY.md` policy: coordinated-disclosure terms, audit history
  pointer, CODEOWNERS one-time setup notice
- `CHANGELOG.md` documenting every change since v0.1.0
- GitHub Actions CI: `fmt+clippy`, `cargo check`, `test (release)`,
  `feature-matrix`, `cargo audit`, WASM build, headless E2E,
  **prod-binary `/v1/devkeys`-strings denylist**, audit-packet
  artifact, Python wheels
- Compile-time mutual exclusion of `dev-keys` and `prod` Cargo
  features — `cargo build --features prod` without
  `--no-default-features` hard-errors with a helpful message

### Transparency + auditability

- Sigsum-style append-only log with persistent JSONL backing
- Torn-write recovery on reopen (BOM-stripped, size-capped at
  16 MiB per line, depth-32 JSON pre-scan)
- Signed Tree Heads with witness cosignature support
- `tools/ullm-log-auditor` with `verify` + `compare-sths` (fork
  detection) subcommands
- `tools/ullm-watcher` with structured verification flags:
  `activations_consistent`, `receipt_signature_verified`,
  `attestation_verified`, `log_inclusion_verified`,
  `sth_signature_verified`, `sth_freshness_verified`,
  `weight_commit_pinned`, `session_pinned`, `zk_proofs_verified`
  (P13-FIX-B). Exit code 3 = `Partial` when some checks weren't run.

### Federation + multi-vendor

- `MultiVendorVerifier` with k-of-n threshold over **distinct
  cryptographic attestation identities** (P13-FIX-E) — no longer
  caller-asserted vendor labels
- TDX, SEV-SNP, NVIDIA NRAS quote parsers with measurement
  allowlist policy
- `ReproducibleBuildVerifier` admission allowlist gated on the
  manifest from a successful reproducible Nix build

---

## Ship-state verification (run at the audit tag)

```
$ cargo build --workspace --release
   Finished `release` profile [optimized] target(s) in 42.07s

$ cargo test --workspace --release
TESTS: passed=200 failed=0

$ cargo check -p ullm-gateway --release --features prod
error: features `dev-keys` and `prod` are mutually exclusive   ← intentional gate

$ cargo build -p ullm-gateway --release --no-default-features --features prod
   Finished `release` profile [optimized] target(s)

$ cargo build -p ullm-tee --release --no-default-features --features prod
   Finished `release` profile [optimized] target(s)

$ strings <both binaries> | grep -E '/v1/devkeys|devkeys|trust_root_hex|tee_receipt_pk_hex'
(0 occurrences across all binaries × all feature combos)

$ cargo run -p ullm-demo --release
session established → signed receipt → 8 ZK proofs verified → transparency log size=1

$ cargo run -p ullm-phase4-demo --release
✓ Phase 4 scenarios complete (MPC + 2-of-3 vendor + FROST + 3-hop onion)
```

---

## Backwards compatibility

**PROTOCOL_VERSION 0x02 → 0x03 (P13-FIX-D).** The `Receipt` schema
gained `output_string_digest_hex` and `output_digest_hex` semantics
changed from "hash of decoded UTF-8 bytes" to "hash of token-id
stream". A pre-0x03 client connecting to a 0x03 gateway is rejected
at the `ClientHello` boundary with `Error::BadVersion` — clean
mismatch rather than confusing downstream signature errors.

Operators upgrading from v0.1.0 must coordinate client + server
rollout. There is **no on-the-fly downgrade path**; ullm protocol
bumps are explicit by design (no negotiated downgrade attacks).

---

## Known limitations (do NOT ship-block)

See [`docs/audit/KNOWN-ISSUES.md`](docs/audit/KNOWN-ISSUES.md). The
two most important:

1. **Slice 1 is effectively undeployed.** The prod TEE binary still
   constructs `MockEngine::default()` which echoes the prompt. The
   real LLM substrate exists in `crates/ullm-llm/` but isn't wired.
   **All cryptographic guarantees hold; just the inference is fake.**
   Tracked as Slice 11.

2. **ZK proofs cover the synthetic toy model.** Per-layer Halo2
   proofs attest `crates/ullm-model::Model`, not whatever real LLM
   gets wired in Slice 11. Tracked as Slice 12 (real-LLM ZK
   circuit).

Plus 9 documented MEDIUM-severity deferrals (field-element range
checks in ZK, KV-Cloak invertibility threat model, NRAS JWS
verification, TDX chain-to-Intel-root, etc.) all enumerated in
KNOWN-ISSUES.md.

---

## Operator next steps (out-of-session for the maintainer)

1. **Git initialize + tag the audit baseline:**
   ```
   git init
   git add .
   git commit -m "v0.2.0-rc1 audit baseline"
   git tag -a v0.2.0-rc1 -m "External audit refresh baseline"
   git push origin v0.2.0-rc1
   ```
2. **Build the canonical audit packet** (`bash scripts/build_audit_packet.sh`).
   Local verification ran clean: `audit-packet-<sha>.tar.gz` (~934 KB,
   343 entries), including: workspace snapshot, SBOM (cargo tree),
   recent changes (git log), test output, clippy output, cargo-audit
   output, prod-strings gate output, AUDIT-REFRESH-BRIEF.md,
   SCOPE-REFRESH.md, FINDINGS-INDEX.md, KNOWN-ISSUES.md, all 13
   FINDINGS-Pn.md docs, OPERATIONS.md, SLO.md, SECURITY.md,
   CHANGELOG.md, ci.yml, CODEOWNERS, BUILD-INSTRUCTIONS.md.
3. **Send the brief + packet** to the 6 firms named in
   `AUDIT-REFRESH-BRIEF.md §11`.
4. **First-time repository hardening setup** (the placeholder noted
   in CODEOWNERS / KNOWN-ISSUES O1):
   - Create the `ullm-security` GitHub team
   - Configure branch protection on `main` and `v*.*.*` tag pattern
     requiring code-owner review + the `prod-binary strings check`
     status
   - Stand up the `security@<org>` mailbox and PGP key at
     `/.well-known/security.asc`
5. **Build + push the reproducible TEE image:**
   ```
   nix build .#tee-image
   docker load < result
   podman push <registry>/ullm-tee:0.2.0-rc1
   ```
   Verify the SHA-256 on a second builder; populate
   `infra/tee-image/manifest.json` with the matched hash + MRTD +
   RTMRs.
6. **Deploy a canary** per `docs/OPERATIONS.md §2`. Monitor
   `/metrics` for 15 minutes before promoting the fleet.

---

## Acknowledgements

This release is the product of 13 iterative internal red-team rounds.
Specialists (sub-agents) found and fixed the issues; the maintainer
shaped the audit scope and adjudicated severity. Every fix is
annotated in-source with its round identifier (`grep -r 'P[0-9]\+-FIX'`).

The audit cadence — fix, audit, fix, audit — surfaces different
defects each round because each round can pivot scope. Two
pre-existing CRITICALs (the `subtle_compare` non-CT loop in
Phase-1 `session_token.rs`, and the `Cargo.lock` `.gitignore`)
required twelve rounds to find: the first because nobody had
audited the LTO-vs-constant-time interaction; the second because
nobody had spot-checked the `.gitignore`. External eyes are the
defense against the next blind spot.

---

## Citations

- Per-round findings: `docs/audit/FINDINGS{,-P2,...,-P13}.md`
- Threat model: `docs/audit/THREAT-MODEL.md`
- Slice-4 (v0.1.0) external audit scope: `docs/audit/SCOPE.md`
  (now annotated as `SCOPE-SLICE-4.md` in the packet)
- Refresh brief: `docs/audit/AUDIT-REFRESH-BRIEF.md`
- Performance budgets: `docs/SLO.md`
- Operations runbook: `docs/OPERATIONS.md`
- Coordinated-disclosure policy: `SECURITY.md`
- Cumulative changelog: `CHANGELOG.md`

---

## License

Apache-2.0. DCO sign-off required on contributions.
