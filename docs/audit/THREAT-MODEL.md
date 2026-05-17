# Threat Model (Audit Companion)

See also: the per-phase design plans in `docs/phase{1..4}-design.md` (Google
Drive). This document is the executive summary the auditor needs.

## Adversary tiers

| Tier | Capability | Coverage in v0.1.0 |
|---|---|---|
| T1 (curious provider) | Read provider logs, employees | Confidentiality via PQ-hybrid record layer; receipts signed by TEE; transparency log of attestations |
| T2 (active malicious provider) | Forge bundles, replay handshakes, tamper packets | Attestation cross-binding to handshake; per-frame AEAD with monotonic seq; 64-slot replay window |
| T3 (compromised TEE / firmware) | Known CVE class against SEV-SNP / TDX / GPU CC | Hybrid trust: ZK proof of per-layer matmul + Poseidon commitment open against weight commitment in attestation; fraud-proof watcher detects activation tampering |
| T4 (nation-state, vendor PKI coercion) | Sign forged firmware/quotes via vendor key | Multi-vendor k-of-n attestation + MPC fallback for opt-out tenants; threshold-signed federation receipts |

## In-scope assets

1. **User prompt** — must remain confidential from gateway, network, and other tenants.
2. **Model output** — must remain confidential in transit; clients verify provenance via signed receipts + ZK proofs.
3. **KV-cache** — protected by per-tenant `MatrixCloakKey` (Slice 8); Petridish SPD process model isolates tenants.
4. **Long-term TEE identity key** — sealed in TEE; rotated periodically; FROST-threshold-signed in Phase 4 deployments.
5. **Model weights** — committed and bound into attestation `report_data`.
6. **Transparency log** — append-only; signed tree heads + witness cosignatures.

## Out-of-scope assets

- User identity (mitigated by Phase 4 onion overlay; out of cryptographic scope here).
- Model accuracy/alignment.
- Network metadata against a global passive adversary (Tor-like routing in
  Phase 4 partial).

## Trust assumptions

1. **Rust `std` + LLVM are not adversarial**. Standard build-chain trust.
2. **`ml-kem` and other RustCrypto crates implement their specs correctly**.
   These are the auditor's first review surface inside our deps.
3. **`frost-ed25519` (ZcashFoundation) is correct**. It has its own audit; we
   audit our wrapper.
4. **Vendor PKI (Intel PCS, AMD KDS, NVIDIA NRAS) is uncompromised at the
   moment of attestation verification**. Compromised PKI is T4 territory,
   handled by Phase 4.

## Wire-level invariants the auditor should validate

- `Frame.header.nonce_field == epoch_be || seq_be` (validated on decode).
- AAD covers the full 28-byte header.
- Per-frame AEAD nonce is `nonce_salt XOR (0×8 || epoch || seq)` — unique
  per (epoch, seq) pair under the same chain.
- DH ratchet step makes the post-rotation chain forward-secret against
  pre-rotation key compromise.

## Crypto-stack ⇄ protocol bindings

| Binding | Where | Tested |
|---|---|---|
| Channel ⇄ attestation | `ServerHello.attestation_evidence.report_data == SHA-512(nonce ‖ server_x25519_pk ‖ hash(hybrid_ss))` | `ullm-handshake::state::tests` |
| Channel ⇄ model | `report_data` includes `weight_commit` | `ullm-tee::identity::bundle_report_data` |
| Channel ⇄ TEE identity | Bundle is signed by Ed25519 identity key whose pubkey appears in attestation evidence | `ullm-client::attest_check::verify_bundle` |
| Receipt ⇄ model | `Receipt.weight_commit_hex` cross-verified against attestation's weight commit | `ullm-client::session::TokenStream::finalize` |
| Receipt ⇄ activations | `Receipt.activation_commits_hex[i]` is the public input the LayerCircuit opens | `ullm-client::tests::integration` |

## Known limitations the auditor should NOT flag as findings

These are deliberately deferred to later slices:

- **No live vendor PCS fetch** — Slice 2 next milestone. RealVerifier accepts
  caller-supplied measurement allowlists today.
- **Synthetic model only** — Slice 1. The cryptographic objects are real;
  the inference substrate is a placeholder.
- **In-memory onion overlay only** — Slice 10 + later milestones port to
  real network relays.
- **Sonobe folding is unaudited** — we don't use it in v0.1.0. Per-layer
  proofs ship without folding.
- **No HQC / Classic McEliece path** — Phase 5 only.

## Audit-time builds

```bash
cargo build --workspace --release  # builds everything
cargo test  --workspace --release  # all tests; expect 100+ passing, 0 failed
cargo clippy --workspace --release --all-targets  # zero errors
cargo bench -p ullm-bench          # baseline numbers vs. SLO doc
```

Reference machine: see `docs/SLO.md`.
