# Internal Red-Team Findings Index (P1 → P13)

One-line summary per round + click-through to the full findings doc.
**104 confirmed vulnerabilities fixed** across thirteen iterative
audits.

| Round | File | Findings | Severity range | One-line summary |
|---|---|---|---|---|
| P1 | [`FINDINGS.md`](FINDINGS.md) | 8 | High/Med/Low | First-pass: hybrid_decap panic on malformed ML-KEM ciphertext, transcript binding gaps, replay-window soundness, dev-only endpoint leakage. |
| P2 | [`FINDINGS-P2.md`](FINDINGS-P2.md) | 11 | High/Med | Ratchet/epoch state desync, ZK Fiat-Shamir transcript binding, attestation parser fuzzing, Merkle proof crafting defenses. |
| P3 | [`FINDINGS-P3.md`](FINDINGS-P3.md) | 11 | High/Med/Low | Concurrency / TOCTOU, side channels, AAD coverage expansion, multi-tenant pivot audit (P3-4 introduced eviction-cooldown). |
| P4 | [`FINDINGS-P4.md`](FINDINGS-P4.md) | 8 | High/Med | Protocol state-confusion eliminated, key-separation invariants, signature-payload domain separation. |
| P5 | [`FINDINGS-P5.md`](FINDINGS-P5.md) | 5 | High/Med | ECDSA low-s normalization (P-256/P-384), network-malice probes, watcher semantic correctness. |
| P6 | [`FINDINGS-P6.md`](FINDINGS-P6.md) | 4 | Med/Low | WASM JS-side audit, `now_unix_or_zero` fail-closed time, zero `unsafe` on security-critical paths. |
| P7 | [`FINDINGS-P7.md`](FINDINGS-P7.md) | 1 | Med | STH/log-entry/receipt canonical-JSON consistency, lock-type review, `cargo audit` on locked tree. |
| P8 | [`FINDINGS-P8.md`](FINDINGS-P8.md) | 2 | Med | PROTOCOL_VERSION bump 0x01→0x02 for cumulative wire deltas; tenant pool LRU cap. |
| P9 | [`FINDINGS-P9.md`](FINDINGS-P9.md) | 7 | High/Med | First red-team on PR-1..PR-8: STH signs unsynced log entries, nonce-registry HashMap/BTreeSet desync, /metrics on public TLS listener, compile_error mutual exclusion. |
| P10 | [`FINDINGS-P10.md`](FINDINGS-P10.md) | 8 | High/Med | Red-team on P9 fixes: Notify registration race, CI matrix self-break via downstream defaults, denylist false-positive on `weight_commit_hex`. |
| P11 | [`FINDINGS-P11.md`](FINDINGS-P11.md) | 10 | High/Med | Red-team on P10 fixes: `wait()` Err swallowing, signal pre-spawn race, JSONL `read_to_end` DoS, unterminated-good-line append corruption. |
| P12 | [`FINDINGS-P12.md`](FINDINGS-P12.md) | 9 | High/Med | Supply-chain pivot: **Cargo.lock not committed**, **hand-rolled subtle_compare non-CT under LTO**, BOM-corrupted log unopenable. |
| P13 | [`FINDINGS-P13.md`](FINDINGS-P13.md) | 20 | **Critical**/High/Med | Underexplored-angle pivot: **5 CRITICALs** including PQ-hybrid downgrade silently permitted, watcher trust-without-verify, ZK proof cross-session replay, output_digest decoded-bytes binding, multi-vendor dedup by caller-asserted kind. |

## Notes for the external auditor

- The audit cadence pivoted scope between rounds. P9–P11 focused on
  newly-added code (deployment-readiness work), which yielded a
  flattening curve toward LOW severity. P12 pivoted to supply-chain
  + LTO and immediately found two pre-existing HIGHs. P13 pivoted
  to underexplored subsystems and found five CRITICALs (some
  pre-existing since early Slices).
- **P12 and P13 demonstrate the value of an external perspective.**
  An auditor who has not been deep in the codebase for 12+ rounds
  is likely to find similar pre-existing defects in places we've
  blind-spotted.
- Every finding has a regression test in the workspace test suite.
  `cargo test --workspace --release` should show **200 passed,
  0 failed** at the audit tag.
- Every fix is annotated with the round identifier (`P9-FIX-A`,
  `P13-FIX-C`, etc.) in source-code comments — grep for `P\d+-FIX`
  to inspect every fix landed.

## Convergence indicator at the audit tag

| Round | Findings per round | Cumulative |
|---|---|---|
| P1 | 8 | 8 |
| P2 | 11 | 19 |
| P3 | 11 | 30 |
| P4 | 8 | 38 |
| P5 | 5 | 43 |
| P6 | 4 | 47 |
| P7 | 1 | 48 |
| P8 | 2 | 50 |
| P9 | 7 | 57 |
| P10 | 8 | 65 |
| P11 | 10 | 75 |
| P12 | 9 | 84 |
| P13 | 20 | **104** |
