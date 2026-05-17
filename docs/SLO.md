# Per-Component SLO Document

Performance budgets across the ullm stack, sourced from the Criterion bench
suite in `crates/ullm-bench`. Each row lists the green / yellow / red
thresholds the bench target must meet on the reference hardware before a
release ship-gate clears.

## Reference machine

| Property | Value |
|---|---|
| CPU | x86_64, 8+ physical cores, AVX2 |
| RAM | 16 GB+ |
| Build profile | `release` (LTO, single-codegen-unit, panic=abort) |
| OS | Linux 6.x or Windows 11 24H2 |
| Rust | stable 1.78+ |

Benchmarks **must** be run with `cargo bench -p ullm-bench`. CI gates: any
bench breaching the **red** threshold blocks merge.

## Phase 1: Crypto and transport

| Bench target | Green | Yellow | Red | Phase-exit reference |
|---|---|---|---|---|
| `hybrid_encap` (ML-KEM-768 + X25519) | ≤ 200 µs | ≤ 400 µs | ≤ 800 µs | per-session, ≤ 1 ms |
| `hybrid_decap` (ML-KEM-768 + X25519) | ≤ 200 µs | ≤ 400 µs | ≤ 800 µs | per-session, ≤ 1 ms |
| `aead seal` (4 KiB) | ≥ 600 MB/s | ≥ 300 MB/s | ≥ 150 MB/s | stream throughput |
| `aead open` (4 KiB) | ≥ 600 MB/s | ≥ 300 MB/s | ≥ 150 MB/s | stream throughput |
| `aead seal` (16 KiB) | ≥ 1.2 GB/s | ≥ 600 MB/s | ≥ 300 MB/s | record-layer cap |
| `symmetric_ratchet_step` | ≤ 5 µs | ≤ 10 µs | ≤ 25 µs | per frame |
| `x25519_dh_ratchet_step` | ≤ 200 µs | ≤ 400 µs | ≤ 1 ms | per turn |
| `wire encode` (16 KiB) | ≥ 1 GB/s | ≥ 500 MB/s | ≥ 250 MB/s | record-layer |
| `wire decode` (16 KiB) | ≥ 1 GB/s | ≥ 500 MB/s | ≥ 250 MB/s | record-layer |
| `full_1rtt_handshake` | ≤ 1 ms | ≤ 2 ms | ≤ 5 ms | **Phase 1 M5: handshake RTT < 200 ms (network-dominated)** |

## Phase 2: Attestation + ZK output digest

| Bench target | Green | Yellow | Red |
|---|---|---|---|
| `mock_issue` | ≤ 200 µs | ≤ 400 µs | ≤ 1 ms |
| `mock_verify` | ≤ 200 µs | ≤ 400 µs | ≤ 1 ms |
| `tdx_quote_parse` | ≤ 50 µs | ≤ 100 µs | ≤ 250 µs |
| `snp_report_parse` | ≤ 50 µs | ≤ 100 µs | ≤ 250 µs |

## Phase 3: Per-layer ZK

| Bench target | Green | Yellow | Red | Phase-exit reference |
|---|---|---|---|---|
| `prove_one_layer` | ≤ 1 s | ≤ 3 s | ≤ 8 s | full 8-layer proof ≤ 10s (typical), ≤ 60s (worst) |
| `verify_one_layer` | ≤ 20 ms | ≤ 50 ms | ≤ 150 ms | full 8-layer verify ≤ 50 ms (Phase 3 M5) |

## Phase 4: MPC + onion

| Bench target | Green | Yellow | Red |
|---|---|---|---|
| `mpc_session_full_8layer` | ≤ 5 ms | ≤ 20 ms | ≤ 100 ms |
| `onion_wrap_3hop_256B` | ≤ 500 µs | ≤ 1.5 ms | ≤ 5 ms |
| `onion_route_3hop_256B` | ≤ 500 µs | ≤ 1.5 ms | ≤ 5 ms |

## End-to-end overhead

The **Phase 1 M5 exit criterion** is that encrypted-stream latency overhead
versus a plaintext baseline is **< 20%** for Llama-3.1-70B at 50 tok/s. With
the current synthetic model this is measured at startup only (one-shot model
run vs. one-shot plaintext stream); the real overhead measurement lands with
Slice 1 (real LLM substrate).

## Sample measured numbers (reference machine, May 2026)

These are observed values on a typical CI node, not committed thresholds.

| Bench | Measured |
|---|---|
| `hybrid_encap (ML-KEM-768 + X25519)` | ~77 µs |
| `hybrid_decap (ML-KEM-768 + X25519)` | ~74 µs |

## How to run

```bash
# Full sweep
cargo bench -p ullm-bench

# Single target
cargo bench -p ullm-bench --bench kex

# Quick (less stable but faster) variant
cargo bench -p ullm-bench --bench aead -- --quick
```

Criterion writes its HTML report under `target/criterion/`. CI archives that
directory as a build artifact.

## How to add a new bench

1. Add a new file under `crates/ullm-bench/benches/<topic>.rs`.
2. Register it in `crates/ullm-bench/Cargo.toml` under `[[bench]]`.
3. Add the bench target to this document with green/yellow/red thresholds.
4. The PR description must include the measured number on a reference
   machine and the diff against the previous baseline.

## Drift policy

A bench may move toward the **yellow** band without a special review if the
diff is < 10% slowdown and the cause is clear (e.g., new crypto agility
options). A move into the **red** band requires an explicit `BREAKING
PERF` tag in the PR title and reviewer sign-off from the SEC owner.
