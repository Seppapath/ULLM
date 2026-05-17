# Operations Runbook

This document is the production operator's reference for running ullm in
the wild. It covers deploy procedure, configuration knobs, observability,
incident response, and routine upgrade / rollback workflows.

The companion documents are:

- [`docs/SLO.md`](SLO.md) — performance budgets and bench gates.
- [`docs/audit/`](audit/) — cumulative security audit findings (P1–P8).
- [`infra/README.md`](../infra/README.md) — reproducible TEE-image builds
  + cloud recipes for Azure CC and Phala.

---

## 1. Deployment topology

ullm runs in two co-located processes per node:

```
                ┌────────────────────────────────────────┐
   client ─TLS─►│  ullm-gateway                          │
                │  (terminates rustls X25519MLKEM768)    │
                │  rate-limits + transparency log host   │
                └───────────────┬────────────────────────┘
                                │ plaintext loopback only
                                ▼
                ┌────────────────────────────────────────┐
                │  ullm-tee                              │
                │  PQXDH handshake + ratchet + LLM       │
                │  KV-Cloak + nonce registry             │
                │  attestation evidence signer           │
                └────────────────────────────────────────┘
```

**Critical invariant**: the TEE listener (`ULLM_TEE_ADDR`, default
`127.0.0.1:9001`) must NEVER bind to a non-loopback interface. The gateway
is the only thing that talks to it; anything else on the wire would
sidestep the rate limiter and the transparency log.

A node is one TEE-VM with both processes inside the same TDX/SEV-SNP guest.
For multi-tenant fleets, replicate that node behind an L4 load balancer and
let clients pin per-fingerprint via `ullm-watcher`.

---

## 2. Deploy procedure (first launch)

### 2.1. Build the TEE image reproducibly

```bash
# On builder A
nix build .#tee-image
sha256sum result | tee /tmp/image-a.sha
podman push <registry>/ullm-tee:0.2.0-rc1

# On builder B (different host, same flake rev)
nix build .#tee-image
sha256sum result | tee /tmp/image-b.sha

# These MUST match. If they don't, do not deploy. Investigate.
diff /tmp/image-a.sha /tmp/image-b.sha
```

Once the two SHAs agree, populate `infra/tee-image/manifest.json` with
`image_sha256`, MRTD, and RTMRs. The gateway's
`ReproducibleBuildVerifier` admission allowlist reads this manifest at
boot; an image whose measurement is missing from the manifest is refused.

### 2.2. Provision the host (Azure CC example)

```bash
cd infra/azure-cc
terraform init
terraform apply \
    -var=tee_image_uri=<registry>/ullm-tee:0.2.0-rc1 \
    -var=expected_image_sha256=<manifest.json:image_sha256>
```

The terraform module:
- Spins up `Standard_NCC40ads_H100_v5` (H100 CC-mode + Intel TDX).
- Mounts a persistent disk for the transparency log at `/var/lib/ullm/log/`.
- Opens **only** TCP/9000 (gateway TLS) to the internet — the TEE port is
  loopback-only on the VM.
- Renders a systemd unit file with the env vars below.

### 2.3. Set required environment variables

The gateway and TEE binaries read configuration purely from the env. All
values have safe defaults except where noted.

| Variable | Component | Default | Production setting |
|---|---|---|---|
| `ULLM_GATEWAY_ADDR` | gateway | `127.0.0.1:9000` | `0.0.0.0:9000` |
| `ULLM_TEE_URL` | gateway | `http://127.0.0.1:9001` | leave default |
| `ULLM_TEE_ADDR` | tee | `127.0.0.1:9001` | **never** non-loopback |
| `ULLM_LOG_PATH` | gateway | (in-memory) | **required** for prod, e.g. `/var/lib/ullm/log/transparency.jsonl` |
| `ULLM_LOG_FSYNC_EVERY_N` | gateway | per-append fsync | see § 3.3 |
| `ULLM_LOGGER_SEED` | gateway | random per boot | **required**: 32 hex bytes, kept in a sealed store |
| `ULLM_LOG_ID` | gateway | hex of logger pubkey | `ullm-mainnet-eu-1` style stable id |
| `ULLM_MODEL_SEED` | tee | all-zero (dev mock) | 32 hex bytes pinned to the model artifact |
| `RUST_LOG` | both | `info` | `ullm_gateway=info,ullm_tee=info` |

### 2.4. First-boot verification

After the systemd units come up, run the smoke test from a workstation:

```bash
# 1. Gateway TLS health
curl --cacert ca.pem https://<gateway>:9000/v1/transparency | jq .

# 2. Prometheus metrics
curl --cacert ca.pem https://<gateway>:9000/metrics

# 3. End-to-end watcher receipt
ullm-watcher \
    --gateway https://<gateway>:9000 \
    --model-seed <ULLM_MODEL_SEED> \
    --tee-pk $(curl -sS --cacert ca.pem https://<gateway>:9000/v1/transparency/head | jq -r '.logger_pk_hex') \
    --prompt 'health check' \
    --receipt /tmp/receipt.bin

# 4. Audit the receipt offline
ullm-log-auditor verify --head <head.json> --proof <proof.json>
```

If steps 1–3 succeed and step 4 returns `Ok`, the deploy is live.

### 2.5. Production-binary safety check

ullm has a `dev-keys` Cargo feature that exposes `/v1/devkeys` (the
underlying signing material) for tests. **The production binary must be
built without it.** The CI gate enforces this with a strings check —
operators should sanity-check before promoting an image:

```bash
strings $(which ullm-gateway) | grep -F '/v1/devkeys' && echo "FAIL: dev-keys leaked"
```

The expected output is empty. If `/v1/devkeys` is in the binary, do not
promote it.

---

## 3. Configuration deep-dive

### 3.1. Transparency log path

`ULLM_LOG_PATH` enables persistent JSONL-backed logging. Without it, the
log lives in memory and is discarded on restart — that defeats the
auditor's ability to verify a receipt from a prior session, so it must be
set in prod.

The directory must be on a disk that survives the VM reboot (the Azure CC
terraform module wires this up automatically). Backup the file daily;
loss of the log irreversibly breaks receipt verification for past
sessions.

### 3.2. Logger signing key (`ULLM_LOGGER_SEED`)

The Ed25519 signing key for Signed Tree Heads. **Rotation is operationally
expensive** — every client and witness pins this pubkey, so a rotation is
a coordinated event (see § 5.3). For the same reason:

- Keep the seed in a sealed store (HashiCorp Vault, AWS Secrets Manager,
  Azure Key Vault — whichever your platform offers).
- Never log it. The binary itself never prints the seed; only the public
  half is logged on startup.
- Back it up. Loss of the seed forces a key-rotation event for every
  consumer.

### 3.3. Fsync policy

Default: every successful `append` to the transparency log triggers
`f.sync_data()`. This caps log throughput at the disk's fsync rate
(~100 req/s on commodity SSDs, ~30k on NVMe with write-back cache).

For higher throughput, set `ULLM_LOG_FSYNC_EVERY_N` to a value ≥ 1:

| Value | Behavior |
|---|---|
| unset / `1` | per-append fsync. Default. Correct. |
| `8` | fsync every 8 appends. ~8× throughput. Up to 7 entries lost on crash. |
| `64` | fsync every 64 appends. ~64× throughput. Up to 63 entries lost on crash. |

**Safety requirement**: `Periodic` policy requires at least one witness
cosigner in your federation. The witnesses see the truncation on crash and
mark the affected STH range as untrusted, which keeps the audit chain
sound. Without witnesses, do not enable batched fsync — a crash silently
drops entries the gateway has already acknowledged to clients.

The `flush()` API is called automatically before the gateway signs a
fresh STH, so the *signed* head is always durable on disk regardless of
policy. Only the *intermediate* appends between two STH signings are at
risk.

### 3.4. Rate limiter

`RateLimiter` keys on tenant identity from the auth header. Defaults
(see `RateLimiterConfig::default()`):

- `bytes_per_sec`: 1 MB/s refill
- `burst_bytes`: 4 MB burst allowance
- `max_tenants`: 16,384 distinct tenants tracked

The bucket map is hard-capped at `max_tenants`. Once at cap, new tenants
evict the LRU bucket via `BTreeSet`-indexed O(log N) lookup. Operators
monitor `ullm_gateway_rate_limiter_buckets`; if that gauge sits at
`max_tenants` for prolonged periods, see § 5.2 (tenant flood).

Eviction-pressure protection: if the table is hot (eviction in the last
60 s), new buckets get only 1/8 of the burst allowance. This denies a
rotating-tenant-ID amplification attack.

### 3.5. Nonce registry

`NonceRegistry` rejects replayed attestation nonces within the
`NONCE_TTL` window (mirrors `ullm_core::NONCE_TTL_DEFAULT_SEC`). Capped
at 128k entries (~5 MiB worst case). GC runs amortized on every observe:
expired entries are pruned via a BTreeSet LRU index in O(k) where k is
the expired count.

No operator tuning required. Monitor `ullm_tee_nonce_registry_size` —
sustained growth toward the cap indicates either legitimate burst
traffic or a replay-flood probe.

---

## 4. Observability

### 4.1. `/metrics` endpoint (Prometheus)

Both binaries expose Prometheus text-format metrics at `/metrics` (no
auth — this is operator-internal, expose only on the management network
or behind a sidecar):

**Gateway** (`https://<gateway>:9000/metrics`):

```
ullm_gateway_protocol_version 2
ullm_gateway_transparency_log_size{log_id="ullm-mainnet-eu-1"} 18421
ullm_gateway_rate_limiter_buckets 142
```

**TEE** (`http://127.0.0.1:9001/metrics`, loopback-only):

```
ullm_tee_protocol_version 2
ullm_tee_nonce_registry_size 318
ullm_tee_tenant_pool_size 142
```

### 4.2. Recommended alerts

| Metric | Condition | Severity | Likely cause |
|---|---|---|---|
| `ullm_gateway_transparency_log_size` | stops increasing for > 5 min during traffic | page | disk full, fsync stuck, gateway hung |
| `ullm_gateway_rate_limiter_buckets` | == `max_tenants` for > 15 min | warn | tenant flood; § 5.2 |
| `ullm_tee_nonce_registry_size` | > 100k (~80% of cap) | warn | nonce replay storm; § 5.4 |
| `ullm_gateway_protocol_version` | != expected version | page | partial-rollout mismatch |
| HTTP 5xx rate from gateway | > 1% over 5 min | page | TEE-side panic or unreachable |
| `up{job="ullm-gateway"}` | == 0 | page | process down |

### 4.3. Tracing

Both binaries use the `tracing` crate. Default subscriber is
`tracing_subscriber::fmt`; route to `journald` via systemd, then to your
log pipeline. The `info` level is safe for production — secret material
is never logged (see audit P6). Bump to `debug` only for short-lived
troubleshooting under change control.

---

## 5. Incident response

### 5.1. Gateway / TEE process crash

The binaries are stateless except for the transparency log file. systemd
restarts both. On restart:

1. `ullm-tee` reads `ULLM_MODEL_SEED`, rebuilds the model commitment,
   generates a fresh ephemeral identity. Existing client sessions are
   invalidated — clients reconnect and renegotiate.
2. `ullm-gateway` reads the JSONL log from `ULLM_LOG_PATH`, re-derives
   the Merkle tree, and resumes serving. The seq numbers are recomputed
   from file position (defense against tampered persisted seq, see audit
   P4).

If the log file is corrupted (out-of-band edit, partial write, ...) the
gateway refuses to start. Restore from backup and investigate.

### 5.2. Tenant flood (rate-limiter at cap)

If `ullm_gateway_rate_limiter_buckets == max_tenants` sustained:

1. Confirm via gateway logs which auth-identity prefixes are rotating.
2. If a single upstream client is generating unique tenant IDs:
   - Block at the upstream auth provider.
3. If the flood is broad-based (real spike), bump `max_tenants` in
   `RateLimiterConfig` (currently a code constant — file a follow-up to
   make it env-configurable if this recurs).

The eviction-cooldown means an attacker rotating IDs pays a 7/8 quota
penalty per cycle, so a flood degrades performance without enabling
unbounded resource use.

### 5.3. Logger key compromise

If `ULLM_LOGGER_SEED` leaks:

1. **Immediately** stop signing new STHs by killing the gateway.
2. Publish a key-revocation notice (signed under the *old* key one last
   time, with a published rotation pubkey).
3. Generate a fresh seed, bring up a new gateway instance with the new
   `ULLM_LOGGER_SEED` and `ULLM_LOG_ID` (the log-id rotates in lockstep
   so consumers don't accidentally trust a forked log under the same id).
4. Clients re-pin to the new pubkey via out-of-band distribution
   (transparency-log gossip, ullm.org-style canonical registry, etc.).

The old log file remains valid evidence for past receipts; do not delete
it. The new log starts at seq 0.

### 5.4. Suspected log fork

A "log fork" is when two distinct STHs are signed at the same tree size
with different roots — proof that the logger signed contradictory
histories. Detection:

1. Witnesses gossip STHs; if any pair of STHs at the same `size` has
   different `root_hex`, the witness flags a fork.
2. The auditor binary (`ullm-log-auditor`) accepts `--head-a` and
   `--head-b` to verify both signatures + emit a fork certificate.

Response:

- Treat as logger key compromise (§ 5.3). Even an honest logger that has
  forked is unsalvageable: clients can no longer trust *which* history
  is the real one.
- Preserve both forked log files for post-mortem.

### 5.5. Replay attack on attestation nonce

If `ullm_tee_nonce_registry_size` is growing pathologically (e.g.,
quadrupling within minutes) and `/v1/attest` 4xx rates spike, that's the
nonce registry rejecting replays — the system is defending itself.

If the registry is at its 128k cap and legitimate clients are being
rejected:

1. Confirm via TEE logs that the rejections are concentrated on a
   specific source IP / tenant.
2. Block upstream at the gateway's auth layer or via L4 firewall.
3. The registry GCs entries after `NONCE_TTL` (mirrors the freshness
   window the client checks), so attack pressure subsides naturally
   within ~5 minutes of blocking the source.

### 5.6. Reproducible-build mismatch

If builder A and builder B produce different image SHAs:

1. Pause the deploy pipeline. Do not promote.
2. Inspect the Nix flake closure for impurities — usually a non-pinned
   git input or an upstream Nixpkgs revision drift.
3. Lock the offending input, rebuild, re-verify on a third builder.

This is rare in steady state but common when bumping toolchain versions.

### 5.7. Witness cosigner divergence

If a witness refuses to cosign the latest STH:

1. Pull the witness's reason via its `/v1/witness/explain` endpoint
   (when implemented; today the witness logs the conflict).
2. Diff the witness-observed Merkle root against the gateway's. If they
   match but the witness rejected for another reason (e.g., timestamp
   drift), reconcile.
3. If the roots differ at the same size, treat as § 5.4 (log fork).

---

## 6. Upgrade procedure

### 6.1. Minor / patch upgrade (no protocol bump)

1. Build the new image reproducibly (§ 2.1) and update
   `manifest.json`.
2. Promote one canary node. Monitor for 15 minutes:
   - `/metrics` continues serving
   - watcher receipts still verify
   - 5xx rate unchanged
3. Promote the rest of the fleet in batches.

### 6.2. Protocol-version bump (`ullm_core::PROTOCOL_VERSION`)

A protocol bump is breaking for older clients. Procedure:

1. Ship a release where the binary speaks **both** the old and the new
   protocol version (negotiated in the handshake).
2. Operate the dual-version build for at least one client-update cycle
   (typically 2 weeks).
3. Ship the release that drops support for the old version.

The `ullm_gateway_protocol_version` metric lets operators confirm every
node is on the same version before step 3.

### 6.3. Adding a new TEE vendor / image

To onboard, e.g., a new GPU-CC vendor:

1. Reproducibly build the vendor-specific TEE image.
2. Run the `MultiVendorVerifier` smoke test from the federation crate
   against the new vendor's first quote.
3. Add the new vendor's measurement to `manifest.json` under
   `vendors[]`. Existing vendors stay live.
4. Bump the federation pool's `n` count; `k` requirements are
   re-evaluated at session admission.

---

## 7. Rollback procedure

### 7.1. Code rollback

1. Re-tag the previous container image as `:current`.
2. systemd unit reload (the unit file references `:current`).
3. Verify `/metrics` and watcher health.

### 7.2. Configuration rollback

systemd environment files are version-controlled. `git revert` the bad
change, deploy via the same pipeline as a code rollback.

### 7.3. Transparency-log rollback (**never**)

Do not rewrite the log file. It is append-only by contract — any rollback
of the JSONL invalidates every published STH and every client receipt.
If the log is corrupt, restore from backup at the last-known-good seq;
do not truncate.

---

## 8. Routine maintenance

- **Daily**: verify `/metrics` scrape, alert pipeline health, log file
  size growth is within budget.
- **Weekly**: spot-check a random watcher receipt against the live log.
- **Monthly**: run `cargo audit` against the locked `Cargo.lock`. (CI
  does this on every PR; the monthly run catches advisories filed
  between releases.)
- **Quarterly**: rotate operator credentials, review audit findings
  (`docs/audit/FINDINGS-P*.md`), bump dependency floors where
  appropriate.

---

## 9. Graceful shutdown

Both binaries handle `SIGTERM` and `SIGINT`:

- `ullm-tee`: stops accepting new HTTP connections immediately; in-flight
  WebSocket sessions are allowed to complete naturally. `AppState` drops
  when the last Arc clone goes out of scope, which zeroizes secrets and
  closes the tenant pool.
- `ullm-gateway`: triggers `axum-server::Handle::graceful_shutdown(Some(
  Duration::from_secs(30)))`. In-flight TLS connections and the
  transparency-log appender are allowed 30 seconds to drain, then the
  listener forcibly closes.

systemd should be configured with `TimeoutStopSec=45s` (gateway) and
`TimeoutStopSec=30s` (tee) to give the graceful drain time to complete
before a SIGKILL.

---

## 10. Contacts and escalation

- Security disclosures: see [`SECURITY.md`](../SECURITY.md).
- Operator on-call: rotates via the team's pager schedule.
- Witness federation: see the federation pool registry; contact each
  witness operator directly for cosigning issues.
