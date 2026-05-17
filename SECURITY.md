# Security Policy

## Supported versions

ullm is pre-1.0. Until the first stable release, only the most recent
tagged release receives security fixes. After 1.0 lands, the last two
minor versions will be supported in parallel.

| Version | Supported |
|---|---|
| `0.2.x` (current) | yes |
| `0.1.x` | no |
| `< 0.1` | no |

## Reporting a vulnerability

**Do not file a public GitHub issue for security bugs.**

If you believe you have found a vulnerability — in the cryptographic
protocol, the transparency log, the attestation chain, the WASM/Python
bindings, or anywhere in the workspace — please report it privately via
GitHub Security Advisories:

> https://github.com/example/ullm/security/advisories/new

Alternatively, email `security@example.org` with PGP-encrypted contents.
The PGP key fingerprint is published at
`https://example.org/.well-known/security.asc` and rotates annually on
the first business day of January.

### What to include

A useful report contains:

- A description of the issue and the security guarantee it breaks
  (confidentiality, integrity, replay protection, forward secrecy, audit
  soundness, denial-of-service, …).
- The affected version, branch, or commit hash.
- A reproduction recipe — a failing test case, a malicious input, or a
  protocol trace.
- Your impact assessment (read/write, local/remote, authenticated/not).
- Any patch suggestion you'd like considered (optional).

### What to expect

- **Acknowledgement** within 3 business days. If you don't hear back,
  please re-send via the email backup above in case the GitHub-side
  notification was lost.
- **Triage decision** (in-scope / not-in-scope / duplicate) within 7
  business days.
- **Fix landing target**:
  - Critical (active exploitation, plaintext disclosure, key
    extraction): 7 days.
  - High (protocol break, audit log forgery): 30 days.
  - Medium (defense-in-depth, DoS): 90 days.
  - Low (hygiene): next scheduled release.
- **Coordinated disclosure** — we will work with you on a public
  disclosure date once the fix has landed. Default embargo is 90 days
  from triage acknowledgement; we'll negotiate a longer embargo if
  downstream coordination requires it.
- **Credit** — your name and a link of your choice in the advisory and
  the CHANGELOG, unless you ask to remain anonymous.

We do not currently run a paid bounty program. We will publicly credit
reporters and provide swag where applicable.

## In-scope

- All crates in this workspace (`crates/ullm-*`, `tools/*`,
  `bindings/*`).
- The reference deployment recipes in `infra/`.
- The WASM and Python bindings.

## Out-of-scope

- Third-party hosts running unmodified ullm (route those reports
  through the host operator).
- Vulnerabilities in upstream dependencies (`ml-kem`, `rustls`,
  `frost-ed25519`, …) — please report those to the upstream project.
  We will track and update our floor.
- Issues that require a malicious operator with full root inside a TEE
  that has already broken its TDX/SEV-SNP/NRAS attestation chain. This
  is explicitly outside the threat model (see
  [`docs/audit/THREAT-MODEL.md`](docs/audit/THREAT-MODEL.md)).
- Performance pathologies that are not exploitable for DoS at honest
  load (a 2× slowdown under a 100k-tenant adversarial flood is a
  performance bug; please file a regular issue).
- Issues in the `dev-keys` feature — that feature exists for tests, is
  off in production builds, and the CI strings-check enforces it.

## Audit history

The codebase has been through **thirteen rounds** of internal
red-team review (P1 → P13) documented under
[`docs/audit/`](docs/audit/). **104 cumulative vulnerabilities have
been fixed**, with regression tests in the workspace for every fix.
Full per-round catalogue in
[`docs/audit/FINDINGS-INDEX.md`](docs/audit/FINDINGS-INDEX.md).

Slice 4 of the roadmap was the first external crypto + protocol
audit, covering the v0.1.0 cryptographic core. An external audit
**refresh** has been commissioned for v0.2.0-rc1, covering the
delta since v0.1.0 (Slices 1–10, PR-1..PR-8, P1–P13). Deliverables
for the refresh:

- [`docs/audit/AUDIT-REFRESH-BRIEF.md`](docs/audit/AUDIT-REFRESH-BRIEF.md)
  — cover letter sent to candidate audit firms
- [`docs/audit/SCOPE-REFRESH.md`](docs/audit/SCOPE-REFRESH.md) —
  what changed since v0.1.0
- [`docs/audit/KNOWN-ISSUES.md`](docs/audit/KNOWN-ISSUES.md) —
  deliberately-deferred items (do NOT flag as new findings)
- [`scripts/build_audit_packet.sh`](scripts/build_audit_packet.sh)
  — produces `audit-packet-<sha>.tar.gz` for the auditor

Public external-audit reports land in
`docs/audit/EXTERNAL-AUDIT-REPORT-v<version>.md`.

## Cryptographic primitives

For reference, the security claims in this codebase rest on:

- **ML-KEM-768** (FIPS 203) for the post-quantum KEM half.
- **X25519** (RFC 7748) for the classical ECDH half.
- **Hybrid combination** via concat-then-HKDF with the transcript hash
  as salt (matches NIST IR 8413, SPQR, RFC 9180 patterns).
- **XChaCha20-Poly1305** (RFC 8439 / draft-irtf-cfrg-xchacha) for AEAD.
- **HKDF-SHA-384** for key derivation.
- **Ed25519** (RFC 8032) for signatures.
- **FROST-Ed25519** (RFC 9591) for threshold signatures.
- **rustls-post-quantum** `X25519MLKEM768` (draft-kwiatkowski-tls-ecdhe-mlkem)
  for transport TLS.

A break of any of these primitives is a generational research event and
out of scope for this disclosure policy; please contact the upstream
authors directly.

## Repository hardening (maintainer policy)

### One-time setup for the CODEOWNERS team

`.github/CODEOWNERS` routes every security-critical path to
`@ullm-security`. **This is a placeholder handle** — until a GitHub
team or user with that exact name exists in the organization, the
CODEOWNERS file is silently no-op'd by GitHub: any reviewer can
approve a PR that removes the `compile_error!` mutual-exclusion in
`crates/ullm-{gateway,tee}/src/lib.rs` *and* the `prod-strings` job
in `.github/workflows/ci.yml` in a single commit.

First-time repository setup MUST:

1. Create a `ullm-security` team in the organization (or rename the
   handle in `CODEOWNERS` to your actual security-review team).
2. Grant the team write access to this repository.
3. Configure branch protection on `main` and on the `v*.*.*` tag
   pattern with **Require review from Code Owners** + **Require
   approvals: 1** + **Restrict who can dismiss reviews**.

### Required branch-protection rules

The following GitHub branch-protection rules MUST be in place on `main`
and on any release tag pattern (`v*.*.*`):

1. **Required status checks** before merge:
   - `fmt + clippy`
   - `cargo check`
   - `test (release)`
   - `feature-matrix`
   - `cargo audit`
   - `prod-binary strings check` — the critical gate; failure means a
     release candidate exposes the `/v1/devkeys` development endpoint
     or related dev-only string literals.
2. **Require pull-request reviews** (≥ 1 reviewer, code-owners
   acknowledged).
3. **Require signed commits**.
4. **Restrict who can push to matching branches** to the release
   maintainer set.
5. **Disable force-push to `main` and to release tags.**

The strings-check job is a defense-in-depth gate, not the sole line
of defense — the workspace also enforces compile-time mutual exclusion
of the `dev-keys` and `prod` Cargo features (a `cargo build --features
prod` that forgets `--no-default-features` is a hard compile error).
Both layers are required: the compile-time gate catches local-build
mistakes, the CI gate catches feature-flag drift introduced by a PR.

CI runs on `ubuntu-latest`, which is a GitHub-hosted runner. A
compromised runner could in principle subvert the gate. Release tags
SHOULD additionally be re-verified on a self-hosted attested runner
(TDX/SEV-SNP) that signs the resulting binary hash and the strings-check
output before promotion. Until that pipeline is wired, the
GitHub-hosted gate is the developer-feedback signal and the manual
operator strings-check in [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
§2.5 is the release-promotion signal.

## Hardening guidance for operators

See [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for the full operations
runbook including key management, incident response (key compromise,
log fork, replay attack), and the `dev-keys` strings-check that must
be part of any release-promotion pipeline.
