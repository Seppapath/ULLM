#!/usr/bin/env bash
# Build the audit packet that ships to the external auditor.
# Output: audit-packet-<git-sha>.tar.gz in the repo root.
#
# Refreshed for the v0.2.0-rc1 external-audit refresh (post-P13).
# Now bundles: the brief, scope-refresh, findings-index, known-issues,
# every per-round findings doc, the threat model, the SLO doc, the
# OPERATIONS runbook, the SECURITY policy, the CHANGELOG, the CI yml,
# the CODEOWNERS, and the source snapshot.
#
# Run from a clean checkout at the audit tag.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found"; exit 1
fi

SHA="$(git rev-parse --short HEAD 2>/dev/null || echo "untagged")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

OUT="$STAGE/audit-packet-$SHA"
mkdir -p "$OUT"

echo "==> snapshot crates + docs"
# rsync is preferred when available; fall back to cp -R for portability.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude target --exclude .git --exclude node_modules --exclude pkg --exclude dist . "$OUT/repo/"
else
    mkdir -p "$OUT/repo"
    cp -R . "$OUT/repo/"
    rm -rf "$OUT/repo/target" "$OUT/repo/.git" "$OUT/repo/node_modules" "$OUT/repo/pkg" "$OUT/repo/dist"
fi

echo "==> generating SBOM (cargo tree)"
cargo tree --workspace --edges normal,build --prefix none > "$OUT/DEPENDENCY-SBOM.txt"

echo "==> capturing recent changes"
git log --oneline -n 500 > "$OUT/RECENT-CHANGES.txt" 2>/dev/null || echo "(no git history)" > "$OUT/RECENT-CHANGES.txt"

echo "==> running tests to capture the baseline"
cargo test --workspace --release 2>&1 | tee "$OUT/TEST-OUTPUT.txt" || true

echo "==> running clippy"
cargo clippy --workspace --release --all-targets 2>&1 | tee "$OUT/CLIPPY-OUTPUT.txt" || true

echo "==> running cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit 2>&1 | tee "$OUT/CARGO-AUDIT-OUTPUT.txt" || true
else
    echo "(cargo-audit not installed; auditor should run \`cargo install --locked cargo-audit\` and re-run)" > "$OUT/CARGO-AUDIT-OUTPUT.txt"
fi

echo "==> running prod-strings check"
{
    echo "Prod-binary strings check (P9/P10/P11/P12 gate)"
    echo "Expected: zero occurrences of every needle in both binaries."
    echo
    # Discover the actual `target/` directory — operators commonly
    # set `CARGO_TARGET_DIR` to a non-default path, in which case
    # `target/release/` doesn't exist under the workspace root.
    if command -v jq >/dev/null 2>&1; then
        TARGET_DIR=$(cargo metadata --no-deps --format-version 1 | jq -r '.target_directory')
    else
        # Fallback for runners without jq: grep the metadata JSON.
        TARGET_DIR=$(cargo metadata --no-deps --format-version 1 \
            | tr ',' '\n' | grep -oE '"target_directory":"[^"]+"' \
            | head -1 | sed 's/.*:"//; s/"$//')
    fi
    : "${TARGET_DIR:=target}"
    echo "(target directory: $TARGET_DIR)"
    set +e
    fail=0
    for FEATS in "--no-default-features" "--no-default-features --features prod"; do
        echo "=== building gateway + tee with: $FEATS ==="
        # Use `-p` rather than `--bin`: in a virtual workspace, `--bin`
        # filters which binaries get linked but does NOT narrow the
        # feature-flag scope. `--no-default-features` would otherwise
        # apply to the workspace root (which has no features) instead
        # of the target crate, leaving `default = ["dev-keys"]`
        # active and tripping the compile_error gate.
        cargo build -p ullm-gateway --release $FEATS 2>&1 | tail -3
        cargo build -p ullm-tee     --release $FEATS 2>&1 | tail -3
        for bin_name in ullm-gateway ullm-tee; do
            for ext in "" ".exe"; do
                bin="$TARGET_DIR/release/$bin_name$ext"
                if [ ! -f "$bin" ]; then continue; fi
                for needle in "/v1/devkeys" "devkeys" "trust_root_hex" "tee_receipt_pk_hex"; do
                    count=$(strings "$bin" 2>/dev/null | grep -cF "$needle" || true)
                    echo "$bin (feats=$FEATS): $needle => $count occurrence(s)"
                    if [ "$count" != "0" ]; then
                        echo "FAIL: '$needle' present in $bin"
                        fail=1
                    fi
                done
            done
        done
    done
    set -e
    if [ "$fail" = "0" ]; then echo "STRINGS-CHECK: PASS"; else echo "STRINGS-CHECK: FAIL"; fi
} 2>&1 | tee "$OUT/PROD-STRINGS-CHECK.txt"

echo "==> assembling audit-refresh docs"
# Top-level pointers
cp docs/audit/AUDIT-REFRESH-BRIEF.md "$OUT/"
cp docs/audit/SCOPE-REFRESH.md       "$OUT/"
cp docs/audit/FINDINGS-INDEX.md      "$OUT/"
cp docs/audit/KNOWN-ISSUES.md        "$OUT/"

# Originals (Slice 4)
cp docs/audit/SCOPE.md               "$OUT/SCOPE-SLICE-4.md"
cp docs/audit/THREAT-MODEL.md        "$OUT/"

# Every per-round findings doc
mkdir -p "$OUT/findings"
cp docs/audit/FINDINGS.md "$OUT/findings/FINDINGS-P1.md"
for f in docs/audit/FINDINGS-P*.md; do
    cp "$f" "$OUT/findings/$(basename "$f")"
done

# Operational + release docs
cp docs/OPERATIONS.md "$OUT/" 2>/dev/null || echo "(OPERATIONS.md missing)"
cp docs/SLO.md         "$OUT/" 2>/dev/null || echo "(SLO.md missing)"
cp SECURITY.md         "$OUT/" 2>/dev/null || echo "(SECURITY.md missing)"
cp CHANGELOG.md        "$OUT/" 2>/dev/null || echo "(CHANGELOG.md missing)"

# CI + CODEOWNERS (so auditors see the policy hooks)
mkdir -p "$OUT/ci"
cp .github/workflows/ci.yml "$OUT/ci/" 2>/dev/null || echo "(ci.yml missing)"
cp .github/CODEOWNERS       "$OUT/ci/" 2>/dev/null || echo "(CODEOWNERS missing)"

# Build instructions
cat > "$OUT/BUILD-INSTRUCTIONS.md" <<'EOF'
# Reproducing the audit baseline

```bash
# 1. Extract the snapshot
cd repo

# 2. Build the workspace
cargo build --workspace --release
# Expect: 0 warnings, 0 errors.

# 3. Run the full test suite
cargo test --workspace --release
# Expect (at v0.2.0-rc1): 200 passed, 0 failed.

# 4. Verify the prod-feature compile-error
cargo check -p ullm-gateway --release --features prod
# Expect: compile_error! firing.

cargo check -p ullm-gateway -p ullm-tee --release --no-default-features --features prod
# Expect: clean compile.

# 5. Run cargo-audit
cargo install --locked cargo-audit
cargo audit
# Expect: clean (advisory-db is fetched at run time).

# 6. Run the prod-strings denylist
# (See PROD-STRINGS-CHECK.txt for the script + expected output.)
```

## Reference machine

x86_64 Linux 6.x or Windows 11 24H2, AVX2, 16 GB RAM, Rust stable
1.78+. See SLO.md for performance baselines.

## Reproducibility

The TEE container image is produced reproducibly via
`infra/tee-image/flake.nix`. Two independent builders running the
same Nix flake revision must produce identical OCI image SHAs.
EOF

echo "==> packing"
tar -czf "audit-packet-$SHA.tar.gz" -C "$STAGE" "audit-packet-$SHA"
echo "wrote audit-packet-$SHA.tar.gz"
echo
echo "Contents summary:"
tar -tzf "audit-packet-$SHA.tar.gz" | head -40
echo "..."
echo "($(tar -tzf "audit-packet-$SHA.tar.gz" | wc -l) entries total)"
