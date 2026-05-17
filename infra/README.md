# Deployment Recipes

## Reproducible TEE image

`infra/tee-image/flake.nix` builds the production TEE image bit-reproducibly.
Two independent builders running the same Nix flake revision must produce
identical OCI image hashes; if they don't, the build is not safe to deploy.

```bash
# Build once.
nix build .#tee-image
docker load < result
podman push <registry>/ullm-tee:0.1.0

# Verify reproducibility on a different host.
nix build .#tee-image
docker load < result
podman push <registry>/ullm-tee:0.1.0-builder-b

# The two image SHA-256s must match.
```

After the first reproducible build, populate `infra/tee-image/manifest.json`
with the resulting `image_sha256`, MRTD, and RTMRs. The gateway's
`ReproducibleBuildVerifier` admission allowlist references this manifest.

## Azure Confidential Computing (H100 CC + Intel TDX)

```bash
cd infra/azure-cc
terraform init
terraform apply \
    -var=tee_image_uri=<registry>/ullm-tee:0.1.0 \
    -var=expected_image_sha256=<manifest.json:image_sha256>
```

The Standard_NCC40ads_H100_v5 SKU pairs an H100 in CC-mode with an Intel
TDX host. First boot fetches the pinned image, refuses to launch if the
SHA-256 doesn't match the manifest, and starts `ullm-tee` on port 9001.

## Phala Network

```bash
cd infra/phala
export PHALA_API_TOKEN=phk_xxx
export TEE_IMAGE_URI=<registry>/ullm-tee:0.1.0
export EXPECTED_IMAGE_SHA256=<manifest.json:image_sha256>
./deploy.sh
```

Phala provisions a TEE worker, runs the pinned image, and returns an
`endpoint_url`. The script also fetches first-boot attestation evidence and
writes it to `phala-attestation-<worker_id>.bin` for the federation pool.

## Verifying a live deployment

Once running, the client can pin the deployment by fingerprint:

```bash
ullm-watcher \
    --model-seed 0000000000000000000000000000000000000000000000000000000000000000 \
    --tee-pk $(curl -sS https://<gateway>/v1/transparency/head | jq -r '.logger_pk_hex') \
    --prompt 'health check' \
    --receipt /tmp/receipt.bin
```

## Federation onboarding

Each running TEE registers with one or more federation pools. The
`MultiVendorVerifier` requires `k-of-n` distinct vendors per session, so a
deployment that uses both Azure-TDX and Phala-NVIDIA counts as two
disjoint vendors and unlocks `k=2` plans.
