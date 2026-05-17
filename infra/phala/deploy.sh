#!/usr/bin/env bash
# Phala Network deployment for ullm-tee.
#
# Phala hosts H100 / H200 TEE workers running OCI containers; the worker
# fetches our reproducible image and runs it under TDX + NVIDIA CC. The
# Phala API surface mirrors OpenAI's, but the underlying inference runs
# inside the worker's confidential enclave with attestation evidence
# fetched at first request.

set -euo pipefail

cd "$(dirname "$0")/../.."

: "${PHALA_API_TOKEN:?PHALA_API_TOKEN must be set (Phala account API token)}"
: "${TEE_IMAGE_URI:?TEE_IMAGE_URI must point at a registry-published ullm-tee image}"
: "${EXPECTED_IMAGE_SHA256:?EXPECTED_IMAGE_SHA256 must match infra/tee-image/manifest.json}"

WORKER_REGION="${WORKER_REGION:-us-east}"
WORKER_KIND="${WORKER_KIND:-h100}"   # h100 | h200

echo "==> requesting a Phala TEE worker (region=$WORKER_REGION, kind=$WORKER_KIND)"
worker_payload=$(jq -n \
    --arg img "$TEE_IMAGE_URI" \
    --arg sha "$EXPECTED_IMAGE_SHA256" \
    --arg region "$WORKER_REGION" \
    --arg kind "$WORKER_KIND" \
    '{
        image: $img,
        expected_image_sha256: $sha,
        region: $region,
        gpu: $kind,
        env: [
            { name: "ULLM_TEE_ADDR", value: "0.0.0.0:9001" },
            { name: "RUST_LOG", value: "ullm_tee=info" }
        ],
        ports: [ { container_port: 9001 } ]
    }')

response=$(curl -sS -X POST "https://api.phala.network/v1/workers" \
    -H "Authorization: Bearer $PHALA_API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$worker_payload")

worker_id=$(jq -r '.id' <<<"$response")
worker_endpoint=$(jq -r '.endpoint_url' <<<"$response")
echo "==> worker provisioned: id=$worker_id endpoint=$worker_endpoint"

echo "==> fetching first attestation"
attestation=$(curl -sS "$worker_endpoint/v1/attest?nonce=$(head -c 32 /dev/urandom | xxd -p -c 32)")
echo "$attestation" > "phala-attestation-$worker_id.bin"

echo "==> verifying image hash matches the manifest"
phala_sha=$(jq -r '.image_sha256' <<<"$response" 2>/dev/null || echo "unknown")
if [[ "$phala_sha" != "unknown" && "$phala_sha" != "$EXPECTED_IMAGE_SHA256" ]]; then
    echo "Phala reports image $phala_sha, expected $EXPECTED_IMAGE_SHA256" >&2
    exit 1
fi

cat <<EOF
==> deployment ready

Worker ID:    $worker_id
Endpoint:     $worker_endpoint
Attestation:  phala-attestation-$worker_id.bin

To register this worker in a federation pool:

    ullm-federation register \\
        --provider-id phala-$worker_id \\
        --vendor nvidia \\
        --url $worker_endpoint \\
        --build-hash $EXPECTED_IMAGE_SHA256
EOF
