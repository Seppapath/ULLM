// SPDX-License-Identifier: Apache-2.0
//! Phala worker metadata.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhalaWorkerStatus {
    Provisioning,
    Ready,
    Degraded,
    Decommissioned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhalaWorker {
    pub id: String,
    pub region: String,
    pub gpu_kind: String,
    pub endpoint_url: String,
    pub image_uri: String,
    /// SHA-256 of the worker's reproducible image. The federation
    /// `ReproducibleBuildVerifier` cross-checks this against its allowlist.
    pub image_sha256_hex: String,
    pub status: PhalaWorkerStatus,
}
