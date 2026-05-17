// SPDX-License-Identifier: Apache-2.0
//! Phala → federation `Provider` adapter.

use ullm_federation::{BuildHash, Provider, ProviderManifest, VendorKind};

use crate::attest::PhalaAttestationKind;
use crate::descriptor::{PhalaWorker, PhalaWorkerStatus};

pub struct PhalaAdapter;

impl PhalaAdapter {
    /// Convert a `PhalaWorker` into a `Provider` registered for a federation
    /// pool. Returns `Err` if the worker isn't `Ready` or if its image hash
    /// is malformed.
    pub fn provider(
        worker: &PhalaWorker,
        attestation: PhalaAttestationKind,
    ) -> Result<Provider, AdapterError> {
        if worker.status != PhalaWorkerStatus::Ready {
            return Err(AdapterError::NotReady(worker.status.clone()));
        }
        let sha = hex::decode(&worker.image_sha256_hex)
            .map_err(|e| AdapterError::BadHash(e.to_string()))?;
        let arr: [u8; 32] = sha
            .as_slice()
            .try_into()
            .map_err(|_| AdapterError::BadHash("image hash != 32 bytes".into()))?;
        Ok(Provider {
            manifest: ProviderManifest {
                provider_id: format!("phala-{}", worker.id),
                build_hash: BuildHash(arr),
                region: worker.region.clone(),
            },
            vendor: attestation.vendor_kind(),
            url: worker.endpoint_url.clone(),
            healthy: true,
        })
    }

    pub fn vendor(_attestation: PhalaAttestationKind) -> VendorKind {
        VendorKind::Nvidia
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("worker is not ready (status: {0:?})")]
    NotReady(PhalaWorkerStatus),
    #[error("bad image_sha256_hex: {0}")]
    BadHash(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_worker() -> PhalaWorker {
        PhalaWorker {
            id: "abc123".into(),
            region: "us-east".into(),
            gpu_kind: "h100".into(),
            endpoint_url: "https://phala-abc123.run/v1".into(),
            image_uri: "registry/ullm-tee:0.1.0".into(),
            image_sha256_hex: "11".repeat(32),
            status: PhalaWorkerStatus::Ready,
        }
    }

    #[test]
    fn ready_worker_becomes_provider() {
        let w = ready_worker();
        let p = PhalaAdapter::provider(&w, PhalaAttestationKind::TdxH100).unwrap();
        assert_eq!(p.manifest.provider_id, "phala-abc123");
        assert_eq!(p.vendor, VendorKind::Nvidia);
        assert!(p.healthy);
        assert_eq!(p.url, "https://phala-abc123.run/v1");
    }

    #[test]
    fn provisioning_worker_rejected() {
        let mut w = ready_worker();
        w.status = PhalaWorkerStatus::Provisioning;
        assert!(matches!(
            PhalaAdapter::provider(&w, PhalaAttestationKind::TdxH100),
            Err(AdapterError::NotReady(_))
        ));
    }

    #[test]
    fn bad_hash_rejected() {
        let mut w = ready_worker();
        w.image_sha256_hex = "not-hex".into();
        assert!(matches!(
            PhalaAdapter::provider(&w, PhalaAttestationKind::TdxH100),
            Err(AdapterError::BadHash(_))
        ));
    }

    #[test]
    fn worker_plugs_into_pool_with_vendor_disjointness() {
        use ullm_federation::{Provider, ProviderPool};

        let phala = PhalaAdapter::provider(&ready_worker(), PhalaAttestationKind::TdxH100).unwrap();
        let own_tdx = Provider {
            manifest: ProviderManifest {
                provider_id: "own-tdx-1".into(),
                build_hash: BuildHash([0xAA; 32]),
                region: "eu-west".into(),
            },
            vendor: VendorKind::Tdx,
            url: "https://own-tdx/v1".into(),
            healthy: true,
        };
        let pool = ProviderPool::new(vec![phala, own_tdx]);
        let plan = pool.plan_disjoint(2).unwrap();
        assert_eq!(plan.providers.len(), 2);
        let kinds: std::collections::HashSet<_> = plan.providers.iter().map(|p| p.vendor).collect();
        assert_eq!(kinds.len(), 2);
        assert!(kinds.contains(&VendorKind::Nvidia));
        assert!(kinds.contains(&VendorKind::Tdx));
    }
}
