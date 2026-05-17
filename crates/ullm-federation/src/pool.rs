// SPDX-License-Identifier: Apache-2.0
//! Provider pool. Selects a vendor-disjoint k-of-n routing plan for a session.

use std::collections::HashSet;

use ullm_core::{Error, Result};

use crate::build::ProviderManifest;
use crate::multi_vendor::VendorKind;

#[derive(Debug, Clone)]
pub struct Provider {
    pub manifest: ProviderManifest,
    pub vendor: VendorKind,
    pub url: String,
    /// Aggregate health: false → skip when planning.
    pub healthy: bool,
}

pub struct ProviderPool {
    pub providers: Vec<Provider>,
}

#[derive(Debug, Clone)]
pub struct RoutingPlan {
    pub providers: Vec<Provider>,
}

impl ProviderPool {
    pub fn new(providers: Vec<Provider>) -> Self {
        Self { providers }
    }

    /// Pick `k` healthy providers from disjoint vendors. Returns the routing
    /// plan or fails if fewer than `k` distinct vendors are available.
    pub fn plan_disjoint(&self, k: usize) -> Result<RoutingPlan> {
        if k == 0 {
            return Err(Error::Other("k must be > 0".into()));
        }
        let mut chosen: Vec<Provider> = Vec::new();
        let mut seen: HashSet<VendorKind> = HashSet::new();
        for p in &self.providers {
            if !p.healthy {
                continue;
            }
            if seen.insert(p.vendor) {
                chosen.push(p.clone());
                if chosen.len() == k {
                    return Ok(RoutingPlan { providers: chosen });
                }
            }
        }
        Err(Error::Other(format!(
            "only {} vendor-disjoint healthy providers; needed {}",
            chosen.len(),
            k
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::BuildHash;

    fn prov(id: &str, vendor: VendorKind, healthy: bool) -> Provider {
        Provider {
            manifest: ProviderManifest {
                provider_id: id.into(),
                build_hash: BuildHash([0; 32]),
                region: "us-east".into(),
            },
            vendor,
            url: format!("https://{id}/v1"),
            healthy,
        }
    }

    #[test]
    fn picks_disjoint_k_of_n() {
        let pool = ProviderPool::new(vec![
            prov("a", VendorKind::Tdx, true),
            prov("b", VendorKind::Snp, true),
            prov("c", VendorKind::Nvidia, true),
        ]);
        let plan = pool.plan_disjoint(2).unwrap();
        assert_eq!(plan.providers.len(), 2);
        let kinds: HashSet<_> = plan.providers.iter().map(|p| p.vendor).collect();
        assert_eq!(kinds.len(), 2);
    }

    #[test]
    fn skips_unhealthy_providers() {
        let pool = ProviderPool::new(vec![
            prov("a", VendorKind::Tdx, false),
            prov("b", VendorKind::Snp, true),
            prov("c", VendorKind::Nvidia, true),
        ]);
        let plan = pool.plan_disjoint(2).unwrap();
        assert_eq!(plan.providers.len(), 2);
        assert!(plan.providers.iter().all(|p| p.vendor != VendorKind::Tdx));
    }

    #[test]
    fn ignores_duplicate_vendors() {
        let pool = ProviderPool::new(vec![
            prov("a1", VendorKind::Tdx, true),
            prov("a2", VendorKind::Tdx, true),
            prov("b", VendorKind::Snp, true),
        ]);
        let plan = pool.plan_disjoint(2).unwrap();
        assert_eq!(plan.providers.len(), 2);
    }

    #[test]
    fn fails_when_too_few_distinct() {
        let pool = ProviderPool::new(vec![
            prov("a1", VendorKind::Tdx, true),
            prov("a2", VendorKind::Tdx, true),
        ]);
        assert!(pool.plan_disjoint(2).is_err());
    }
}
