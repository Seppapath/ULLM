// SPDX-License-Identifier: Apache-2.0
//! Phala attestation kind. Maps the worker's underlying TEE to the
//! `VendorKind` used by `MultiVendorVerifier`.

use ullm_federation::VendorKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhalaAttestationKind {
    /// Intel TDX host + NVIDIA H100 in CC-mode.
    TdxH100,
    /// Intel TDX host + NVIDIA H200 in CC-mode.
    TdxH200,
    /// AMD SEV-SNP host + NVIDIA H100.
    SnpH100,
}

impl PhalaAttestationKind {
    /// Phala workers always include a GPU TEE alongside a CPU TEE. For
    /// vendor-disjointness purposes we route them under NVIDIA — operators
    /// who want CPU-vendor disjointness pair Phala with their own
    /// non-NVIDIA TEE.
    pub fn vendor_kind(self) -> VendorKind {
        VendorKind::Nvidia
    }
}
