// SPDX-License-Identifier: Apache-2.0
//! Multi-vendor k-of-n attestation aggregator + provider pool + reproducible-build admission.
//!
//! Three trust-reduction levers that compose:
//!
//! 1. **`MultiVendorVerifier`** wraps a slice of `Verifier`s tagged with a
//!    `VendorKind`. A bundle is accepted only when at least `k` distinct
//!    vendors verify successfully. A single-vendor PKI compromise breaks
//!    only its own slot; the federation continues.
//!
//! 2. **`ReproducibleBuildVerifier`** decorates an underlying verifier and
//!    rejects any attestation whose declared build hash isn't in an
//!    allowlist. Operators cannot route to an unattested image even if their
//!    TEE produces a valid quote.
//!
//! 3. **`ProviderPool`** holds N TEE backends with associated manifests and
//!    selects a vendor-disjoint k-of-n routing for a session.

pub mod build;
pub mod multi_vendor;
pub mod pool;

pub use build::{BuildHash, ProviderManifest, ReproducibleBuildVerifier};
pub use multi_vendor::{MultiVendorVerifier, VendorKind, VendorVerifier};
pub use pool::{Provider, ProviderPool, RoutingPlan};
