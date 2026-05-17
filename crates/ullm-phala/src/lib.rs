// SPDX-License-Identifier: Apache-2.0
//! Phala Network DePIN adapter.
//!
//! Phala hosts H100/H200 TEE workers running OCI containers. Once a worker
//! is provisioned (see `infra/phala/deploy.sh`) it exposes an OpenAI-
//! compatible HTTPS endpoint plus our standard `/v1/attest` route. This
//! crate wraps a worker as a `ullm_federation::Provider` so it can plug
//! straight into a `ProviderPool`.
//!
//! The `live` feature enables real HTTP calls to Phala's worker-registry
//! API. Without it, this crate exposes the type shape + protocol
//! abstractions and the conversion from a Phala worker descriptor to a
//! `Provider` is unit-testable offline.

pub mod adapter;
pub mod attest;
pub mod descriptor;

pub use adapter::PhalaAdapter;
pub use attest::PhalaAttestationKind;
pub use descriptor::{PhalaWorker, PhalaWorkerStatus};
