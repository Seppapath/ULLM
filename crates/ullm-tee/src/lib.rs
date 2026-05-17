// SPDX-License-Identifier: Apache-2.0
//! TEE-side service.
//!
//! In production this code runs inside an attested Confidential VM with
//! GPU CC; here it runs anywhere and uses a `MockIssuer` to stand in for real
//! attestation. The protocol surface is identical.

// P9-FIX-D: `dev-keys` and `prod` are mutually exclusive Cargo features.
// A `cargo build --release --features prod` that forgets
// `--no-default-features` would otherwise unify `dev-keys` back in and
// ship the `/v1/devkeys` endpoint in what the operator believes is a
// hardened binary. Reject the combination at compile time.
#[cfg(all(feature = "dev-keys", feature = "prod"))]
compile_error!(
    "ullm-tee: features `dev-keys` and `prod` are mutually exclusive. \
     For a production build pass `--no-default-features --features prod`."
);

pub mod identity;
pub mod inference;
pub mod nonce_registry;
pub mod service;
pub mod tenant;

pub use identity::TeeIdentity;
pub use inference::{InferenceEngine, MockEngine, TokenChunk};
pub use nonce_registry::{NonceRegistry, NonceReplay};
pub use service::{metrics_router, router, AppState, LayerProver};
pub use tenant::{SessionSlot, TenantPool};
