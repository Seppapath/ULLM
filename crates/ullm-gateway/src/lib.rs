// SPDX-License-Identifier: Apache-2.0
//! Blind gateway. Cannot see plaintext: forwards `/v1/attest` responses and
//! WS frames verbatim, throttles by ciphertext byte budget per tenant, and
//! mints stateless HMAC session tokens for sticky replica routing.

// P9-FIX-D: `dev-keys` and `prod` are mutually exclusive Cargo features.
// Building the gateway with both unified in (e.g. `cargo build --release
// --features prod` while leaving `default = ["dev-keys"]` intact) would
// silently ship the `/v1/devkeys` route in a binary the operator believes
// is hardened. Reject that combination at compile time so the CI strings
// gate is belt-and-suspenders, not the only line of defense.
#[cfg(all(feature = "dev-keys", feature = "prod"))]
compile_error!(
    "ullm-gateway: features `dev-keys` and `prod` are mutually exclusive. \
     For a production build pass `--no-default-features --features prod`."
);

pub mod proxy;
pub mod rate_limit;
pub mod session_token;
pub mod transparency;

pub use proxy::{metrics_router, router, GatewayState, SthCache};
pub use rate_limit::{RateLimiter, RateLimiterConfig};
pub use session_token::{SessionToken, SessionTokenSigner};
pub use transparency::{LogEntry, LogStatus, TransparencyLog};
