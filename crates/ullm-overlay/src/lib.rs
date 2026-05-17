// SPDX-License-Identifier: Apache-2.0
//! Application-layer onion routing.
//!
//! Each relay has an X25519 long-term keypair. The client wraps the inner
//! payload in N nested AEAD layers; layer `i` is keyed via X25519 ECDH
//! between a fresh client ephemeral and relay `i`'s public key. Each relay
//! peels exactly one layer and sees only `(next_hop_address, inner_bytes)`.
//!
//! No relay sees the original client identity (only its immediate
//! predecessor) and no relay sees the final destination address (only its
//! immediate successor) — standard Tor-shape privacy.
//!
//! This is NOT Tor — there's no consensus, directory authorities, padding,
//! or guard discipline. It's a clean primitive for tenants who need
//! gateway-layer privacy without taking on Tor as a dependency.

pub mod layer;
pub mod relay;
pub mod transport;

pub use layer::{peel_layer, wrap_layers, OnionLayer, Relay};
pub use relay::{InMemoryRelay, RelayId};
pub use transport::{deliver, send_through};
