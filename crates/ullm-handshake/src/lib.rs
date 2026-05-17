// SPDX-License-Identifier: Apache-2.0
//! PQXDH-style 1-RTT handshake.
//!
//! ## Roles
//!
//! - **Server (TEE)** publishes a signed pre-key bundle:
//!   `{ id_pk, spk_pk (X25519), pq_pk (ML-KEM-768), attestation_evidence }`.
//! - **Client** fetches the bundle (out-of-band, e.g. via `GET /attest`),
//!   verifies the attestation evidence, then constructs a `ClientHello`.
//! - Server replies with `ServerHello` containing a fresh X25519 ratchet
//!   public key, an updated attestation evidence whose `REPORT_DATA` binds the
//!   handshake transcript, and a signature.
//!
//! The hybrid shared secret `mlkem_ss || x25519_ss` is fed through HKDF with
//! salt = transcript hash to derive the root key.

pub mod messages;
pub mod state;
pub mod transcript;

pub use messages::{
    ClientHello, PreKeyBundle, ServerHello, REPORT_DATA_LEN, SIG_DOMAIN_BUNDLE,
    SIG_DOMAIN_HANDSHAKE,
};
pub use state::{ClientHandshake, EstablishedKeys, ServerHandshake};
pub use transcript::Transcript;
