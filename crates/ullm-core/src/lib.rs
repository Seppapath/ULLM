// SPDX-License-Identifier: Apache-2.0
//! Shared protocol constants, identifiers, and errors.

pub mod clock;
pub mod error;
pub mod ids;
pub mod shutdown;
pub mod version;

pub use clock::{now_unix, now_unix_or_zero};
pub use error::{Error, Result};
pub use ids::{Epoch, Seq, SessionId, TenantId};
pub use shutdown::{shutdown_signal, validate_metrics_addr, ShutdownBroadcaster};
pub use version::{
    AeadId, HashId, KemId, ATTESTATION_CACHE_TTL_HOURS, MAX_ATTESTATION_EVIDENCE_LEN,
    MAX_PLAINTEXT_PER_RECORD, MAX_WS_MESSAGE_BYTES, ML_KEM_768_EK_LEN,
    NONCE_TTL_DEFAULT_SEC, PROTOCOL_ID, PROTOCOL_VERSION, SESSION_TTL_DEFAULT_SEC,
};
