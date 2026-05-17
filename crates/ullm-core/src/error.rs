// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// Cleartext error codes that may appear in protocol ERROR frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    BadVersion = 0x0001,
    BadCipherSuite = 0x0002,
    AttestationFailed = 0x0003,
    Replay = 0x0004,
    SeqGap = 0x0005,
    Decrypt = 0x0006,
    StaleAttestation = 0x0007,
    QuotaExceeded = 0x0008,
    Unauthorized = 0x0009,
    ModelUnavailable = 0x000A,
    Oom = 0x000B,
    ContentPolicy = 0x000C,
    TeeOutOfDate = 0x000D,
    Internal = 0x00FF,
}

impl ErrorCode {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0001 => Self::BadVersion,
            0x0002 => Self::BadCipherSuite,
            0x0003 => Self::AttestationFailed,
            0x0004 => Self::Replay,
            0x0005 => Self::SeqGap,
            0x0006 => Self::Decrypt,
            0x0007 => Self::StaleAttestation,
            0x0008 => Self::QuotaExceeded,
            0x0009 => Self::Unauthorized,
            0x000A => Self::ModelUnavailable,
            0x000B => Self::Oom,
            0x000C => Self::ContentPolicy,
            0x000D => Self::TeeOutOfDate,
            0x00FF => Self::Internal,
            _ => return None,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("bad protocol version: got {got:#04x}, expected {expected:#04x}")]
    BadVersion { got: u8, expected: u8 },

    #[error("unsupported cipher suite")]
    BadCipherSuite,

    #[error("attestation verification failed: {0}")]
    AttestationFailed(String),

    #[error("attestation evidence is stale (older than {ttl_sec}s)")]
    StaleAttestation { ttl_sec: u64 },

    #[error("frame replay detected at seq={seq}")]
    Replay { seq: u64 },

    #[error("sequence number gap of {gap} exceeds replay window")]
    SeqGap { gap: u64 },

    #[error("AEAD decryption failed")]
    Decrypt,

    #[error("frame too short: {0} bytes")]
    ShortFrame(usize),

    #[error("frame too long: {0} bytes")]
    LongFrame(usize),

    #[error("invalid frame type {0:#04x}")]
    BadFrameType(u8),

    #[error("invalid handshake message")]
    BadHandshake,

    #[error("invalid receipt signature")]
    BadReceipt,

    #[error("transport error: {0}")]
    Transport(String),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::BadVersion { .. } => ErrorCode::BadVersion,
            Error::BadCipherSuite => ErrorCode::BadCipherSuite,
            Error::AttestationFailed(_) => ErrorCode::AttestationFailed,
            Error::StaleAttestation { .. } => ErrorCode::StaleAttestation,
            Error::Replay { .. } => ErrorCode::Replay,
            Error::SeqGap { .. } => ErrorCode::SeqGap,
            Error::Decrypt => ErrorCode::Decrypt,
            _ => ErrorCode::Internal,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
