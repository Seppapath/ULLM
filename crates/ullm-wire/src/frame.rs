// SPDX-License-Identifier: Apache-2.0
use ullm_core::{Epoch, Seq};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Handshake = 0x01,
    Data = 0x02,
    Control = 0x03,
    ToolStream = 0x04,
    Proof = 0x05,
    AttestRefresh = 0x06,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::Handshake,
            0x02 => Self::Data,
            0x03 => Self::Control,
            0x04 => Self::ToolStream,
            0x05 => Self::Proof,
            0x06 => Self::AttestRefresh,
            _ => return None,
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct FrameFlags: u16 {
        const END_OF_TURN          = 1 << 0;
        const KEY_UPDATE_PENDING   = 1 << 1;
        const COMPRESSED           = 1 << 2;
        const PROOF_ATTACHED       = 1 << 3;
        const STREAM_ID_MASK       = 0x0FF0;
    }
}

impl FrameFlags {
    pub fn with_stream_id(self, stream_id: u8) -> Self {
        let cleared = self.bits() & !Self::STREAM_ID_MASK.bits();
        Self::from_bits_retain(cleared | ((stream_id as u16) << 4))
    }

    pub fn stream_id(self) -> u8 {
        ((self.bits() & Self::STREAM_ID_MASK.bits()) >> 4) as u8
    }
}

/// Control-frame op codes (payload-internal; not a frame `type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlOp {
    Ping = 0x01,
    Pong = 0x02,
    Cancel = 0x03,
    KeyUpdate = 0x04,
    Error = 0x05,
    FlowCredit = 0x06,
    AttestRefreshChallenge = 0x07,
    AttestRefreshResponse = 0x08,
}

impl ControlOp {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::Ping,
            0x02 => Self::Pong,
            0x03 => Self::Cancel,
            0x04 => Self::KeyUpdate,
            0x05 => Self::Error,
            0x06 => Self::FlowCredit,
            0x07 => Self::AttestRefreshChallenge,
            0x08 => Self::AttestRefreshResponse,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub seq: Seq,
    pub epoch: Epoch,
    pub nonce_field: [u8; 12],
}

impl Header {
    /// Construct a header from `(type, flags, epoch, seq)`. The `nonce_field`
    /// is the deterministic `epoch_be || seq_be` projection.
    pub fn new(frame_type: FrameType, flags: FrameFlags, epoch: Epoch, seq: Seq) -> Self {
        let mut nonce_field = [0u8; 12];
        nonce_field[..4].copy_from_slice(&epoch.0.to_be_bytes());
        nonce_field[4..].copy_from_slice(&seq.0.to_be_bytes());
        Self {
            version: ullm_core::PROTOCOL_VERSION,
            frame_type,
            flags,
            seq,
            epoch,
            nonce_field,
        }
    }

    pub fn expected_nonce_field(&self) -> [u8; 12] {
        let mut f = [0u8; 12];
        f[..4].copy_from_slice(&self.epoch.0.to_be_bytes());
        f[4..].copy_from_slice(&self.seq.0.to_be_bytes());
        f
    }
}
