// SPDX-License-Identifier: Apache-2.0
//! Codec for the plaintext body of `FrameType::Control` frames.
//!
//! The body layout is `op (1 byte) || payload (variable)`. Op codes match
//! `ControlOp`. Payloads are minimal binary encodings to keep parsing
//! constant-time and obvious.

use ullm_core::{Error, Result};

use crate::frame::ControlOp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    Ping(u64),
    Pong(u64),
    Cancel { code: u16 },
    KeyUpdate { new_pk: [u8; 32] },
    Error { code: u16 },
    FlowCredit { bytes: u32 },
}

impl Control {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Control::Ping(ts) => {
                let mut v = Vec::with_capacity(9);
                v.push(ControlOp::Ping as u8);
                v.extend_from_slice(&ts.to_be_bytes());
                v
            }
            Control::Pong(ts) => {
                let mut v = Vec::with_capacity(9);
                v.push(ControlOp::Pong as u8);
                v.extend_from_slice(&ts.to_be_bytes());
                v
            }
            Control::Cancel { code } => {
                let mut v = Vec::with_capacity(3);
                v.push(ControlOp::Cancel as u8);
                v.extend_from_slice(&code.to_be_bytes());
                v
            }
            Control::KeyUpdate { new_pk } => {
                let mut v = Vec::with_capacity(33);
                v.push(ControlOp::KeyUpdate as u8);
                v.extend_from_slice(new_pk);
                v
            }
            Control::Error { code } => {
                let mut v = Vec::with_capacity(3);
                v.push(ControlOp::Error as u8);
                v.extend_from_slice(&code.to_be_bytes());
                v
            }
            Control::FlowCredit { bytes } => {
                let mut v = Vec::with_capacity(5);
                v.push(ControlOp::FlowCredit as u8);
                v.extend_from_slice(&bytes.to_be_bytes());
                v
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let (op_byte, rest) = b
            .split_first()
            .ok_or_else(|| Error::Other("empty control body".into()))?;
        let op = ControlOp::from_u8(*op_byte)
            .ok_or_else(|| Error::Other(format!("unknown control op {op_byte:#04x}")))?;
        match op {
            ControlOp::Ping => Ok(Control::Ping(read_u64(rest)?)),
            ControlOp::Pong => Ok(Control::Pong(read_u64(rest)?)),
            ControlOp::Cancel => Ok(Control::Cancel { code: read_u16(rest)? }),
            ControlOp::KeyUpdate => {
                let new_pk: [u8; 32] = rest
                    .try_into()
                    .map_err(|_| Error::Other("KeyUpdate payload != 32 bytes".into()))?;
                Ok(Control::KeyUpdate { new_pk })
            }
            ControlOp::Error => Ok(Control::Error { code: read_u16(rest)? }),
            ControlOp::FlowCredit => Ok(Control::FlowCredit { bytes: read_u32(rest)? }),
            other => Err(Error::Other(format!("unsupported control op {other:?}"))),
        }
    }
}

fn read_u16(b: &[u8]) -> Result<u16> {
    if b.len() != 2 {
        return Err(Error::Other(format!("expected 2-byte payload, got {}", b.len())));
    }
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(b: &[u8]) -> Result<u32> {
    if b.len() != 4 {
        return Err(Error::Other(format!("expected 4-byte payload, got {}", b.len())));
    }
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(b: &[u8]) -> Result<u64> {
    if b.len() != 8 {
        return Err(Error::Other(format!("expected 8-byte payload, got {}", b.len())));
    }
    Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_update_roundtrip() {
        let ku = Control::KeyUpdate { new_pk: [3u8; 32] };
        let bytes = ku.encode();
        let back = Control::decode(&bytes).unwrap();
        assert_eq!(ku, back);
    }

    #[test]
    fn ping_pong_roundtrip() {
        for c in [Control::Ping(42), Control::Pong(99)] {
            let bytes = c.encode();
            assert_eq!(Control::decode(&bytes).unwrap(), c);
        }
    }

    #[test]
    fn rejects_bad_key_update_length() {
        let mut b = Control::KeyUpdate { new_pk: [0; 32] }.encode();
        b.pop();
        assert!(Control::decode(&b).is_err());
    }
}
