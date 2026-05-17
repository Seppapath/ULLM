// SPDX-License-Identifier: Apache-2.0
//! Frame encode/decode + AEAD glue.

use ullm_core::{Epoch, Error, Result, Seq, MAX_PLAINTEXT_PER_RECORD};
use ullm_crypto::{aead_open, aead_seal, frame_nonce, AeadKey, NonceSalt};

use crate::frame::{FrameFlags, FrameType, Header};

pub const HEADER_LEN: usize = 28;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct EncodeOutput {
    pub header: Header,
    pub wire: Vec<u8>,
}

/// Encode a frame: produce `header_bytes || ciphertext || tag`.
///
/// `key` MUST be a one-shot AEAD key derived from the chain ratchet for this
/// specific frame. The 24-byte XChaCha20 nonce is derived from the per-session
/// `salt` XOR `(epoch || seq)`.
pub fn encode_frame(
    key: &AeadKey,
    salt: &NonceSalt,
    frame_type: FrameType,
    flags: FrameFlags,
    epoch: Epoch,
    seq: Seq,
    plaintext: &[u8],
) -> Result<EncodeOutput> {
    if plaintext.len() > MAX_PLAINTEXT_PER_RECORD {
        return Err(Error::LongFrame(plaintext.len()));
    }
    let header = Header::new(frame_type, flags, epoch, seq);
    let header_bytes = write_header(&header);
    let nonce = frame_nonce(salt, epoch.0, seq.0);
    let ct = aead_seal(key, &nonce, &header_bytes, plaintext);
    let mut wire = Vec::with_capacity(HEADER_LEN + ct.len());
    wire.extend_from_slice(&header_bytes);
    wire.extend_from_slice(&ct);
    Ok(EncodeOutput { header, wire })
}

/// Decode a frame: parse header, verify nonce-field consistency, then AEAD-open.
pub fn decode_frame(key: &AeadKey, salt: &NonceSalt, wire: &[u8]) -> Result<(Header, Vec<u8>)> {
    if wire.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::ShortFrame(wire.len()));
    }
    let (header_bytes, rest) = wire.split_at(HEADER_LEN);
    let header = read_header(header_bytes)?;
    if header.nonce_field != header.expected_nonce_field() {
        return Err(Error::Decrypt);
    }
    let nonce = frame_nonce(salt, header.epoch.0, header.seq.0);
    let plaintext = aead_open(key, &nonce, header_bytes, rest)?;
    Ok((header, plaintext))
}

fn write_header(h: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = h.version;
    out[1] = h.frame_type as u8;
    out[2..4].copy_from_slice(&h.flags.bits().to_be_bytes());
    out[4..12].copy_from_slice(&h.seq.0.to_be_bytes());
    out[12..16].copy_from_slice(&h.epoch.0.to_be_bytes());
    out[16..28].copy_from_slice(&h.nonce_field);
    out
}

fn read_header(b: &[u8]) -> Result<Header> {
    if b.len() != HEADER_LEN {
        return Err(Error::ShortFrame(b.len()));
    }
    let version = b[0];
    if version != ullm_core::PROTOCOL_VERSION {
        return Err(Error::BadVersion {
            got: version,
            expected: ullm_core::PROTOCOL_VERSION,
        });
    }
    let frame_type = FrameType::from_u8(b[1]).ok_or(Error::BadFrameType(b[1]))?;
    // P2-10: zero out bits 12-15 (currently undefined) so a future flag added
    // at those positions doesn't get silently honoured by older code that
    // hasn't been re-deployed. The STREAM_ID_MASK occupies bits 4-11; all
    // defined flags live in bits 0-3 or the stream-id window.
    let flags = FrameFlags::from_bits_truncate(u16::from_be_bytes([b[2], b[3]]));
    let mut seq_arr = [0u8; 8];
    seq_arr.copy_from_slice(&b[4..12]);
    let seq = Seq(u64::from_be_bytes(seq_arr));
    let mut epoch_arr = [0u8; 4];
    epoch_arr.copy_from_slice(&b[12..16]);
    let epoch = Epoch(u32::from_be_bytes(epoch_arr));
    let mut nonce_field = [0u8; 12];
    nonce_field.copy_from_slice(&b[16..28]);
    Ok(Header {
        version,
        frame_type,
        flags,
        seq,
        epoch,
        nonce_field,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ullm_crypto::NonceSalt;

    fn fixed_key() -> AeadKey {
        AeadKey([0x42; 32])
    }
    fn fixed_salt() -> NonceSalt {
        NonceSalt([0x77; 24])
    }

    #[test]
    fn encode_decode_roundtrip() {
        let k = fixed_key();
        let s = fixed_salt();
        let out = encode_frame(
            &k,
            &s,
            FrameType::Data,
            FrameFlags::END_OF_TURN,
            Epoch(3),
            Seq(7),
            b"hello",
        )
        .unwrap();
        let (h, pt) = decode_frame(&k, &s, &out.wire).unwrap();
        assert_eq!(h.frame_type, FrameType::Data);
        assert!(h.flags.contains(FrameFlags::END_OF_TURN));
        assert_eq!(h.epoch.0, 3);
        assert_eq!(h.seq.0, 7);
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn tampered_header_breaks_decryption() {
        let k = fixed_key();
        let s = fixed_salt();
        let mut out = encode_frame(&k, &s, FrameType::Data, FrameFlags::empty(), Epoch(1), Seq(1), b"x")
            .unwrap()
            .wire;
        // flip a flag bit
        out[2] ^= 0x01;
        assert!(decode_frame(&k, &s, &out).is_err());
    }

    #[test]
    fn mismatched_nonce_field_rejected() {
        let k = fixed_key();
        let s = fixed_salt();
        let mut out = encode_frame(&k, &s, FrameType::Data, FrameFlags::empty(), Epoch(1), Seq(1), b"x")
            .unwrap()
            .wire;
        // corrupt the nonce_field
        out[16] ^= 0xFF;
        assert!(decode_frame(&k, &s, &out).is_err());
    }

    #[test]
    fn rejects_long_plaintext() {
        let k = fixed_key();
        let s = fixed_salt();
        let pt = vec![0u8; MAX_PLAINTEXT_PER_RECORD + 1];
        assert!(encode_frame(&k, &s, FrameType::Data, FrameFlags::empty(), Epoch(0), Seq(0), &pt).is_err());
    }

    /// Regression for P2-10: a malicious peer that sets bits 12-15 in the
    /// flags field — even if they somehow forged a valid AEAD tag — must
    /// have those bits normalized away on decode rather than retained for
    /// some future flag definition to silently honour.
    #[test]
    fn unknown_flag_bits_are_normalized_on_read() {
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes[0] = ullm_core::PROTOCOL_VERSION;
        header_bytes[1] = FrameType::Data as u8;
        // Flags = END_OF_TURN | bits 12-15 set.
        let flag_word: u16 = FrameFlags::END_OF_TURN.bits() | 0xF000;
        header_bytes[2..4].copy_from_slice(&flag_word.to_be_bytes());
        // nonce_field needs to be epoch_be || seq_be for header consistency.
        header_bytes[4..12].copy_from_slice(&0u64.to_be_bytes());
        header_bytes[12..16].copy_from_slice(&0u32.to_be_bytes());
        header_bytes[16..20].copy_from_slice(&0u32.to_be_bytes());
        header_bytes[20..28].copy_from_slice(&0u64.to_be_bytes());

        let header = read_header(&header_bytes).expect("parses");
        // Unknown bits dropped; defined bits preserved.
        assert!(header.flags.contains(FrameFlags::END_OF_TURN));
        assert_eq!(
            header.flags.bits() & 0xF000,
            0,
            "bits 12-15 must be zeroed by from_bits_truncate"
        );
    }
}
