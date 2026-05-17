// SPDX-License-Identifier: Apache-2.0

/// On-the-wire protocol version. Bumped to `0x03` for the P13 audit
/// sweep. Cumulative changes from `0x02`:
///
/// - **P2-5**: empty-tree Merkle root sentinel changed from `[0u8; 32]`
///   to `SHA256("ULLM-transparency-v1 empty")`.
/// - **P2-6**: `TreeHead.log_id` field added to the signed canonical
///   bytes (cross-log replay defense).
/// - **P3-7**: Several `Receipt` fields lost `#[serde(default)]` — a
///   sender omitting them on the wire is now rejected.
/// - **P4-1**: TEE identity-key signatures (bundle + handshake) prepend
///   distinct domain-separation prefixes, so a `v1` verifier reading a
///   `v2` bundle's signature would reject.
/// - **P13-FIX-D** (`0x02` → `0x03`): the `Receipt`'s `output_digest_hex`
///   now binds the canonical token-id stream (u32-LE length + ids)
///   instead of decoded UTF-8 bytes. A new `output_string_digest_hex`
///   field carries the decoded-text digest for UI/debug surfaces. A
///   `v2` verifier reading a `v3` receipt would reject deserialisation
///   because the new field has no `#[serde(default)]`.
///
/// A handshake initiated by an older client (sending `0x01` or `0x02`)
/// is rejected by the server with `Error::BadVersion`, surfacing the
/// mismatch cleanly instead of a confusing downstream signature
/// failure. Clients and servers MUST be built from the same revision.
pub const PROTOCOL_VERSION: u8 = 0x03;
pub const PROTOCOL_ID: &str = "ULLM-v1";

pub const MAX_PLAINTEXT_PER_RECORD: usize = 16 * 1024;
pub const NONCE_TTL_DEFAULT_SEC: u64 = 60;
pub const SESSION_TTL_DEFAULT_SEC: u64 = 300;
pub const ATTESTATION_CACHE_TTL_HOURS: u64 = 24;

/// Hard cap on the size of a single WebSocket message the gateway or TEE
/// will accept. Handshake bundles are ~3 KB, encrypted data frames are
/// bounded by `MAX_PLAINTEXT_PER_RECORD + header + AEAD tag`, proof frames
/// are tens of kilobytes — 256 KB leaves comfortable headroom while denying
/// a peer the ability to allocate-and-buffer multi-gigabyte WS frames.
pub const MAX_WS_MESSAGE_BYTES: usize = 256 * 1024;

/// Maximum length of the ML-KEM-768 encapsulation key carried in
/// `PreKeyBundle.pq_pk_mlkem`. The spec fixes this to 1184 bytes; we accept
/// the exact value and reject anything else as malformed.
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// Maximum length of the attestation-evidence blob carried in `PreKeyBundle`
/// and `ServerHello`. Real TDX/SEV-SNP/NRAS quotes are 1-2 KB; 8 KB is a
/// permissive ceiling that still kills the "send 4 GB evidence" DoS path.
pub const MAX_ATTESTATION_EVIDENCE_LEN: usize = 8 * 1024;

/// Hybrid KEX cipher-suite identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KemId {
    /// X25519 + ML-KEM-768 hybrid. Matches TLS group 0x11EC.
    X25519MlKem768 = 0x11EC,
}

impl KemId {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x11EC => Some(Self::X25519MlKem768),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AeadId {
    XChaCha20Poly1305 = 0x01,
    Aes256GcmSiv = 0x02,
}

impl AeadId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::XChaCha20Poly1305),
            0x02 => Some(Self::Aes256GcmSiv),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashId {
    Sha256 = 0x01,
    Sha384 = 0x02,
}

impl HashId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Sha256),
            0x02 => Some(Self::Sha384),
            _ => None,
        }
    }
}
