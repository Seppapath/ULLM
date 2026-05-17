// SPDX-License-Identifier: Apache-2.0
//! Wire format and replay-protection primitives.
//!
//! The on-wire layout is:
//!
//! ```text
//! | ver(1) | type(1) | flags(2) | seq(8) | epoch(4) | nonce(12) | ciphertext... | tag(16) |
//! ```
//!
//! Total header = 28 bytes. The header is authenticated as AEAD AAD; the
//! `nonce` field is the deterministic `epoch_be || seq_be` projection of the
//! frame's counter — it is redundant with the explicit `epoch` and `seq`
//! fields and is validated on decode for spec compliance and defense against
//! frame corruption.

pub mod codec;
pub mod control;
pub mod frame;
pub mod replay;

pub use codec::{decode_frame, encode_frame, EncodeOutput, HEADER_LEN};
pub use control::Control;
pub use frame::{ControlOp, FrameFlags, FrameType, Header};
pub use replay::ReplayWindow;
