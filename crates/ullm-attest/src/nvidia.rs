// SPDX-License-Identifier: Apache-2.0
//! NVIDIA NRAS GPU attestation parser.
//!
//! NRAS evidence is a JSON document — typically a JWS (JSON Web Signature)
//! over a payload claiming the GPU's measurement, attestation key, and a
//! `nonce` echoed from the requester. This module parses the **payload**
//! (the part inside the JWS) and extracts the fields ullm cares about.
//!
//! The full NRAS verifier (PKI validation, OCSP, RIM lookup) lives outside
//! Phase 1; we accept user-supplied trust roots downstream.

use serde::Deserialize;
use ullm_core::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct NvidiaPayload {
    /// Hex-encoded SHA-256 (or similar) of the requester nonce; the client
    /// recomputes and matches.
    #[serde(default)]
    pub nonce: String,
    /// GPU architecture (e.g., "Hopper", "Blackwell").
    #[serde(default)]
    pub arch: String,
    /// Per-GPU UUID.
    #[serde(default, alias = "gpu_uuid")]
    pub gpu_uuid: String,
    /// VBIOS measurement (hex).
    #[serde(default)]
    pub vbios_version: String,
    /// Driver version string.
    #[serde(default)]
    pub driver_version: String,
    /// Measurement (typically hex-encoded SHA-384 of attested code).
    #[serde(default, alias = "measurement_hex")]
    pub measurement_hex: String,
    /// Free-form claim bag for any other field the verifier wants to inspect.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct NvidiaQuote {
    pub payload: NvidiaPayload,
    /// Hex-decoded signature bytes (if the JWS was provided); empty otherwise.
    pub signature: Vec<u8>,
    /// Raw payload bytes — the message that the signature covers.
    pub signed_message: Vec<u8>,
}

impl NvidiaQuote {
    /// Parse from a JWS compact-serialization string:
    /// `<base64url(header)>.<base64url(payload)>.<base64url(signature)>`
    ///
    /// Or from a plain JSON object (no JWS wrapping) in which case
    /// `signature` is empty.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let s = std::str::from_utf8(bytes)
            .map_err(|_| Error::AttestationFailed("NRAS evidence is not UTF-8".into()))?;
        let parts: Vec<&str> = s.split('.').collect();
        match parts.as_slice() {
            [hdr, pl, sig] => {
                let payload_bytes = b64url_decode(pl)?;
                let payload: NvidiaPayload = serde_json::from_slice(&payload_bytes)
                    .map_err(|e| Error::AttestationFailed(format!("JWS payload: {e}")))?;
                let signature = b64url_decode(sig)?;
                let signed_message = {
                    let mut v = Vec::with_capacity(hdr.len() + 1 + pl.len());
                    v.extend_from_slice(hdr.as_bytes());
                    v.push(b'.');
                    v.extend_from_slice(pl.as_bytes());
                    v
                };
                Ok(Self {
                    payload,
                    signature,
                    signed_message,
                })
            }
            _ => {
                // Treat as plain JSON; no signature.
                let payload: NvidiaPayload = serde_json::from_str(s)
                    .map_err(|e| Error::AttestationFailed(format!("NRAS payload: {e}")))?;
                Ok(Self {
                    payload,
                    signature: vec![],
                    signed_message: s.as_bytes().to_vec(),
                })
            }
        }
    }

    /// The `nonce` claim that the client previously provided to NRAS, used
    /// for freshness binding.
    pub fn nonce_hex(&self) -> &str {
        &self.payload.nonce
    }
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    // Tiny RFC 4648 §5 base64url-no-pad decoder; avoids pulling in a crate.
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity((s.len() * 3) / 4 + 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for ch in s.chars() {
        let v = match ch {
            'A'..='Z' => (ch as u32) - ('A' as u32),
            'a'..='z' => (ch as u32) - ('a' as u32) + 26,
            '0'..='9' => (ch as u32) - ('0' as u32) + 52,
            '-' => 62,
            '_' => 63,
            _ => return Err(Error::AttestationFailed(format!("bad b64url char {ch:?}"))),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_json() {
        let json = r#"{"nonce":"abcd","arch":"Hopper","gpu_uuid":"GPU-1234"}"#;
        let q = NvidiaQuote::parse(json.as_bytes()).unwrap();
        assert_eq!(q.payload.nonce, "abcd");
        assert_eq!(q.payload.arch, "Hopper");
        assert!(q.signature.is_empty());
    }

    #[test]
    fn parses_jws_compact() {
        // header `{"alg":"ES384"}`, payload `{"nonce":"deadbeef","arch":"Blackwell"}`, sig = 3 bytes.
        let hdr = "eyJhbGciOiJFUzM4NCJ9";
        let pl = "eyJub25jZSI6ImRlYWRiZWVmIiwiYXJjaCI6IkJsYWNrd2VsbCJ9";
        let sig = "AQID"; // 3-byte sig
        let jws = format!("{hdr}.{pl}.{sig}");
        let q = NvidiaQuote::parse(jws.as_bytes()).unwrap();
        assert_eq!(q.payload.nonce, "deadbeef");
        assert_eq!(q.payload.arch, "Blackwell");
        assert_eq!(q.signature, vec![1, 2, 3]);
        assert_eq!(q.signed_message, format!("{hdr}.{pl}").into_bytes());
    }
}
