// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use ullm_core::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuoteKind {
    Tdx,
    Snp,
    Mock,
}

/// CPU + GPU attestation evidence, freshness-bound by `report_data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub cpu_quote_kind: QuoteKind,
    pub cpu_quote: Vec<u8>,
    pub gpu_quote: Vec<u8>,
    /// X.509 chain bottom-up; for the mock backend a single self-signed cert.
    pub cert_chain: Vec<Vec<u8>>,
    /// Channel-binding payload that the handshake produced.
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],
    /// Unix seconds — used for freshness checks.
    pub issued_at_unix: u64,
}

pub fn encode_evidence(ev: &Evidence) -> Result<Vec<u8>> {
    postcard::to_allocvec(ev).map_err(|e| Error::Serde(e.to_string()))
}

pub fn decode_evidence(bytes: &[u8]) -> Result<Evidence> {
    postcard::from_bytes(bytes).map_err(|e| Error::Serde(e.to_string()))
}
