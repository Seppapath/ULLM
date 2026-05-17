// SPDX-License-Identifier: Apache-2.0
//! Stub implementation for the default (no-candle) build.
//!
//! Honest constraints:
//!
//! - The full inference path requires the `candle` feature.
//! - Without it, this adapter still implements `InferenceEngine` (the trait
//!   is the real protocol surface) and emits a deterministic SHA-256-derived
//!   token sequence so end-to-end tests can exercise the data path.

use std::pin::Pin;

use tokio::sync::mpsc;

use crate::{InferenceEngine, ModelConfig, TokenChunk};

pub struct RealLlmEngine {
    config: ModelConfig,
}

impl RealLlmEngine {
    pub fn load(config: ModelConfig) -> Result<Self, std::io::Error> {
        // Confirm the files exist, but don't load them; the stub doesn't use them.
        if !config.weights_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("weights not found at {:?}", config.weights_path),
            ));
        }
        if !config.tokenizer_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("tokenizer not found at {:?}", config.tokenizer_path),
            ));
        }
        Ok(Self { config })
    }
}

impl InferenceEngine for RealLlmEngine {
    fn run(
        &self,
        prompt: String,
        tx: mpsc::Sender<TokenChunk>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let cfg = self.config.clone();
        Box::pin(async move {
            // Deterministic placeholder output derived from prompt bytes.
            use sha2::{Digest, Sha256};
            let digest: [u8; 32] = Sha256::digest(prompt.as_bytes()).into();
            let response = format!(
                "[stub-llm/{}] {}",
                hex_short(&digest),
                prompt
            );
            for chunk in response.as_bytes().chunks(cfg.chunk_size.max(1)) {
                let s = String::from_utf8_lossy(chunk).into_owned();
                // P13-FIX-D: synthesise one fake token id per UTF-8
                // codepoint. No real tokenizer here — the goal is just
                // to keep the digest binding deterministic and
                // distinguishable across distinct prompts.
                let ids: Vec<u32> = s.chars().map(|c| c as u32).collect();
                if tx.send(TokenChunk::new(ids, s)).await.is_err() {
                    return;
                }
            }
        })
    }
}

fn hex_short(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &d[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
