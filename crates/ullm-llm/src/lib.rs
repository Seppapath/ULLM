// SPDX-License-Identifier: Apache-2.0
//! Real-LLM adapter for the `InferenceEngine` trait.
//!
//! Phase 1 baseline shipped `ullm_tee::MockEngine` which echoes its prompt.
//! Slice 1 replaces that with a real safetensors-backed model. This crate
//! exposes:
//!
//! - [`RealLlmEngine`] — the production adapter. Holds the model handle,
//!   tokenizer, and a token-stream callback.
//! - The `candle` feature enables actual inference via the `candle-core`
//!   crate. Without the feature flag the adapter compiles to a thin shell
//!   that proves the wiring works (it returns a deterministic
//!   token-by-token response derived from a SHA-256 of the prompt).
//!
//! The honest reading: the protocol surface and trait integration are real
//! today; the production model file is supplied at deployment time. We do
//! not ship model weights in the repo (Llama license, file size).

use std::pin::Pin;

use tokio::sync::mpsc;

/// One streamed inference output piece (P13-FIX-D).
///
/// Mirrors `ullm_tee::TokenChunk`. We don't share the type across crates
/// to avoid a `ullm-llm` → `ullm-tee` dependency edge — the TEE adapter
/// that wraps a `RealLlmEngine` performs the trivial 1:1 conversion at
/// the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChunk {
    /// Canonical model-emitted token ids covered by this piece. Length 1
    /// for the real adapter (one decoded token per emit); can be longer
    /// for the stub which synthesises ids from UTF-8 codepoints.
    pub ids: Vec<u32>,
    /// Decoded UTF-8 piece the user sees. May be empty independently of
    /// `ids` (e.g. on tokenizer decode failure the engine should still
    /// emit the id so the digest stays bound to the model output).
    pub text: String,
}

impl TokenChunk {
    pub fn new(ids: Vec<u32>, text: String) -> Self {
        Self { ids, text }
    }
}

/// Mirror of `ullm_tee::inference::InferenceEngine`. We don't depend on
/// `ullm-tee` here to avoid a cyclical workspace; instead `ullm-tee`'s
/// engine adapter wraps a `RealLlmEngine`.
pub trait InferenceEngine: Send + Sync + 'static {
    fn run(
        &self,
        prompt: String,
        tx: mpsc::Sender<TokenChunk>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// Configuration for loading a real model.
#[derive(Clone, Debug)]
pub struct ModelConfig {
    pub weights_path: std::path::PathBuf,
    pub tokenizer_path: std::path::PathBuf,
    pub max_new_tokens: usize,
    pub chunk_size: usize,
}

#[cfg(feature = "candle")]
pub mod real;
#[cfg(feature = "candle")]
pub use real::RealLlmEngine;

#[cfg(not(feature = "candle"))]
pub mod stub;
#[cfg(not(feature = "candle"))]
pub use stub::RealLlmEngine;
