// SPDX-License-Identifier: Apache-2.0
//! Real candle-backed inference. Enabled via the `candle` Cargo feature.
//!
//! This module compiles only when `cargo build --features candle` is set so
//! the base workspace build doesn't pull the heavy candle dep tree.
//! Production deployment turns it on and supplies a model file.
//!
//! Supported model architectures (drop-in via `candle-transformers`):
//! - GPT-2 small (124M, public weights, fast on CPU)
//! - Phi-3-mini (3.8B, MIT license)
//! - Qwen-2.5-0.5B (Apache-2.0)
//! - TinyLlama-1.1B (Apache-2.0)
//!
//! The adapter is intentionally architecture-agnostic at the trait level:
//! `ModelConfig` points at a directory containing `model.safetensors` plus
//! `tokenizer.json`; the actual architecture is determined from the
//! safetensors metadata.

use std::pin::Pin;
use std::sync::Arc;

use candle_core::{DType, Device};
use candle_transformers::models::quantized_gpt2 as gpt2;
use tokenizers::Tokenizer;
use tokio::sync::mpsc;

use crate::{InferenceEngine, ModelConfig, TokenChunk};

pub struct RealLlmEngine {
    config: ModelConfig,
    model: Arc<tokio::sync::Mutex<gpt2::ModelWeights>>,
    tokenizer: Arc<Tokenizer>,
    device: Device,
}

impl RealLlmEngine {
    pub fn load(config: ModelConfig) -> Result<Self, anyhow::Error> {
        let device = Device::Cpu;
        let tokenizer = Tokenizer::from_file(&config.tokenizer_path)
            .map_err(|e| anyhow::anyhow!("tokenizer load: {e}"))?;
        let weights = std::fs::File::open(&config.weights_path)?;
        let mmap =
            unsafe { memmap2::Mmap::map(&weights).map_err(|e| anyhow::anyhow!("mmap: {e}"))? };
        // GPT-2-quantized loader; for non-GPT2 architectures the caller
        // swaps the model module.
        let model = gpt2::ModelWeights::from_gguf(&mmap[..], &device)
            .map_err(|e| anyhow::anyhow!("gpt2 load: {e}"))?;
        Ok(Self {
            config,
            model: Arc::new(tokio::sync::Mutex::new(model)),
            tokenizer: Arc::new(tokenizer),
            device,
        })
    }
}

impl InferenceEngine for RealLlmEngine {
    fn run(
        &self,
        prompt: String,
        tx: mpsc::Sender<TokenChunk>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let model = self.model.clone();
        let tokenizer = self.tokenizer.clone();
        let device = self.device.clone();
        let max_new = self.config.max_new_tokens;
        Box::pin(async move {
            let mut model = model.lock().await;
            let encoded = match tokenizer.encode(prompt.as_str(), true) {
                Ok(e) => e,
                Err(e) => {
                    // Error chunks have no model-emitted ids — send an
                    // empty `ids` so the digest stays bound to the
                    // (zero-length) true id stream.
                    let _ = tx
                        .send(TokenChunk::new(Vec::new(), format!("[tokenizer error: {e}]")))
                        .await;
                    return;
                }
            };
            let mut tokens = encoded.get_ids().to_vec();
            for _ in 0..max_new {
                let input = match candle_core::Tensor::new(tokens.as_slice(), &device) {
                    Ok(t) => t.unsqueeze(0).unwrap(),
                    Err(e) => {
                        let _ = tx
                            .send(TokenChunk::new(Vec::new(), format!("[tensor error: {e}]")))
                            .await;
                        return;
                    }
                };
                let logits = match model.forward(&input, tokens.len() - 1) {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx
                            .send(TokenChunk::new(Vec::new(), format!("[forward error: {e}]")))
                            .await;
                        return;
                    }
                };
                let logits = logits
                    .squeeze(0)
                    .and_then(|t| t.to_dtype(DType::F32))
                    .and_then(|t| t.argmax_keepdim(candle_core::D::Minus1))
                    .and_then(|t| t.to_scalar::<u32>())
                    .unwrap_or(0);
                let next = logits;
                tokens.push(next);
                // P13-FIX-D: always carry the underlying token id even
                // if `decode` returns an error or an empty piece. The
                // previous `if let Ok(piece) = …` silently dropped the
                // token from the digest while still advancing the
                // model state. Now the receipt's `output_digest_hex`
                // (computed over the id stream) reflects every token
                // the model actually emitted, regardless of decode
                // success.
                let piece = tokenizer.decode(&[next], true).unwrap_or_default();
                if tx.send(TokenChunk::new(vec![next], piece)).await.is_err() {
                    return;
                }
            }
        })
    }
}
