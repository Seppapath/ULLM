// SPDX-License-Identifier: Apache-2.0
//! Inference adapter trait + a deterministic mock implementation.
//!
//! P13-FIX-D: engines now stream `TokenChunk`s (canonical token-id sequence
//! plus the decoded UTF-8 piece) rather than raw `String`s. The receipt's
//! `output_digest_hex` is computed over the token-id stream — distinct token
//! sequences that decode to the same string therefore commit to distinct
//! digests, closing the BPE byte-fallback collision and the silent
//! decode-failure drop.

use std::pin::Pin;
use tokio::sync::mpsc;

/// One streamed inference output piece.
///
/// `ids` is the canonical model-emitted token-id sequence covered by this
/// piece (length 1 for the typical real-engine path; can be longer for
/// chunked synthetic engines). `text` is the decoded UTF-8 the user
/// receives. Either may be empty independently — a decode failure should
/// leave `text` empty *but still carry the ids* so the digest stays bound
/// to what the model produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChunk {
    pub ids: Vec<u32>,
    pub text: String,
}

impl TokenChunk {
    pub fn new(ids: Vec<u32>, text: String) -> Self {
        Self { ids, text }
    }
}

pub trait InferenceEngine: Send + Sync + 'static {
    /// Run inference. Implementations stream output tokens through the
    /// returned channel and close it when finished. `prompt` is the decrypted
    /// user prompt, never logged.
    fn run(
        &self,
        prompt: String,
        tx: mpsc::Sender<TokenChunk>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

pub struct MockEngine {
    chunk_size: usize,
    /// If set, emit exactly `n` chunks (filling each with `chunk_size` 'x'
    /// bytes after the "echo: <prompt>" prefix). Used by the long-stream
    /// mid-`key_update` test in Slice 9.
    chunks_to_emit: Option<usize>,
}

impl Default for MockEngine {
    fn default() -> Self {
        Self {
            chunk_size: 16,
            chunks_to_emit: None,
        }
    }
}

impl MockEngine {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            chunks_to_emit: None,
        }
    }

    /// Configure the engine to emit exactly `n` chunks of `chunk_size` bytes
    /// (after the "echo: " prefix on the first chunk). For deterministic
    /// long-stream tests.
    pub fn with_fixed_chunk_count(chunk_size: usize, n: usize) -> Self {
        Self {
            chunk_size,
            chunks_to_emit: Some(n),
        }
    }
}

/// P13-FIX-D: derive a deterministic "token id" sequence from a UTF-8
/// string. Because `MockEngine` has no real tokenizer, we map every
/// Unicode codepoint in the chunk to one synthetic `u32` token. This
/// keeps the digest binding meaningful (different prompts → different
/// id streams) without pretending to model a real BPE table.
fn synth_ids_for_text(text: &str) -> Vec<u32> {
    text.chars().map(|c| c as u32).collect()
}

impl InferenceEngine for MockEngine {
    fn run(
        &self,
        prompt: String,
        tx: mpsc::Sender<TokenChunk>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let chunk_size = self.chunk_size;
        let fixed = self.chunks_to_emit;
        Box::pin(async move {
            match fixed {
                None => {
                    let response = format!("echo: {}", prompt);
                    for chunk in chunked(&response, chunk_size) {
                        let ids = synth_ids_for_text(&chunk);
                        if tx.send(TokenChunk::new(ids, chunk)).await.is_err() {
                            return;
                        }
                    }
                }
                Some(n) => {
                    for i in 0..n {
                        let body = if i == 0 {
                            let mut s = format!("echo: {}", prompt);
                            while s.len() < chunk_size {
                                s.push('x');
                            }
                            s.truncate(chunk_size);
                            s
                        } else {
                            "x".repeat(chunk_size)
                        };
                        let ids = synth_ids_for_text(&body);
                        if tx.send(TokenChunk::new(ids, body)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        })
    }
}

fn chunked(s: &str, size: usize) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + size).min(bytes.len());
        let slice = &bytes[i..end];
        out.push(String::from_utf8_lossy(slice).into_owned());
        i = end;
    }
    out
}

/// Helper for tests: collect a full response from an engine.
pub async fn collect<E: InferenceEngine>(engine: &E, prompt: &str) -> String {
    let (tx, mut rx) = mpsc::channel(32);
    let fut = engine.run(prompt.to_owned(), tx);
    let collect_task = tokio::spawn(async move {
        let mut out = String::new();
        while let Some(c) = rx.recv().await {
            out.push_str(&c.text);
        }
        out
    });
    fut.await;
    collect_task.await.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_engine_echoes() {
        let e = MockEngine::default();
        let out = collect(&e, "hello").await;
        assert_eq!(out, "echo: hello");
    }

    /// Synthetic-id mapping is deterministic and surjective onto codepoints.
    #[test]
    fn synth_ids_round_trip_codepoints() {
        let ids = synth_ids_for_text("abc");
        assert_eq!(ids, vec![b'a' as u32, b'b' as u32, b'c' as u32]);
    }
}
