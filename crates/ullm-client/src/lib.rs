// SPDX-License-Identifier: Apache-2.0
//! Client SDK.
//!
//! ```no_run
//! # use ullm_client::{Session, TlsPinning};
//! # use ed25519_dalek::VerifyingKey;
//! # async fn run(
//! #     trust_root: VerifyingKey,
//! #     tee_pk: VerifyingKey,
//! #     fp: [u8; 32],
//! #     weight_commit: [u8; 32],
//! # ) -> anyhow::Result<()> {
//! let tls = Some(TlsPinning::pin("localhost", fp));
//! let mut session =
//!     Session::connect("https://127.0.0.1:9000", &trust_root, &tee_pk, weight_commit, tls).await?;
//! let mut stream = session.send("hello").await?;
//! while let Some(chunk) = stream.next_token().await? {
//!     print!("{chunk}");
//! }
//! let receipt = stream.finalize().await?;
//! println!("\nbilled {} tokens", receipt.receipt.output_tokens);
//! # Ok(()) }
//! ```

mod attest_check;
mod session;

pub use attest_check::verify_bundle;
pub use session::{LayerVerifier, Session, TlsPinning, TokenStream};
