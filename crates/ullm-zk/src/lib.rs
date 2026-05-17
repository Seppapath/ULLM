// SPDX-License-Identifier: Apache-2.0
//! Phase 2 zero-knowledge: prove knowledge of a 2-element Poseidon preimage.
//!
//! Public input: a single 32-byte digest `H` (a Pallas `Fp` field element).
//! Witness: two `Fp` elements `(x, y)`.
//! Constraint: `H = Poseidon_P128Pow5T3(x, y)`.
//!
//! The TEE encodes its `(input_hash, output_hash)` pair as `(x, y)`, computes
//! `H` natively (Poseidon primitive — same as the in-circuit gadget), and
//! generates a proof of knowledge of `(x, y)`. After P13-FIX-D the
//! receipt's `output_digest_hex` binds the **token-id stream** rather
//! than the decoded UTF-8; the legacy SHA-256-over-bytes digest the
//! preimage opens now lives in `output_string_digest_hex`. Callers that
//! still want to open the byte-digest commitment recover `H` from
//! `output_string_digest_hex` and run `Verifier::verify` as before.
//!
//! Phase 3 swaps the preimage for actual inference activations + intermediate
//! computations; the API surface stays the same.

mod circuit;
pub mod layer;

pub use circuit::{
    digest_from_inputs, fp_from_bytes, fp_to_bytes, setup, Proof, Prover, ProverParams,
    VerifyError, Verifier, VerifierParams,
};
pub use layer::{
    build_instance, domain_x, domain_y, session_id_to_fp, setup_layer, split_commit_to_fp,
    tagged_vector_hash, LayerProof, LayerProver, LayerProverParams, LayerVerifier,
    LayerVerifierParams, LAYER_CIRCUIT_K, NUM_INSTANCES, TAGGED_LEN, VEC_DIM,
};

pub use halo2_proofs::pasta::Fp;
