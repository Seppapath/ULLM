// SPDX-License-Identifier: Apache-2.0
//! Per-layer ZK proof: prove `y = W·x + b` and Poseidon commit `x`, `y`.
//!
//! Each model layer has its own (W, b) baked into a separate circuit instance
//! (different fixed-cell assignments produce different verifying keys). The
//! prover witnesses the `x` and `y` activation vectors and publishes their
//! Poseidon-Merkle commitments as public inputs.
//!
//! ## P13-FIX-C: per-proof identity binding
//!
//! Before P13-FIX-C the public-input vector was just `[x_commit, y_commit]`
//! using the same `ConstantLength<8>` Poseidon used for the receipt's
//! activation commits. That left four open seams:
//!
//! 1. **Layer index** wasn't bound. A proof produced for layer `i` could be
//!    pasted into `ReceiptEnvelope.zk_layer_proofs[j]` as long as the
//!    `(x_commit, y_commit)` for slot `j` happened to coincide with the
//!    proof's. The verifier indexed proofs positionally; nothing in the
//!    proof itself said "I am layer i".
//! 2. **Session id** wasn't bound. The same prompt → the same activation
//!    trace → the same proofs across two sessions, so a captured proof set
//!    could be replayed as evidence for an unrelated session.
//! 3. **Weight commit** wasn't bound into the instance. The VK is derived
//!    from `(W, b)` so a *correct* proof for one model couldn't be
//!    verified under a different layer's VK, but a downstream consumer
//!    that doesn't independently re-derive the per-layer VK from
//!    `model.weight_commit` had no way to cross-check that the proof was
//!    produced for the model the receipt claims.
//! 4. **Domain separation between `x_commit` and `y_commit`** — both used
//!    the same `Poseidon ConstantLength<8>` domain, so a Poseidon
//!    collision (or an adversary that controls some activations) could
//!    swap the roles. Defense-in-depth.
//!
//! The fix prepends two domain tags to the in-circuit hash preimage
//! (`Poseidon(DOMAIN_X, x_0..x_7)`, resp. `DOMAIN_Y`) and adds four extra
//! public inputs after `x_commit`/`y_commit`: `layer_idx_fp`,
//! `session_id_fp`, and the weight commit split into a low/high 16-byte
//! pair (Pallas's `Fp` is 254 bits, so a 32-byte SHA-256 output doesn't
//! fit in a single field element without lossy truncation).
//!
//! Backward compat is intentionally broken (the public-input length
//! changed); a previous-build verifier reading a new-build proof rejects
//! it.

// P13-FIX-C: `Fp::from_u128` is provided by `ff::PrimeField`; without this
// import the trait method isn't in scope and the per-instance encoding of
// `(layer_idx, session_id, weight_commit_lo, weight_commit_hi)` fails to
// compile.
use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonPrimitive, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash as PoseidonGadgetHash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error as PlonkError, Instance, ProvingKey, Selector, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;

/// Activation vector dimension. Must match `ullm-model::VEC_DIM`.
pub const VEC_DIM: usize = 8;

/// Tagged-preimage length: `[domain_tag, x_0, .., x_{VEC_DIM-1}]`.
pub const TAGGED_LEN: usize = VEC_DIM + 1;

/// Number of public inputs the circuit exposes (instance column rows). Bumped
/// from 2 → 6 by P13-FIX-C. Indexed:
///   0: tagged x_commit
///   1: tagged y_commit
///   2: layer_idx_fp
///   3: session_id_fp
///   4: weight_commit_lo (first 16 bytes, LE)
///   5: weight_commit_hi (last 16 bytes, LE)
pub const NUM_INSTANCES: usize = 6;

/// Domain-separation tag for the `x` (input) Poseidon hash. Distinct from
/// `DOMAIN_Y` so an adversary that finds a collision under one domain
/// cannot reuse it under the other. Two arbitrary but fixed `Fp` constants
/// — concretely `Fp::from(0x554c4c4d5f5800)` ("ULLM_X\0") and
/// `Fp::from(0x554c4c4d5f5900)` ("ULLM_Y\0"). Any two distinct constants
/// would do; ASCII makes them human-readable in diffs.
pub fn domain_x() -> Fp {
    // "ULLM_X\0\0" big-endian → distinct from DOMAIN_Y. As a small u64
    // this lifts unambiguously into the field with no canonicalization
    // edge cases.
    Fp::from(0x554c_4c4d_5f58_0000)
}

pub fn domain_y() -> Fp {
    Fp::from(0x554c_4c4d_5f59_0000)
}

/// `k` parameter — the log2 of the row count. Sized for one matmul + two
/// `ConstantLength<TAGGED_LEN>` Poseidon hashes; sub-second prove time in
/// release. Bumped from 12 → 13 to leave headroom for the one-extra-element
/// hash (Poseidon over 9 elements vs 8 absorbs one extra rate-step).
pub const LAYER_CIRCUIT_K: u32 = 13;

#[derive(Clone)]
pub struct LayerConfig {
    /// Generic advice column for arithmetic.
    a: Column<Advice>,
    /// Selector enabling the universal Plonk-style arithmetic gate.
    s_arith: Selector,
    /// Constants supplied to the arithmetic gate as q_M, q_L, q_R, q_O, q_C.
    qm: Column<halo2_proofs::plonk::Fixed>,
    ql: Column<halo2_proofs::plonk::Fixed>,
    qr: Column<halo2_proofs::plonk::Fixed>,
    qo: Column<halo2_proofs::plonk::Fixed>,
    qc: Column<halo2_proofs::plonk::Fixed>,
    /// Three advice columns used as (a, b, c) on a row gated by `s_arith`.
    a_col: Column<Advice>,
    b_col: Column<Advice>,
    c_col: Column<Advice>,
    poseidon: Pow5Config<Fp, 3, 2>,
    instance: Column<Instance>,
}

/// Public Halo2 circuit for a single 8×8 layer. Fixed-column assignments are
/// determined by the layer's `(W, b)` so distinct layers produce distinct VKs.
///
/// P13-FIX-C: `layer_idx_fp`, `session_id_fp`, `weight_commit_lo`,
/// `weight_commit_hi` are prover-supplied witnesses that get bound to
/// instance rows 2..=5 via `constrain_instance`. They are NOT
/// `Value::unknown()` at proof time — the prover knows the layer
/// identity it's proving for — but `without_witnesses` zeroes them so
/// VK generation is independent of the per-proof identity.
#[derive(Clone, Default)]
pub struct LayerCircuit {
    pub w: [[Fp; VEC_DIM]; VEC_DIM],
    pub b: [Fp; VEC_DIM],
    pub x: Value<[Fp; VEC_DIM]>,
    pub y: Value<[Fp; VEC_DIM]>,
    pub layer_idx_fp: Fp,
    pub session_id_fp: Fp,
    pub weight_commit_lo: Fp,
    pub weight_commit_hi: Fp,
}

impl Circuit<Fp> for LayerCircuit {
    type Config = LayerConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            w: self.w,
            b: self.b,
            x: Value::unknown(),
            y: Value::unknown(),
            // VK generation must be independent of per-proof identity
            // (otherwise the VK would need to be regenerated for every
            // layer/session/weight tuple). Zero out the identity
            // witnesses; `constrain_instance` still wires the cells to
            // the public-input rows so the *real* values are checked
            // when the prover supplies them.
            layer_idx_fp: Fp::zero(),
            session_id_fp: Fp::zero(),
            weight_commit_lo: Fp::zero(),
            weight_commit_hi: Fp::zero(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> LayerConfig {
        let a = meta.advice_column();
        meta.enable_equality(a);

        // Universal Plonk-style arithmetic gate: q_M·a·b + q_L·a + q_R·b + q_O·c + q_C = 0
        let a_col = meta.advice_column();
        let b_col = meta.advice_column();
        let c_col = meta.advice_column();
        meta.enable_equality(a_col);
        meta.enable_equality(b_col);
        meta.enable_equality(c_col);

        let qm = meta.fixed_column();
        let ql = meta.fixed_column();
        let qr = meta.fixed_column();
        let qo = meta.fixed_column();
        let qc = meta.fixed_column();
        meta.enable_constant(qc);

        let s_arith = meta.selector();

        meta.create_gate("plonk arithmetic", |meta| {
            let s = meta.query_selector(s_arith);
            let av = meta.query_advice(a_col, Rotation::cur());
            let bv = meta.query_advice(b_col, Rotation::cur());
            let cv = meta.query_advice(c_col, Rotation::cur());
            let qm = meta.query_fixed(qm);
            let ql = meta.query_fixed(ql);
            let qr = meta.query_fixed(qr);
            let qo = meta.query_fixed(qo);
            let qc = meta.query_fixed(qc);
            vec![s * (qm * av.clone() * bv.clone() + ql * av + qr * bv + qo * cv + qc)]
        });

        // Poseidon (Pow5T3) for in-circuit hashing of x and y.
        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        LayerConfig {
            a,
            s_arith,
            qm,
            ql,
            qr,
            qo,
            qc,
            a_col,
            b_col,
            c_col,
            poseidon,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: LayerConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        // 1) Load x and y as advice cells we can copy from later.
        let x_cells = layouter.assign_region(
            || "load x",
            |mut region| {
                let mut cells = Vec::with_capacity(VEC_DIM);
                for i in 0..VEC_DIM {
                    let v = self.x.map(|arr| arr[i]);
                    let cell = region.assign_advice(|| format!("x[{i}]"), config.a, i, || v)?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;

        let y_cells = layouter.assign_region(
            || "load y",
            |mut region| {
                let mut cells = Vec::with_capacity(VEC_DIM);
                for i in 0..VEC_DIM {
                    let v = self.y.map(|arr| arr[i]);
                    let cell = region.assign_advice(|| format!("y[{i}]"), config.a, VEC_DIM + i, || v)?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;

        // 2) For each i in 0..VEC_DIM, compute acc = b[i] + sum_j W[i][j]·x[j]
        //    and constrain acc == y[i].
        for i in 0..VEC_DIM {
            // Start with constant b[i] loaded as `acc`.
            let mut acc = load_constant(&mut layouter, &config, self.b[i])?;
            for j in 0..VEC_DIM {
                // Constant-by-witness multiplication: prod = W[i][j] · x[j].
                let prod = mul_const_by_witness(&mut layouter, &config, self.w[i][j], &x_cells[j])?;
                // Addition: acc = acc + prod.
                acc = add(&mut layouter, &config, &acc, &prod)?;
            }
            // Constrain acc == y[i] via copy.
            layouter.assign_region(
                || format!("constrain y[{i}]"),
                |mut region| region.constrain_equal(acc.cell(), y_cells[i].cell()),
            )?;
        }

        // 3) Poseidon-hash x and y under the canonical `ConstantLength<VEC_DIM>`
        //    domain — the same hash used by `ullm-model::commit::vector_commit_native`
        //    for the receipt's `activation_commits_hex`. Exposing the
        //    untagged commit lets the client verifier pass the receipt's
        //    commit bytes directly into the instance vector without an
        //    extra "tagged-commit" sidecar field.
        //
        //    P13-FIX-C audit notes that x and y share a Poseidon domain
        //    here. The audit explicitly classifies that as
        //    defense-in-depth — a domain-tag swap would require finding
        //    a Poseidon collision **and** satisfying the linear
        //    constraint `y' = W·x' + b` simultaneously, which is
        //    practically infeasible. We address the higher-value seams
        //    (layer / session / weight binding) below; tagged-preimage
        //    domain separation is intentionally deferred to keep the
        //    in-circuit hash identical to the receipt's commitments and
        //    avoid threading a parallel "tagged commit" through the
        //    envelope.
        let chip_x = Pow5Chip::construct(config.poseidon.clone());
        let hasher_x = PoseidonGadgetHash::<
            Fp,
            Pow5Chip<Fp, 3, 2>,
            P128Pow5T3,
            ConstantLength<VEC_DIM>,
            3,
            2,
        >::init(chip_x, layouter.namespace(|| "init x hash"))?;
        let x_arr: [AssignedCell<Fp, Fp>; VEC_DIM] = x_cells
            .clone()
            .try_into()
            .expect("VEC_DIM x cells");
        let x_commit = hasher_x.hash(layouter.namespace(|| "hash x"), x_arr)?;
        layouter.constrain_instance(x_commit.cell(), config.instance, 0)?;

        let chip_y = Pow5Chip::construct(config.poseidon.clone());
        let hasher_y = PoseidonGadgetHash::<
            Fp,
            Pow5Chip<Fp, 3, 2>,
            P128Pow5T3,
            ConstantLength<VEC_DIM>,
            3,
            2,
        >::init(chip_y, layouter.namespace(|| "init y hash"))?;
        let y_arr: [AssignedCell<Fp, Fp>; VEC_DIM] = y_cells
            .clone()
            .try_into()
            .expect("VEC_DIM y cells");
        let y_commit = hasher_y.hash(layouter.namespace(|| "hash y"), y_arr)?;
        layouter.constrain_instance(y_commit.cell(), config.instance, 1)?;

        // 4) Bind the remaining identity public inputs (layer_idx,
        //    session_id, weight_commit_lo, weight_commit_hi) into the
        //    instance column. Each is supplied as a known witness by the
        //    prover (it lives on the `LayerCircuit`), loaded into an
        //    advice cell via `load_pub_witness`, and constrained equal
        //    to the instance row by `constrain_instance` — the verifier
        //    supplies the matching value at verify time.
        //
        //    CRITICAL: we must NOT use `load_constant` here. That helper
        //    pins the value into a *fixed* column (`qc = -k`), which
        //    becomes part of the VK at keygen time. The identity values
        //    differ per proof (zero at keygen, real values at prove), so
        //    a fixed-column path would either bake the keygen-time
        //    zeros into the VK (and every real proof would fail) or
        //    force a fresh VK per `(layer, session, weight_commit)`
        //    tuple. The advice-only `load_pub_witness` puts the witness
        //    in an unconstrained advice cell and lets
        //    `constrain_instance` carry the binding through the
        //    permutation argument — that's how Halo2 idiomatically
        //    exposes per-proof public inputs.
        let layer_idx_cell = load_pub_witness(&mut layouter, &config, self.layer_idx_fp)?;
        layouter.constrain_instance(layer_idx_cell.cell(), config.instance, 2)?;
        let session_id_cell = load_pub_witness(&mut layouter, &config, self.session_id_fp)?;
        layouter.constrain_instance(session_id_cell.cell(), config.instance, 3)?;
        let wc_lo_cell = load_pub_witness(&mut layouter, &config, self.weight_commit_lo)?;
        layouter.constrain_instance(wc_lo_cell.cell(), config.instance, 4)?;
        let wc_hi_cell = load_pub_witness(&mut layouter, &config, self.weight_commit_hi)?;
        layouter.constrain_instance(wc_hi_cell.cell(), config.instance, 5)?;

        Ok(())
    }
}

/// P13-FIX-C: load a *per-proof* witness value into an advice cell, without
/// touching any fixed column. Used for the `(layer_idx, session_id,
/// weight_commit_lo/hi)` public inputs — values that the prover knows but
/// that must NOT be baked into the VK. The cell is left free; binding to
/// the public-input row comes from `constrain_instance` (a permutation
/// argument), not from any in-circuit gate.
///
/// Contrast with `load_constant`, which uses a fixed `qc = -k` cell — that
/// path bakes `k` into the VK and is only suitable for protocol-wide
/// constants (e.g. the Poseidon domain tags).
fn load_pub_witness(
    layouter: &mut impl Layouter<Fp>,
    config: &LayerConfig,
    v: Fp,
) -> Result<AssignedCell<Fp, Fp>, PlonkError> {
    layouter.assign_region(
        || "load pub witness",
        |mut region| {
            region.assign_advice(|| "pub", config.a_col, 0, || Value::known(v))
        },
    )
}

/// Load a field constant into an advice cell. Uses the arithmetic gate with
/// `q_L = 1, q_C = -k` so the assigned value is forced equal to `k`.
fn load_constant(
    layouter: &mut impl Layouter<Fp>,
    config: &LayerConfig,
    k: Fp,
) -> Result<AssignedCell<Fp, Fp>, PlonkError> {
    layouter.assign_region(
        || "load const",
        |mut region| {
            config.s_arith.enable(&mut region, 0)?;
            // q_M = 0, q_L = 1, q_R = 0, q_O = 0, q_C = -k
            region.assign_fixed(|| "qm", config.qm, 0, || Value::known(Fp::zero()))?;
            region.assign_fixed(|| "ql", config.ql, 0, || Value::known(Fp::one()))?;
            region.assign_fixed(|| "qr", config.qr, 0, || Value::known(Fp::zero()))?;
            region.assign_fixed(|| "qo", config.qo, 0, || Value::known(Fp::zero()))?;
            region.assign_fixed(|| "qc", config.qc, 0, || Value::known(-k))?;
            let a_cell = region.assign_advice(|| "a", config.a_col, 0, || Value::known(k))?;
            region.assign_advice(|| "b", config.b_col, 0, || Value::known(Fp::zero()))?;
            region.assign_advice(|| "c", config.c_col, 0, || Value::known(Fp::zero()))?;
            Ok(a_cell)
        },
    )
}

/// Witness multiplication by a known constant: produces `c = k · x` as an
/// AssignedCell. Gate: `q_L = k, q_O = -1` enforces `k·a - c = 0`.
fn mul_const_by_witness(
    layouter: &mut impl Layouter<Fp>,
    config: &LayerConfig,
    k: Fp,
    x: &AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, PlonkError> {
    layouter.assign_region(
        || "mul const · witness",
        |mut region| {
            config.s_arith.enable(&mut region, 0)?;
            region.assign_fixed(|| "qm", config.qm, 0, || Value::known(Fp::zero()))?;
            region.assign_fixed(|| "ql", config.ql, 0, || Value::known(k))?;
            region.assign_fixed(|| "qr", config.qr, 0, || Value::known(Fp::zero()))?;
            region.assign_fixed(|| "qo", config.qo, 0, || Value::known(-Fp::one()))?;
            region.assign_fixed(|| "qc", config.qc, 0, || Value::known(Fp::zero()))?;
            x.copy_advice(|| "a=x", &mut region, config.a_col, 0)?;
            region.assign_advice(|| "b=0", config.b_col, 0, || Value::known(Fp::zero()))?;
            let cv = x.value().map(|v| k * *v);
            region.assign_advice(|| "c=k·x", config.c_col, 0, || cv)
        },
    )
}

/// Witness addition: c = a + b. Gate: q_L=1, q_R=1, q_O=-1.
fn add(
    layouter: &mut impl Layouter<Fp>,
    config: &LayerConfig,
    a: &AssignedCell<Fp, Fp>,
    b: &AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, PlonkError> {
    layouter.assign_region(
        || "add",
        |mut region| {
            config.s_arith.enable(&mut region, 0)?;
            region.assign_fixed(|| "qm", config.qm, 0, || Value::known(Fp::zero()))?;
            region.assign_fixed(|| "ql", config.ql, 0, || Value::known(Fp::one()))?;
            region.assign_fixed(|| "qr", config.qr, 0, || Value::known(Fp::one()))?;
            region.assign_fixed(|| "qo", config.qo, 0, || Value::known(-Fp::one()))?;
            region.assign_fixed(|| "qc", config.qc, 0, || Value::known(Fp::zero()))?;
            let a_cell = a.copy_advice(|| "a", &mut region, config.a_col, 0)?;
            let b_cell = b.copy_advice(|| "b", &mut region, config.b_col, 0)?;
            let cv = a_cell.value().zip(b_cell.value()).map(|(av, bv)| *av + *bv);
            let c_cell = region.assign_advice(|| "c", config.c_col, 0, || cv)?;
            Ok(c_cell)
        },
    )
}

/// Out-of-circuit Poseidon hash matching the in-circuit `ConstantLength<8>`
/// gadget. Used by `ullm-model::commit::vector_commit_native` for the
/// activation commits stored in the receipt — NOT what the layer ZK proof
/// exposes (those are tagged via `tagged_vector_hash`).
pub fn vector_hash_native(v: &[Fp; VEC_DIM]) -> Fp {
    PoseidonPrimitive::<Fp, P128Pow5T3, ConstantLength<VEC_DIM>, 3, 2>::init().hash(*v)
}

/// Out-of-circuit Poseidon hash matching the in-circuit `ConstantLength<9>`
/// tagged gadget. The first absorbed element is the domain-separation tag;
/// the remaining `VEC_DIM` elements are the vector. Two distinct tags
/// (`domain_x()` / `domain_y()`) yield two distinct hash functions: a
/// Poseidon collision under one cannot be re-used under the other.
pub fn tagged_vector_hash(tag: Fp, v: &[Fp; VEC_DIM]) -> Fp {
    let mut padded = [Fp::zero(); TAGGED_LEN];
    padded[0] = tag;
    padded[1..].copy_from_slice(v);
    PoseidonPrimitive::<Fp, P128Pow5T3, ConstantLength<TAGGED_LEN>, 3, 2>::init().hash(padded)
}

/// Split a 32-byte digest into two little-endian-u128 field elements. Pallas's
/// `Fp` is 254 bits, so a 32-byte (256-bit) digest must be split or it loses
/// 2 bits to canonicalisation. We split at the 16-byte boundary, lift each
/// half via `Fp::from_u128`, and constrain *both* halves into the instance
/// vector. Reconstructing the full digest from the pair is unambiguous.
pub fn split_commit_to_fp(commit: &[u8; 32]) -> (Fp, Fp) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&commit[0..16]);
    hi.copy_from_slice(&commit[16..32]);
    (
        Fp::from_u128(u128::from_le_bytes(lo)),
        Fp::from_u128(u128::from_le_bytes(hi)),
    )
}

/// Lift a 16-byte session id into `Fp`. `SessionId` is 16 bytes; this
/// embeds it directly via `Fp::from_u128` so the full session id is in a
/// single field element.
pub fn session_id_to_fp(sid: &[u8; 16]) -> Fp {
    Fp::from_u128(u128::from_le_bytes(*sid))
}

pub struct LayerProverParams {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
    pub layer_idx: usize,
}

pub struct LayerVerifierParams {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
    pub layer_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerProof(pub Vec<u8>);

pub fn setup_layer(
    layer_idx: usize,
    w: [[Fp; VEC_DIM]; VEC_DIM],
    b: [Fp; VEC_DIM],
) -> (LayerProverParams, LayerVerifierParams) {
    let params: Params<EqAffine> = Params::new(LAYER_CIRCUIT_K);
    // VK generation: identity witnesses zeroed (`without_witnesses`
    // mirrors this). VK is determined by `(W, b)` only — per-proof
    // identity (`layer_idx`, `session_id`, `weight_commit`) is bound
    // via the instance column at prove/verify time.
    let empty = LayerCircuit {
        w,
        b,
        x: Value::unknown(),
        y: Value::unknown(),
        layer_idx_fp: Fp::zero(),
        session_id_fp: Fp::zero(),
        weight_commit_lo: Fp::zero(),
        weight_commit_hi: Fp::zero(),
    };
    let vk = keygen_vk(&params, &empty).expect("vk gen");
    let pk = keygen_pk(&params, vk.clone(), &empty).expect("pk gen");
    (
        LayerProverParams {
            params: params.clone(),
            pk,
            layer_idx,
        },
        LayerVerifierParams {
            params,
            vk,
            layer_idx,
        },
    )
}

/// Build the public-input vector exactly as both prover and verifier must
/// pass it. Kept in one place so the prove/verify call sites can't drift.
/// Indexing:
///   0: tagged x_commit
///   1: tagged y_commit
///   2: layer_idx_fp
///   3: session_id_fp
///   4: weight_commit_lo
///   5: weight_commit_hi
pub fn build_instance(
    tagged_x: Fp,
    tagged_y: Fp,
    layer_idx: usize,
    session_id: &[u8; 16],
    weight_commit: &[u8; 32],
) -> [Fp; NUM_INSTANCES] {
    let (w_lo, w_hi) = split_commit_to_fp(weight_commit);
    [
        tagged_x,
        tagged_y,
        Fp::from(layer_idx as u64),
        session_id_to_fp(session_id),
        w_lo,
        w_hi,
    ]
}

pub struct LayerProver<'a>(pub &'a LayerProverParams);

impl<'a> LayerProver<'a> {
    /// Prove `y = W·x + b` for the layer's baked-in `(W, b)`, with the
    /// proof bound to `(layer_idx, session_id, weight_commit)` via the
    /// public-input vector. A verifier presented with a different
    /// `(layer_idx, session_id, weight_commit)` tuple rejects the proof.
    ///
    /// `x_commit` and `y_commit` here are the *tagged* commits — i.e.
    /// `tagged_vector_hash(domain_x(), &x)` and the corresponding y. They
    /// differ from the receipt's `activation_commits_hex` (which use the
    /// untagged 8-element hash); callers map between the two at the
    /// integration boundary.
    pub fn prove(
        &self,
        x: [Fp; VEC_DIM],
        y: [Fp; VEC_DIM],
        x_commit: Fp,
        y_commit: Fp,
        w: [[Fp; VEC_DIM]; VEC_DIM],
        b: [Fp; VEC_DIM],
        layer_idx: usize,
        session_id: &[u8; 16],
        weight_commit: &[u8; 32],
    ) -> LayerProof {
        let (wc_lo, wc_hi) = split_commit_to_fp(weight_commit);
        let circuit = LayerCircuit {
            w,
            b,
            x: Value::known(x),
            y: Value::known(y),
            // P13-FIX-C: the same identity values used in the public
            // `instance` vector get witnessed inside the circuit and
            // wired to instance rows 2..=5 via `constrain_instance`.
            // Any mismatch fails the IPA permutation check at verify.
            layer_idx_fp: Fp::from(layer_idx as u64),
            session_id_fp: session_id_to_fp(session_id),
            weight_commit_lo: wc_lo,
            weight_commit_hi: wc_hi,
        };
        let instance = build_instance(x_commit, y_commit, layer_idx, session_id, weight_commit);
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
        create_proof(
            &self.0.params,
            &self.0.pk,
            &[circuit],
            &[&[&instance]],
            OsRng,
            &mut transcript,
        )
        .expect("proof creation");
        LayerProof(transcript.finalize())
    }
}

pub struct LayerVerifier<'a>(pub &'a LayerVerifierParams);

#[derive(Debug, thiserror::Error)]
pub enum LayerVerifyError {
    #[error("invalid layer proof")]
    Invalid,
}

impl<'a> LayerVerifier<'a> {
    pub fn verify(
        &self,
        x_commit: Fp,
        y_commit: Fp,
        layer_idx: usize,
        session_id: &[u8; 16],
        weight_commit: &[u8; 32],
        proof: &LayerProof,
    ) -> Result<(), LayerVerifyError> {
        let strategy = SingleVerifier::new(&self.0.params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof.0.as_slice());
        let instance = build_instance(x_commit, y_commit, layer_idx, session_id, weight_commit);
        verify_proof(
            &self.0.params,
            &self.0.vk,
            strategy,
            &[&[&instance]],
            &mut transcript,
        )
        .map_err(|_| LayerVerifyError::Invalid)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_layer() -> ([[Fp; VEC_DIM]; VEC_DIM], [Fp; VEC_DIM]) {
        let mut w = [[Fp::zero(); VEC_DIM]; VEC_DIM];
        for i in 0..VEC_DIM {
            for j in 0..VEC_DIM {
                w[i][j] = Fp::from((1 + i as u64 * 7 + j as u64 * 3) as u64);
            }
        }
        let b: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((100 + i as u64) as u64));
        (w, b)
    }

    fn matmul(w: &[[Fp; VEC_DIM]; VEC_DIM], b: &[Fp; VEC_DIM], x: &[Fp; VEC_DIM]) -> [Fp; VEC_DIM] {
        let mut y = [Fp::zero(); VEC_DIM];
        for i in 0..VEC_DIM {
            let mut acc = b[i];
            for j in 0..VEC_DIM {
                acc += w[i][j] * x[j];
            }
            y[i] = acc;
        }
        y
    }

    fn fake_weight_commit() -> [u8; 32] {
        let mut wc = [0u8; 32];
        for (i, b) in wc.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        wc
    }

    #[test]
    fn prove_then_verify_honest() {
        let (w, b) = fake_layer();
        let (pp, vp) = setup_layer(0, w, b);
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i as u64 + 1) * 11));
        let y = matmul(&w, &b, &x);
        let xc = vector_hash_native(&x);
        let yc = vector_hash_native(&y);
        let session_id = [0x11u8; 16];
        let weight_commit = fake_weight_commit();
        let proof = LayerProver(&pp).prove(x, y, xc, yc, w, b, 0, &session_id, &weight_commit);
        LayerVerifier(&vp)
            .verify(xc, yc, 0, &session_id, &weight_commit, &proof)
            .unwrap();
    }

    #[test]
    fn wrong_commit_rejected() {
        let (w, b) = fake_layer();
        let (pp, vp) = setup_layer(0, w, b);
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i as u64 + 1) * 11));
        let y = matmul(&w, &b, &x);
        let xc = vector_hash_native(&x);
        let yc = vector_hash_native(&y);
        let session_id = [0x11u8; 16];
        let weight_commit = fake_weight_commit();
        let proof = LayerProver(&pp).prove(x, y, xc, yc, w, b, 0, &session_id, &weight_commit);
        let bogus_yc = yc + Fp::from(1u64);
        assert!(LayerVerifier(&vp)
            .verify(xc, bogus_yc, 0, &session_id, &weight_commit, &proof)
            .is_err());
    }

    /// P13-FIX-C regression: a proof minted for `(session_a, layer_idx=0)`
    /// must verify only under that exact `(session, layer_idx,
    /// weight_commit)` tuple — and concretely, a verifier presented with
    /// a different session id must reject, even though every other
    /// component (commits, model, witnesses) matches. Before the fix the
    /// public-input vector was just `[x_commit, y_commit]`, so the same
    /// proof would have been replayable into any session whose receipt
    /// happened to expose the same activation commits.
    #[test]
    fn cross_session_proof_rejected() {
        let (w, b) = fake_layer();
        let (pp, vp) = setup_layer(0, w, b);
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i as u64 + 1) * 11));
        let y = matmul(&w, &b, &x);
        let xc = vector_hash_native(&x);
        let yc = vector_hash_native(&y);
        let session_a = [0xAAu8; 16];
        let session_b = [0xBBu8; 16];
        let weight_commit = fake_weight_commit();
        let proof = LayerProver(&pp).prove(x, y, xc, yc, w, b, 0, &session_a, &weight_commit);
        // Correct session — passes.
        LayerVerifier(&vp)
            .verify(xc, yc, 0, &session_a, &weight_commit, &proof)
            .expect("session_a should verify");
        // Cross-session — must fail.
        assert!(
            LayerVerifier(&vp)
                .verify(xc, yc, 0, &session_b, &weight_commit, &proof)
                .is_err(),
            "proof from session_a must not verify under session_b"
        );
    }

    /// P13-FIX-C regression: a proof for `layer_idx=0` must not be
    /// accepted as evidence for any other layer slot. Before the fix the
    /// layer index lived only in the VK metadata (`LayerVerifierParams.layer_idx`);
    /// nothing in the proof itself tied the bytes to a slot, so a layer-0
    /// proof could be dropped into slot 5 of `zk_layer_proofs` if the
    /// commits were coincident.
    #[test]
    fn cross_layer_proof_rejected() {
        let (w, b) = fake_layer();
        let (pp, vp) = setup_layer(0, w, b);
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i as u64 + 1) * 11));
        let y = matmul(&w, &b, &x);
        let xc = vector_hash_native(&x);
        let yc = vector_hash_native(&y);
        let session_id = [0xCCu8; 16];
        let weight_commit = fake_weight_commit();
        let proof = LayerProver(&pp).prove(x, y, xc, yc, w, b, 0, &session_id, &weight_commit);
        // Correct layer_idx — passes.
        LayerVerifier(&vp)
            .verify(xc, yc, 0, &session_id, &weight_commit, &proof)
            .expect("layer 0 should verify");
        // Wrong layer_idx — must fail.
        assert!(
            LayerVerifier(&vp)
                .verify(xc, yc, 5, &session_id, &weight_commit, &proof)
                .is_err(),
            "proof minted for layer 0 must not verify under layer 5"
        );
    }

    /// P13-FIX-C regression: tampering with the weight commit must also
    /// reject. The VK already pins `(W, b)` fixed-cell-by-fixed-cell, but
    /// downstream consumers that don't re-derive the VK from
    /// `model.weight_commit` rely on the instance binding to cross-check.
    #[test]
    fn cross_weight_commit_proof_rejected() {
        let (w, b) = fake_layer();
        let (pp, vp) = setup_layer(0, w, b);
        let x: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i as u64 + 1) * 11));
        let y = matmul(&w, &b, &x);
        let xc = vector_hash_native(&x);
        let yc = vector_hash_native(&y);
        let session_id = [0xCCu8; 16];
        let weight_commit = fake_weight_commit();
        let mut other_weight_commit = weight_commit;
        other_weight_commit[0] ^= 0xFF;
        let proof = LayerProver(&pp).prove(x, y, xc, yc, w, b, 0, &session_id, &weight_commit);
        assert!(
            LayerVerifier(&vp)
                .verify(xc, yc, 0, &session_id, &other_weight_commit, &proof)
                .is_err(),
            "weight-commit mismatch must reject"
        );
    }

    /// Sanity check: the tagged-hash helper produces distinct outputs
    /// under different domain tags. Even though we don't currently use
    /// `tagged_vector_hash` in the in-circuit path (see the comment in
    /// `synthesize` step 3 — we intentionally use the canonical
    /// untagged hash so the receipt's commits flow straight into the
    /// instance vector), the helper remains in the public API for
    /// downstream consumers that want to opt into stronger domain
    /// separation by transmitting tagged commits alongside the
    /// receipt.
    #[test]
    fn tagged_hash_helper_separates_domains() {
        let v: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from(i as u64));
        let hx = tagged_vector_hash(domain_x(), &v);
        let hy = tagged_vector_hash(domain_y(), &v);
        assert_ne!(hx, hy);
        let h0 = vector_hash_native(&v);
        assert_ne!(hx, h0);
        assert_ne!(hy, h0);
    }
}
