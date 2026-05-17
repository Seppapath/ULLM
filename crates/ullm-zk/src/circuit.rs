// SPDX-License-Identifier: Apache-2.0
//! Halo2 Poseidon-preimage circuit + prover + verifier.

use std::marker::PhantomData;

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonPrimitive, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash as PoseidonGadgetHash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error as PlonkError, Instance, ProvingKey, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;

/// `k` parameter — the log2 of the row count. 7 fits a single Poseidon hash.
const K: u32 = 7;

#[derive(Clone)]
struct Config {
    poseidon: Pow5Config<Fp, 3, 2>,
    /// Two advice columns owned by us for loading the witness `(x, y)`.
    input: [Column<Advice>; 2],
    instance: Column<Instance>,
}

#[derive(Default, Clone)]
struct PoseidonPreimageCircuit {
    x: Value<Fp>,
    y: Value<Fp>,
    _marker: PhantomData<P128Pow5T3>,
}

impl Circuit<Fp> for PoseidonPreimageCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let input = [meta.advice_column(), meta.advice_column()];
        for &c in &input {
            meta.enable_equality(c);
        }

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Config {
            poseidon,
            input,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        // 1) Load witness (x, y) into our own advice columns.
        let (cell_x, cell_y) = layouter.assign_region(
            || "load preimage",
            |mut region| {
                let cx = region.assign_advice(|| "x", config.input[0], 0, || self.x)?;
                let cy = region.assign_advice(|| "y", config.input[1], 0, || self.y)?;
                Ok((cx, cy))
            },
        )?;

        // 2) Hash via the Poseidon gadget.
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let hasher = PoseidonGadgetHash::<
            Fp,
            Pow5Chip<Fp, 3, 2>,
            P128Pow5T3,
            ConstantLength<2>,
            3,
            2,
        >::init(chip, layouter.namespace(|| "init poseidon"))?;
        let output = hasher.hash(layouter.namespace(|| "absorb"), [cell_x, cell_y])?;

        // 3) Constrain the gadget's output equal to the public instance.
        layouter.constrain_instance(output.cell(), config.instance, 0)?;
        Ok(())
    }
}

/// Out-of-circuit Poseidon hash, matches the in-circuit gadget exactly.
pub fn digest_from_inputs(x: Fp, y: Fp) -> Fp {
    PoseidonPrimitive::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([x, y])
}

/// Convert 32 bytes (little-endian) to a Pallas `Fp`. **Strict**: bytes
/// must encode a canonical field element (i.e. value `< p`).
///
/// The previous implementation silently clamped the top two bits when the
/// input was `>= p`. That was lossy — distinct byte sequences mapped to the
/// same `Fp`, opening a representation-malleability gap on the receipt /
/// activation-commit boundary. Honest producers (the Poseidon hash + the
/// `fp_to_bytes` round-trip) only ever emit canonical bytes, so the strict
/// contract costs nothing on the happy path while denying an attacker any
/// "two preimages, one field element" leverage.
pub fn fp_from_bytes(b: [u8; 32]) -> Result<Fp, &'static str> {
    Fp::from_repr_vartime(b).ok_or("fp_from_bytes: non-canonical input (>= p)")
}

pub fn fp_to_bytes(f: Fp) -> [u8; 32] {
    f.to_repr()
}

pub struct ProverParams {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

pub struct VerifierParams {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof(pub Vec<u8>);

/// Deterministic setup. Same `K` → same params.
pub fn setup() -> (ProverParams, VerifierParams) {
    let params: Params<EqAffine> = Params::new(K);
    let empty = PoseidonPreimageCircuit::default();
    let vk = keygen_vk(&params, &empty).expect("vk gen");
    let pk = keygen_pk(&params, vk.clone(), &empty).expect("pk gen");
    (
        ProverParams {
            params: params.clone(),
            pk,
        },
        VerifierParams { params, vk },
    )
}

pub struct Prover<'a>(pub &'a ProverParams);

impl<'a> Prover<'a> {
    pub fn prove(&self, x: Fp, y: Fp, digest: Fp) -> Proof {
        let circuit = PoseidonPreimageCircuit {
            x: Value::known(x),
            y: Value::known(y),
            _marker: PhantomData,
        };
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
        create_proof(
            &self.0.params,
            &self.0.pk,
            &[circuit],
            &[&[&[digest]]],
            OsRng,
            &mut transcript,
        )
        .expect("proof creation");
        Proof(transcript.finalize())
    }
}

pub struct Verifier<'a>(pub &'a VerifierParams);

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid ZK proof")]
    Invalid,
}

impl<'a> Verifier<'a> {
    pub fn verify(&self, digest: Fp, proof: &Proof) -> Result<(), VerifyError> {
        let strategy = SingleVerifier::new(&self.0.params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof.0.as_slice());
        verify_proof(
            &self.0.params,
            &self.0.vk,
            strategy,
            &[&[&[digest]]],
            &mut transcript,
        )
        .map_err(|_| VerifyError::Invalid)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_then_verify() {
        let (pp, vp) = setup();
        let x = Fp::from(0x1234_5678_u64);
        let y = Fp::from(0xdead_beef_u64);
        let digest = digest_from_inputs(x, y);
        let proof = Prover(&pp).prove(x, y, digest);
        Verifier(&vp).verify(digest, &proof).unwrap();
    }

    #[test]
    fn wrong_digest_rejected() {
        let (pp, vp) = setup();
        let x = Fp::from(1u64);
        let y = Fp::from(2u64);
        let digest = digest_from_inputs(x, y);
        let proof = Prover(&pp).prove(x, y, digest);
        let bogus = digest + Fp::from(1u64);
        assert!(Verifier(&vp).verify(bogus, &proof).is_err());
    }

    #[test]
    fn fp_bytes_roundtrip_for_in_range() {
        let f = Fp::from(0x42u64);
        let b = fp_to_bytes(f);
        let g = fp_from_bytes(b).expect("canonical");
        assert_eq!(f, g);
    }

    /// Regression for P2-1: non-canonical 32-byte representations
    /// (high bits set so the value is ≥ p) must be rejected, not
    /// silently clamped to a different field element.
    #[test]
    fn fp_from_bytes_rejects_noncanonical() {
        let mut b = [0xFFu8; 32];
        // Force the top bits set so the value is clearly ≥ p for Pallas.
        b[31] = 0xFF;
        assert!(
            fp_from_bytes(b).is_err(),
            "all-0xFF must be rejected as non-canonical"
        );
    }
}
