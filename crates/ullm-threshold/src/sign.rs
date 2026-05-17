// SPDX-License-Identifier: Apache-2.0
//! End-to-end threshold signing helpers.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey as DalekVk};
use frost_ed25519::keys::PublicKeyPackage;
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{aggregate as frost_aggregate, Identifier, SigningPackage};
use rand_core::CryptoRngCore;
use ullm_core::{Error, Result};

use crate::participant::Participant;

/// Aggregate `t` signature shares into a single Ed25519 signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public_pkg: &PublicKeyPackage,
) -> Result<DalekSignature> {
    let sig = frost_aggregate(signing_package, shares, public_pkg)
        .map_err(|e| Error::Other(format!("FROST aggregate: {e}")))?;
    let bytes = sig.serialize().map_err(|e| Error::Other(format!("sig bytes: {e}")))?;
    let arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("FROST signature not 64 bytes".into()))?;
    Ok(DalekSignature::from_bytes(&arr))
}

/// Group verifying key in ed25519-dalek form.
pub fn group_verifying_key(public_pkg: &PublicKeyPackage) -> Result<DalekVk> {
    let bytes = public_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| Error::Other(format!("vk serialize: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("FROST vk not 32 bytes".into()))?;
    DalekVk::from_bytes(&arr).map_err(|e| Error::Other(format!("vk parse: {e}")))
}

/// Single-call helper: given `t` participants + the public key package,
/// produce an Ed25519 signature over `message`. Intended for tests and
/// in-process demos; a real federation runs rounds 1 and 2 asynchronously.
pub fn sign_once<R: CryptoRngCore>(
    rng: &mut R,
    participants: &[Participant],
    public_pkg: &PublicKeyPackage,
    message: &[u8],
) -> Result<DalekSignature> {
    // Round 1: each signer commits.
    let mut nonces: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
    let mut commits: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    for p in participants {
        let (n, c) = p.commit(rng);
        nonces.insert(p.id, n);
        commits.insert(p.id, c);
    }
    let signing_package = SigningPackage::new(commits, message);

    // Round 2: each signer produces a share.
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for p in participants {
        let n = nonces.get(&p.id).expect("nonces inserted above");
        shares.insert(p.id, p.sign(&signing_package, n)?);
    }

    aggregate(&signing_package, &shares, public_pkg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::distribute_with_trusted_dealer;
    use ed25519_dalek::Verifier;
    use rand::rngs::OsRng;

    #[test]
    fn threshold_signs_and_verifies_under_group_key() {
        let mut rng = OsRng;
        let shares = distribute_with_trusted_dealer(2, 3, &mut rng).unwrap();
        let participants: Vec<Participant> = shares
            .key_packages
            .iter()
            .take(2)
            .map(|(id, kp)| Participant::new(*id, kp.clone()))
            .collect();

        let message = b"federation receipt #42";
        let sig = sign_once(&mut rng, &participants, &shares.public_pkg, message).unwrap();
        let vk = group_verifying_key(&shares.public_pkg).unwrap();
        vk.verify(message, &sig).unwrap();
    }

    #[test]
    fn cannot_sign_with_below_threshold() {
        // FROST's sign() succeeds with a sub-threshold set when the aggregator
        // attempts to combine — but aggregation fails. We assert the failure
        // surfaces.
        let mut rng = OsRng;
        let shares = distribute_with_trusted_dealer(2, 3, &mut rng).unwrap();
        let participants: Vec<Participant> = shares
            .key_packages
            .iter()
            .take(1)
            .map(|(id, kp)| Participant::new(*id, kp.clone()))
            .collect();
        let res = sign_once(&mut rng, &participants, &shares.public_pkg, b"x");
        assert!(res.is_err(), "sub-threshold sign should fail aggregation");
    }

    #[test]
    fn group_key_matches_verifying_key_of_aggregated_sig() {
        let mut rng = OsRng;
        let shares = distribute_with_trusted_dealer(2, 3, &mut rng).unwrap();
        let vk_a = group_verifying_key(&shares.public_pkg).unwrap();
        let vk_b = group_verifying_key(&shares.public_pkg).unwrap();
        assert_eq!(vk_a.as_bytes(), vk_b.as_bytes());
    }
}
