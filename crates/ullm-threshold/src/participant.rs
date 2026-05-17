// SPDX-License-Identifier: Apache-2.0
use frost_ed25519::keys::KeyPackage;
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, SigningPackage};
use rand_core::CryptoRngCore;
use ullm_core::{Error, Result};

/// One signing participant. Holds its long-lived key share.
pub struct Participant {
    pub id: Identifier,
    pub key_package: KeyPackage,
}

impl Participant {
    pub fn new(id: Identifier, key_package: KeyPackage) -> Self {
        Self { id, key_package }
    }

    /// Round-1 commitment: generate a fresh nonce + the public commitment to it.
    pub fn commit<R: CryptoRngCore>(&self, rng: &mut R) -> (SigningNonces, SigningCommitments) {
        let signing_share = self.key_package.signing_share();
        frost_ed25519::round1::commit(signing_share, rng)
    }

    /// Round-2 signature share: bind the participant's nonce to the signing
    /// package (which includes the aggregated commitments + message).
    pub fn sign(
        &self,
        signing_package: &SigningPackage,
        nonces: &SigningNonces,
    ) -> Result<SignatureShare> {
        frost_ed25519::round2::sign(signing_package, nonces, &self.key_package)
            .map_err(|e| Error::Other(format!("FROST sign: {e}")))
    }
}
