// SPDX-License-Identifier: Apache-2.0
//! Trusted-dealer DKG for FROST-Ed25519.
//!
//! A trusted dealer generates the secret key, splits it into `n` shares, and
//! hands each share to one participant. The dealer's secret is forgotten
//! after distribution. Suitable for cooperative federations where the
//! dealer can be a one-shot setup ceremony.
//!
//! **NOT FOR PRODUCTION.** The dealer is a single point of failure: a
//! compromised dealer learns the master secret and can forge any
//! threshold signature. P4-10 audit gated this entry point behind the
//! `trusted-dealer` Cargo feature so a production build (built with
//! `--no-default-features`) drops the function entirely. Production
//! deployments need a decentralized DKG (Pedersen / Lindell-Jarecki); a
//! future variant will live behind its own feature.

use std::collections::BTreeMap;

use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
#[cfg(feature = "trusted-dealer")]
use frost_ed25519::keys::{generate_with_dealer, IdentifierList, SecretShare};
use frost_ed25519::Identifier;
#[cfg(feature = "trusted-dealer")]
use rand_core::CryptoRngCore;
#[cfg(feature = "trusted-dealer")]
use ullm_core::{Error, Result};

pub struct KeyShares {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub public_pkg: PublicKeyPackage,
}

/// Run the trusted-dealer protocol producing `n` key shares, with threshold
/// `t`. The dealer's master secret is dropped after this call returns.
///
/// **Available only when the `trusted-dealer` Cargo feature is enabled**
/// (default for tests / demos; off in production via
/// `--no-default-features`). See module docs for rationale.
#[cfg(feature = "trusted-dealer")]
pub fn distribute_with_trusted_dealer<R: CryptoRngCore>(
    threshold_t: u16,
    num_n: u16,
    rng: &mut R,
) -> Result<KeyShares> {
    let (secret_shares, public_pkg) =
        generate_with_dealer(num_n, threshold_t, IdentifierList::Default, rng)
            .map_err(|e| Error::Other(format!("FROST DKG failed: {e}")))?;
    let mut key_packages = BTreeMap::new();
    for (id, share) in secret_shares {
        let kp = KeyPackage::try_from(share)
            .map_err(|e| Error::Other(format!("FROST KeyPackage: {e}")))?;
        key_packages.insert(id, kp);
    }
    // Silence the unused warning for `SecretShare` import while keeping the
    // type available for downstream consumers that may want it.
    let _ = std::any::type_name::<SecretShare>();
    Ok(KeyShares {
        key_packages,
        public_pkg,
    })
}

/// Compatibility shim — old name. Kept callable only while the
/// `trusted-dealer` feature is on; production builds get a compile-time
/// error if anything still calls this. New code should use
/// `distribute_with_trusted_dealer` and remember to feature-gate the
/// call site too.
#[cfg(feature = "trusted-dealer")]
#[deprecated(note = "renamed to distribute_with_trusted_dealer for clarity (P4-10)")]
pub fn distribute<R: CryptoRngCore>(
    threshold_t: u16,
    num_n: u16,
    rng: &mut R,
) -> Result<KeyShares> {
    distribute_with_trusted_dealer(threshold_t, num_n, rng)
}

#[cfg(all(test, feature = "trusted-dealer"))]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn dkg_produces_n_shares() {
        let mut rng = OsRng;
        let shares = distribute_with_trusted_dealer(2, 3, &mut rng).unwrap();
        assert_eq!(shares.key_packages.len(), 3);
    }

    #[test]
    fn rejects_invalid_threshold() {
        let mut rng = OsRng;
        assert!(distribute_with_trusted_dealer(0, 3, &mut rng).is_err());
        assert!(distribute_with_trusted_dealer(4, 3, &mut rng).is_err());
    }
}
