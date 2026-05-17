// SPDX-License-Identifier: Apache-2.0
//! Deterministic fixtures shared across bench targets.

use rand::rngs::OsRng;
use ullm_crypto::{
    hybrid_encap, ml_kem_keypair, MlKemPublicKey, MlKemSecretKey, X25519PublicKey, X25519SecretKey,
};

pub fn hybrid_keypairs() -> (
    MlKemSecretKey,
    MlKemPublicKey,
    X25519SecretKey,
    X25519PublicKey,
) {
    let mut rng = OsRng;
    let (mlkem_sk, mlkem_pk) = ml_kem_keypair(&mut rng);
    let x25519_sk = X25519SecretKey::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    (mlkem_sk, mlkem_pk, x25519_sk, x25519_pk)
}

pub fn handshake_encap_output() -> Vec<u8> {
    let (_, mlkem_pk, _, x25519_pk) = hybrid_keypairs();
    let mut rng = OsRng;
    let (_ct, _client_pk, _) = hybrid_encap(&mut rng, &mlkem_pk, &x25519_pk);
    Vec::new()
}
