// SPDX-License-Identifier: Apache-2.0
//! Hybrid KEX: X25519 ECDH combined with ML-KEM-768 (FIPS 203).
//!
//! Output is the 64-byte concatenation `MLKEM_ss || X25519_ss`, fed through
//! HKDF (see `kdf.rs`) to derive the root key.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// ML-KEM-768 encapsulation key (server-side).
pub type MlKemPublicKey = <MlKem768 as KemCore>::EncapsulationKey;
/// ML-KEM-768 decapsulation key (server-side).
pub type MlKemSecretKey = <MlKem768 as KemCore>::DecapsulationKey;
/// ML-KEM-768 ciphertext.
pub type MlKemCiphertext = Ciphertext<MlKem768>;

/// Concatenated 64-byte shared secret: `MLKEM_ss(32) || X25519_ss(32)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecret(pub [u8; 64]);

/// Encrypt: client side. Produces:
/// - ML-KEM ciphertext (1088 B) targeting the server's encapsulation key
/// - X25519 ephemeral public key (client emits its own)
/// - The shared secret only the client and server can derive
///
/// The X25519 secret key is consumed; callers retain the public key to send.
pub fn hybrid_encap<R: CryptoRngCore>(
    rng: &mut R,
    server_mlkem_pk: &MlKemPublicKey,
    server_x25519_pk: &X25519PublicKey,
) -> (MlKemCiphertext, X25519PublicKey, HybridSecret) {
    let (mlkem_ct, mlkem_ss) = server_mlkem_pk
        .encapsulate(rng)
        .expect("ml-kem encap is infallible with valid pk");

    let client_x25519_sk = X25519SecretKey::random_from_rng(&mut *rng);
    let client_x25519_pk = X25519PublicKey::from(&client_x25519_sk);
    let x25519_ss = client_x25519_sk.diffie_hellman(server_x25519_pk);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(mlkem_ss.as_ref());
    out[32..].copy_from_slice(x25519_ss.as_bytes());
    (mlkem_ct, client_x25519_pk, HybridSecret(out))
}

/// Decrypt: server side.
///
/// Returns an `Err` if ML-KEM decapsulation fails. With FIPS 203's implicit
/// rejection this is unreachable in practice for valid-length ciphertexts,
/// but we surface a typed error rather than panicking — the input here is
/// attacker-controlled (network-supplied client_mlkem_ct).
pub fn hybrid_decap(
    server_mlkem_sk: &MlKemSecretKey,
    server_x25519_sk: &X25519SecretKey,
    mlkem_ct: &MlKemCiphertext,
    client_x25519_pk: &X25519PublicKey,
) -> Result<HybridSecret, ullm_core::Error> {
    let mlkem_ss = server_mlkem_sk
        .decapsulate(mlkem_ct)
        .map_err(|_| ullm_core::Error::Other("ml-kem decap failed".into()))?;
    let x25519_ss = server_x25519_sk.diffie_hellman(client_x25519_pk);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(mlkem_ss.as_ref());
    out[32..].copy_from_slice(x25519_ss.as_bytes());
    Ok(HybridSecret(out))
}

/// Generate a fresh ML-KEM-768 keypair.
pub fn ml_kem_keypair<R: CryptoRngCore>(rng: &mut R) -> (MlKemSecretKey, MlKemPublicKey) {
    let (sk, pk) = MlKem768::generate(rng);
    (sk, pk)
}

/// Serialize an ML-KEM public key for wire transport.
pub fn ml_kem_pk_bytes(pk: &MlKemPublicKey) -> Vec<u8> {
    pk.as_bytes().to_vec()
}

/// Deserialize an ML-KEM public key.
pub fn ml_kem_pk_from_bytes(b: &[u8]) -> Option<MlKemPublicKey> {
    let arr: &ml_kem::Encoded<MlKemPublicKey> = b.try_into().ok()?;
    Some(<MlKemPublicKey as EncodedSizeUser>::from_bytes(arr))
}

/// Serialize an ML-KEM ciphertext.
pub fn ml_kem_ct_bytes(ct: &MlKemCiphertext) -> Vec<u8> {
    ct.as_slice().to_vec()
}

/// Deserialize an ML-KEM ciphertext.
pub fn ml_kem_ct_from_bytes(b: &[u8]) -> Option<MlKemCiphertext> {
    let arr: &ml_kem::Ciphertext<MlKem768> = b.try_into().ok()?;
    Some(arr.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip_hybrid() {
        let mut rng = OsRng;
        let (sk_kem, pk_kem) = ml_kem_keypair(&mut rng);
        let sk_x = X25519SecretKey::random_from_rng(&mut rng);
        let pk_x = X25519PublicKey::from(&sk_x);

        let (ct, client_pk_x, client_ss) = hybrid_encap(&mut rng, &pk_kem, &pk_x);
        let server_ss = hybrid_decap(&sk_kem, &sk_x, &ct, &client_pk_x).expect("decap");
        assert_eq!(client_ss.0, server_ss.0);
    }

    /// Regression for F-1: a wrong-length ML-KEM ciphertext must be rejected
    /// at the parsing boundary instead of panicking in the responder path.
    /// ML-KEM is randomized + IND-CCA2 so a byte-flipped ct still parses and
    /// silently decaps to a different secret — the only structural failure
    /// we can drive is a length mismatch, which `ml_kem_ct_from_bytes`
    /// must turn into `None` (and `hybrid_decap`'s caller into `Err`).
    #[test]
    fn hybrid_decap_rejects_garbled_kem_ciphertext() {
        let mut rng = OsRng;
        let (sk_kem, pk_kem) = ml_kem_keypair(&mut rng);
        let sk_x = X25519SecretKey::random_from_rng(&mut rng);
        let pk_x = X25519PublicKey::from(&sk_x);
        let (ct, client_pk_x, _) = hybrid_encap(&mut rng, &pk_kem, &pk_x);

        let mut bytes = ml_kem_ct_bytes(&ct);
        bytes.truncate(bytes.len() / 2);
        assert!(
            ml_kem_ct_from_bytes(&bytes).is_none(),
            "wrong-length ML-KEM ciphertext must be rejected"
        );

        // Sanity: the original well-formed ct still decaps successfully.
        let ok = hybrid_decap(&sk_kem, &sk_x, &ct, &client_pk_x);
        assert!(ok.is_ok(), "well-formed ct must still decap");
    }
}
