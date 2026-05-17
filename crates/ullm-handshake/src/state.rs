// SPDX-License-Identifier: Apache-2.0
//! Explicit state machines for client and server.

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use ullm_core::{Error, Result};
use ullm_crypto::{
    derive_initial_keys, derive_root, hybrid_decap, hybrid_encap, ml_kem_ct_bytes,
    ml_kem_ct_from_bytes, ml_kem_pk_from_bytes, ChainKey, HybridSecret, MlKemSecretKey, NonceSalt,
    RootKey, X25519PublicKey, X25519SecretKey,
};

use crate::messages::{
    decode, encode, CipherSuite, ClientHello, PreKeyBundle, ServerHello, ATTESTATION_NONCE_LEN,
    RANDOM_LEN,
};
use crate::transcript::Transcript;

/// Output of a completed handshake: the keys both sides need for the
/// record layer.
pub struct EstablishedKeys {
    pub root: RootKey,
    pub c2s_chain: ChainKey,
    pub s2c_chain: ChainKey,
    pub nonce_salt: NonceSalt,
    pub transcript_hash: [u8; 32],
    /// REPORT_DATA the client should match against the attestation evidence.
    pub report_data: [u8; 64],
    /// Ephemeral X25519 public key the server sent; the client retains it as
    /// the starting point of the per-turn DH ratchet.
    pub server_ratchet_pk: X25519PublicKey,
    /// Client's session-long ratchet public key (server side will see this).
    pub client_ratchet_pk: X25519PublicKey,
    /// Attestation evidence the server attached to its `ServerHello`. The
    /// caller is responsible for running it through a `Verifier` against
    /// `report_data`.
    pub server_attestation_evidence: Vec<u8>,
}

/// Client-side handshake driver.
pub struct ClientHandshake {
    transcript: Transcript,
    client_random: [u8; RANDOM_LEN],
    attestation_nonce: [u8; ATTESTATION_NONCE_LEN],
    hybrid: HybridSecret,
    /// Session-long ratchet secret; the client retains this past handshake.
    client_ratchet_sk: X25519SecretKey,
}

impl ClientHandshake {
    pub fn client_ratchet_sk(&self) -> &X25519SecretKey {
        &self.client_ratchet_sk
    }
}

impl ClientHandshake {
    /// Step 1: given the server's pre-key bundle, produce a `ClientHello`
    /// and return both the wire bytes and an in-progress handshake.
    pub fn initiate<R: CryptoRngCore>(rng: &mut R, bundle: &PreKeyBundle) -> Result<(Self, Vec<u8>)> {
        let pq_pk = ml_kem_pk_from_bytes(&bundle.pq_pk_mlkem)
            .ok_or_else(|| Error::Other("invalid ML-KEM public key in bundle".into()))?;
        let spk_pk = X25519PublicKey::from(bundle.spk_pk_x25519);

        let (mlkem_ct, client_x25519_pk, hybrid) = hybrid_encap(rng, &pq_pk, &spk_pk);

        let mut client_random = [0u8; RANDOM_LEN];
        rng.fill_bytes(&mut client_random);
        let mut attestation_nonce = [0u8; ATTESTATION_NONCE_LEN];
        rng.fill_bytes(&mut attestation_nonce);

        let client_ratchet_sk = X25519SecretKey::random_from_rng(&mut *rng);
        let client_ratchet_pk = X25519PublicKey::from(&client_ratchet_sk);

        let hello = ClientHello {
            version: ullm_core::PROTOCOL_VERSION,
            client_random,
            attestation_nonce,
            client_x25519_pk: *client_x25519_pk.as_bytes(),
            client_mlkem_ct: ml_kem_ct_bytes(&mlkem_ct),
            client_ratchet_pk: *client_ratchet_pk.as_bytes(),
            cipher_suite: CipherSuite::default_phase1(),
        };
        let hello_bytes = encode(&hello)?;

        let mut transcript = Transcript::new();
        transcript.update(&hello_bytes);

        Ok((
            Self {
                transcript,
                client_random,
                attestation_nonce,
                hybrid,
                client_ratchet_sk,
            },
            hello_bytes,
        ))
    }

    pub fn attestation_nonce(&self) -> [u8; ATTESTATION_NONCE_LEN] {
        self.attestation_nonce
    }

    pub fn client_random(&self) -> [u8; RANDOM_LEN] {
        self.client_random
    }

    /// Step 2: consume the server's `ServerHello`, derive keys, return them.
    ///
    /// `verify_signature` receives:
    ///   - the **pre-server-hello transcript hash** (32 bytes)
    ///   - the signature carried in `ServerHello.signature`
    /// and must return `Ok(())` iff the signature is valid under the trusted
    /// TEE identity key. This mirrors the server's `make_evidence_and_sig`
    /// callback and keeps `ullm-handshake` independent of `ed25519-dalek`.
    pub fn complete<F>(
        self,
        server_hello_bytes: &[u8],
        verify_signature: F,
    ) -> Result<EstablishedKeys>
    where
        F: FnOnce(&[u8; 32], &[u8; 64]) -> Result<()>,
    {
        let server_hello: ServerHello = decode(server_hello_bytes)?;
        if server_hello.version != ullm_core::PROTOCOL_VERSION {
            return Err(Error::BadVersion {
                got: server_hello.version,
                expected: ullm_core::PROTOCOL_VERSION,
            });
        }

        let pre_sig_hash = self.transcript.hash();
        verify_signature(&pre_sig_hash, &server_hello.signature)?;

        let mut transcript = self.transcript;
        transcript.update(server_hello_bytes);
        let transcript_hash = transcript.hash();
        let server_ratchet_pk = X25519PublicKey::from(server_hello.server_x25519_pk);

        let root = derive_root(&transcript_hash, &self.hybrid);
        let keys = derive_initial_keys(&root);

        let report_data = compute_report_data(
            &self.attestation_nonce,
            &server_hello.server_x25519_pk,
            &self.hybrid,
        );

        let client_ratchet_pk = X25519PublicKey::from(&self.client_ratchet_sk);
        Ok(EstablishedKeys {
            root,
            c2s_chain: keys.c2s_chain,
            s2c_chain: keys.s2c_chain,
            nonce_salt: keys.nonce_salt,
            transcript_hash,
            report_data,
            server_ratchet_pk,
            client_ratchet_pk,
            server_attestation_evidence: server_hello.attestation_evidence,
        })
    }
}

/// Server-side handshake driver. Holds long-lived secrets needed to decap.
pub struct ServerHandshake<'a> {
    pub spk_sk_x25519: &'a X25519SecretKey,
    pub pq_sk_mlkem: &'a MlKemSecretKey,
}

impl<'a> ServerHandshake<'a> {
    /// Process a `ClientHello`, produce `ServerHello` bytes + established keys.
    ///
    /// `make_evidence_and_sig` is a callback that produces:
    /// 1. attestation evidence bound to `report_data`
    /// 2. an Ed25519 signature over the transcript hash by the TEE identity key
    ///
    /// Separating this callback keeps `ullm-handshake` independent of the
    /// attestation backend.
    pub fn respond<R, F>(
        &self,
        rng: &mut R,
        client_hello_bytes: &[u8],
        ratchet_sk: &X25519SecretKey,
        make_evidence_and_sig: F,
    ) -> Result<(Vec<u8>, EstablishedKeys)>
    where
        R: CryptoRngCore,
        F: FnOnce(&[u8; 64], &[u8; 32]) -> Result<(Vec<u8>, [u8; 64])>,
    {
        let client_hello: ClientHello = decode(client_hello_bytes)?;
        if client_hello.version != ullm_core::PROTOCOL_VERSION {
            return Err(Error::BadVersion {
                got: client_hello.version,
                expected: ullm_core::PROTOCOL_VERSION,
            });
        }
        client_hello.cipher_suite.validate()?;

        let mlkem_ct = ml_kem_ct_from_bytes(&client_hello.client_mlkem_ct)
            .ok_or_else(|| Error::Other("invalid ML-KEM ciphertext in client hello".into()))?;
        let client_x25519_pk = X25519PublicKey::from(client_hello.client_x25519_pk);
        let client_ratchet_pk = X25519PublicKey::from(client_hello.client_ratchet_pk);

        let hybrid = hybrid_decap(self.pq_sk_mlkem, self.spk_sk_x25519, &mlkem_ct, &client_x25519_pk)
            .map_err(|_| Error::Other("ml-kem decap failed".into()))?;

        let server_ratchet_pk_bytes = *X25519PublicKey::from(ratchet_sk).as_bytes();

        let report_data = compute_report_data(
            &client_hello.attestation_nonce,
            &server_ratchet_pk_bytes,
            &hybrid,
        );

        // Build the transcript through the ClientHello.
        let mut transcript = Transcript::new();
        transcript.update(client_hello_bytes);

        // We need a deterministic ServerHello prior to signing the transcript
        // hash that includes ServerHello bytes. The signature is over the
        // **client-hello-only** transcript snapshot (matching PQXDH practice).
        let pre_signature_hash = transcript.hash();
        let (evidence_bytes, signature) = make_evidence_and_sig(&report_data, &pre_signature_hash)?;
        let evidence_for_keys = evidence_bytes.clone();

        let mut server_random = [0u8; RANDOM_LEN];
        rng.fill_bytes(&mut server_random);

        let server_hello = ServerHello {
            version: ullm_core::PROTOCOL_VERSION,
            server_random,
            server_x25519_pk: server_ratchet_pk_bytes,
            attestation_evidence: evidence_bytes,
            signature,
        };
        let server_hello_bytes = encode(&server_hello)?;

        transcript.update(&server_hello_bytes);
        let transcript_hash = transcript.hash();

        let root = derive_root(&transcript_hash, &hybrid);
        let keys = derive_initial_keys(&root);

        Ok((
            server_hello_bytes,
            EstablishedKeys {
                root,
                c2s_chain: keys.c2s_chain,
                s2c_chain: keys.s2c_chain,
                nonce_salt: keys.nonce_salt,
                transcript_hash,
                report_data,
                server_ratchet_pk: X25519PublicKey::from(server_ratchet_pk_bytes),
                client_ratchet_pk,
                server_attestation_evidence: evidence_for_keys,
            },
        ))
    }
}

/// REPORT_DATA = SHA-512(attestation_nonce || server_x25519_pk || SHA-256(hybrid_ss)),
/// padded/truncated to 64 bytes (already 64 from SHA-512).
fn compute_report_data(
    attestation_nonce: &[u8; ATTESTATION_NONCE_LEN],
    server_x25519_pk: &[u8; 32],
    hybrid: &HybridSecret,
) -> [u8; 64] {
    let hybrid_hash: [u8; 32] = Sha256::digest(hybrid.0).into();
    let mut h = sha2::Sha512::new();
    h.update(attestation_nonce);
    h.update(server_x25519_pk);
    h.update(hybrid_hash);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ullm_crypto::{ml_kem_keypair, ml_kem_pk_bytes};

    #[test]
    fn full_handshake_yields_matching_keys() {
        let mut rng = OsRng;
        let spk_sk = X25519SecretKey::random_from_rng(&mut rng);
        let spk_pk = X25519PublicKey::from(&spk_sk);
        let (pq_sk, pq_pk) = ml_kem_keypair(&mut rng);

        let bundle = PreKeyBundle {
            id_pk: [0u8; 32],
            spk_pk_x25519: *spk_pk.as_bytes(),
            pq_pk_mlkem: ml_kem_pk_bytes(&pq_pk),
            attestation_evidence: vec![],
            signature: [0u8; 64],
        };

        let (client, hello_bytes) = ClientHandshake::initiate(&mut rng, &bundle).unwrap();

        let ratchet_sk = X25519SecretKey::random_from_rng(&mut rng);
        let server = ServerHandshake {
            spk_sk_x25519: &spk_sk,
            pq_sk_mlkem: &pq_sk,
        };
        let (server_hello_bytes, server_keys) = server
            .respond(&mut rng, &hello_bytes, &ratchet_sk, |_report, _hash| {
                Ok((vec![0xAA; 4], [0u8; 64]))
            })
            .unwrap();

        let client_keys = client
            .complete(&server_hello_bytes, |_hash, _sig| Ok(()))
            .unwrap();
        assert_eq!(
            *client_keys.client_ratchet_pk.as_bytes(),
            *server_keys.client_ratchet_pk.as_bytes()
        );

        assert_eq!(client_keys.root.0, server_keys.root.0);
        assert_eq!(client_keys.c2s_chain.0, server_keys.c2s_chain.0);
        assert_eq!(client_keys.s2c_chain.0, server_keys.s2c_chain.0);
        assert_eq!(client_keys.nonce_salt.0, server_keys.nonce_salt.0);
        assert_eq!(client_keys.transcript_hash, server_keys.transcript_hash);
        assert_eq!(client_keys.report_data, server_keys.report_data);
    }
}
